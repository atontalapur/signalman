package fuzz

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp/syntax"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/sigma"
)

// known() is a pure function and the closed set of suppressions it
// implements is exactly what KNOWN_DIVERGENCES.md documents. These tests
// exercise it directly so every branch is pinned without needing the pySigma
// venv, which TestKnownAcceptanceDivergences in differential_test.go only
// reaches for a handful of them.
//
// Every suppression keys on a code or an error type, never on message text.
// The fuzzer puts arbitrary strings into rule values, and error messages
// quote rule values back, so text matching lets a value suppress an
// unrelated failure. The negative cases below are exactly that.

func TestKnownTimeoutIsAlwaysSuppressed(t *testing.T) {
	wrapped := fmt.Errorf("%w after 5s", ErrOracleTimeout)
	if !known(nil, wrapped) {
		t.Fatal("a timed-out oracle request must always be suppressed, regardless of errG")
	}
	if !known(errors.New("anything"), wrapped) {
		t.Fatal("timeout suppression must win even when Signalman also errored")
	}
}

func loadErr(code, reason string) error {
	return &sigma.LoadError{Path: "fuzz.yml", Code: code, Reason: reason, Line: 1}
}

func TestKnownSignalmanLoadDivergences(t *testing.T) {
	cases := []struct {
		name string
		errG error
		want bool
	}{
		{"no taxonomy", loadErr(sigma.CodeNoTaxonomy, "no taxonomy entry"), true},
		{"aggregation", loadErr(sigma.CodeAggregation, "aggregation is not supported"), true},
		{"missing id", loadErr(sigma.CodeMissingID, "rule has no id"), true},
		{"regexp syntax", &sigma.LoadError{Code: sigma.CodeDetection, Err: &syntax.Error{Code: syntax.ErrMissingBracket}}, true},
		// A loaded rule whose logsource then fails to resolve means the
		// loader and Resolve disagree: a Signalman bug, not an oracle gap.
		{"does not resolve", errors.New("rule loaded but logsource windows/process_creation does not resolve"), false},
		// The message quotes the value; the code is what decides.
		{"text without the code", loadErr(sigma.CodeDetection, "value 'aggregation is not supported [missing-id] error parsing regexp'"), false},
		{"plain error with the text", errors.New("no taxonomy entry"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := known(c.errG, nil); got != c.want {
				t.Fatalf("known(%v, nil) = %v, want %v", c.errG, got, c.want)
			}
		})
	}
}

// A regex RE2 rejects has to be recognizable through the real loader, not
// only through a hand-built LoadError.
func TestKnownRecognizesRealRegexRejection(t *testing.T) {
	rule := strings.Replace(seedRule, `Image|endswith: '\rundll32.exe'`, `Image|re: '(?<!a)b'`, 1)
	_, errG := EvalOnce([]byte(rule), taxonomyDir, Fields{"Image": "b"})
	if errG == nil {
		t.Fatal("expected RE2 to reject a lookbehind")
	}
	if !known(errG, nil) {
		t.Fatalf("an RE2 syntax rejection must be recognized by type: %v", errG)
	}
}

func TestKnownOracleRefusalDivergences(t *testing.T) {
	for code := range refusalCodes {
		t.Run(code, func(t *testing.T) {
			if !known(nil, &RefusalError{Code: code}) {
				t.Fatalf("documented refusal %q must be suppressed", code)
			}
		})
	}
	if known(nil, &RefusalError{Code: "something-new"}) {
		t.Fatal("an undocumented refusal code must surface")
	}
}

// An oracle error with no refusal code is something nobody documented, even
// when its text carries every phrase the old text matching suppressed on.
func TestKnownDoesNotSuppressUncodedOracleErrors(t *testing.T) {
	for _, msg := range []string{
		"SigmaFeatureNotSupportedByBackendError: something new",
		"KeyError: 'keywords'",
		"ValueError: Unknown modifier in value 'unsupported-value: x'",
		"OperationalError: near \"Full Text Search\": syntax error",
	} {
		if known(nil, fmt.Errorf("oracle rejected rule: %s", msg)) {
			t.Fatalf("uncoded oracle error %q must surface", msg)
		}
	}
}

func TestKnownDoesNotSuppressBrokenOracle(t *testing.T) {
	broken := fmt.Errorf("%w: oracle closed stdout", ErrOracleBroken)
	if known(nil, broken) || known(errors.New("x"), broken) {
		t.Fatal("a broken oracle bridge must never be suppressed")
	}
}

func TestKnownReturnsFalseWithNoErrors(t *testing.T) {
	if known(nil, nil) {
		t.Fatal("known(nil, nil) must be false: there is nothing to suppress")
	}
}

// Python's stderr is kept for diagnosis, but only its tail: one subprocess
// lives for the whole run, and a per-request warning would otherwise grow
// without bound.
func TestSyncBuilderKeepsTail(t *testing.T) {
	var s syncBuilder
	for i := 0; i < 3; i++ {
		_, _ = s.Write([]byte(strings.Repeat("x", maxStderr)))
	}
	_, _ = s.Write([]byte("END"))
	got := s.String()
	if len(got) > maxStderr {
		t.Fatalf("kept %d bytes, want at most %d", len(got), maxStderr)
	}
	if !strings.HasSuffix(got, "END") {
		t.Fatal("the most recent output must be kept: a traceback is at the end")
	}
}

// awaitReady is exercised here against a synthetic oracleProc so the
// channel-closed and bad-readiness-line branches are pinned without paying
// for a subprocess, and without the 60s oracleStartup timer the real timeout
// branch would need.
func TestAwaitReady(t *testing.T) {
	t.Run("channel closed during startup", func(t *testing.T) {
		p := &oracleProc{lines: make(chan []byte), stderr: &syncBuilder{}}
		p.stderr.Write([]byte("Traceback (most recent call last):\n"))
		close(p.lines)

		err := p.awaitReady()
		if err == nil || !strings.Contains(err.Error(), "oracle exited during startup") {
			t.Fatalf("awaitReady() = %v, want an error naming a startup exit", err)
		}
		if !strings.Contains(err.Error(), "Traceback") {
			t.Fatalf("awaitReady() = %v, want the captured stderr included", err)
		}
	})

	t.Run("line before readiness", func(t *testing.T) {
		p := &oracleProc{lines: make(chan []byte, 1), stderr: &syncBuilder{}}
		p.lines <- []byte(`{"ready":false}`)

		err := p.awaitReady()
		if err == nil || !strings.Contains(err.Error(), "before announcing readiness") {
			t.Fatalf("awaitReady() = %v, want an error about an unready line", err)
		}
	})

	t.Run("malformed json before readiness", func(t *testing.T) {
		p := &oracleProc{lines: make(chan []byte, 1), stderr: &syncBuilder{}}
		p.lines <- []byte(`not json`)

		err := p.awaitReady()
		if err == nil || !strings.Contains(err.Error(), "before announcing readiness") {
			t.Fatalf("awaitReady() = %v, want an error about an unready line", err)
		}
	})

	t.Run("ready", func(t *testing.T) {
		p := &oracleProc{lines: make(chan []byte, 1), stderr: &syncBuilder{}}
		p.lines <- []byte(`{"ready":true}`)

		if err := p.awaitReady(); err != nil {
			t.Fatalf("awaitReady() = %v, want nil once ready is announced", err)
		}
	})
}

// drain forwards every line the subprocess writes and closes the channel at
// EOF. Testing it against a plain reader avoids starting a subprocess just
// to exercise the plumbing between stdout and the lines channel.
func TestOracleProcDrainForwardsLinesAndClosesOnEOF(t *testing.T) {
	p := &oracleProc{lines: make(chan []byte, 4)}
	go p.drain(strings.NewReader("{\"a\":1}\n{\"b\":2}\n"))

	first, ok := <-p.lines
	if !ok || string(first) != `{"a":1}` {
		t.Fatalf("first line = %q, ok=%v, want {\"a\":1}, true", first, ok)
	}
	second, ok := <-p.lines
	if !ok || string(second) != `{"b":2}` {
		t.Fatalf("second line = %q, ok=%v, want {\"b\":2}, true", second, ok)
	}
	if _, ok := <-p.lines; ok {
		t.Fatal("lines channel should be closed once the reader hits EOF")
	}
}

// TestOracleEvalRestartsAfterProcessDeath kills the subprocess out from
// under a live Oracle and checks that Eval reports the failure and replaces
// it with a working one, rather than wedging every request after the first
// crash. This is the restart-on-failure path the fuzzer depends on to
// survive a single bad subprocess over a long run.
func TestOracleEvalRestartsAfterProcessDeath(t *testing.T) {
	requireOracle(t)
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	if err := o.proc.cmd.Process.Kill(); err != nil {
		t.Fatalf("killing the oracle subprocess: %v", err)
	}
	_, _ = o.proc.cmd.Process.Wait() // reap so the pipe closes promptly

	if _, _, err := o.Eval(seedRule, Fields{"Image": `C:\Windows\rundll32.exe`}); !errors.Is(err, ErrOracleBroken) {
		t.Fatalf("Eval after killing the subprocess = %v, want ErrOracleBroken", err)
	}

	// The restart should have left a working subprocess in place.
	want, res, err := o.Eval(seedRule, Fields{"Image": `C:\Windows\rundll32.exe`})
	if err != nil {
		t.Fatalf("Eval after restart: %v", err)
	}
	if !want || len(res.Fields) != 1 || res.Fields[0] != "Image" {
		t.Fatalf("Eval after restart = %v, %+v, want a normal match on the seed rule", want, res)
	}
}

// A line that is not a response means the pipe is out of step with the
// requests. Eval has to replace the subprocess and report a broken bridge,
// never a rule rejection, and the replacement has to answer normally.
func TestOracleEvalRestartsOnMalformedResponse(t *testing.T) {
	requireOracle(t)
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	// Swap in a fake subprocess whose next line is garbage. Its stdin
	// discards the request; kill() on it is a no-op apart from the close.
	real := o.proc
	fake := &oracleProc{
		cmd:    exec.Command("true"),
		stdin:  nopWriteCloser{},
		in:     bufio.NewWriter(io.Discard),
		lines:  make(chan []byte, 1),
		stderr: &syncBuilder{},
	}
	fake.lines <- []byte("not json")
	o.proc = fake
	real.kill()

	_, _, err = o.Eval(seedRule, Fields{"Image": `C:\Windows\rundll32.exe`})
	if !errors.Is(err, ErrOracleBroken) {
		t.Fatalf("Eval on a malformed line = %v, want ErrOracleBroken", err)
	}
	var refusal *RefusalError
	if errors.As(err, &refusal) {
		t.Fatal("a malformed line must not read as an oracle refusal")
	}

	want, _, err := o.Eval(seedRule, Fields{"Image": `C:\Windows\rundll32.exe`})
	if err != nil || !want {
		t.Fatalf("Eval after restart = %v, %v, want a normal match", want, err)
	}
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

// TestOracleEvalRestartsOnTimeout pins the behavior of Eval's timeout
// branch: on a timeout the hung subprocess is killed and
// replaced, not merely reported. Without that, the subprocess would still be
// computing when it finally answers, and that stale line would be handed to
// whatever Eval call happens to be reading next -- comparing one case's
// verdict against a different case's rule.
//
// (a+)+$ is the textbook catastrophic-backtracking pattern reSafe exists to
// keep out of the fuzz corpus: RE2 rejects nested quantifiers outright, but
// Python's backtracking engine accepts it and, against a string that almost
// but does not quite match, takes far longer than oracleTimeout.
func TestOracleEvalRestartsOnTimeout(t *testing.T) {
	requireOracle(t)
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	o.timeout = 500 * time.Millisecond

	rule := `title: evil regex
id: 00000000-0000-4000-8000-0000000000ff
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|re: '(a+)+$'
  condition: selection
`
	ev := Fields{"Image": strings.Repeat("a", 40) + "!"}

	start := time.Now()
	_, _, err = o.Eval(rule, ev)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrOracleTimeout) {
		t.Fatalf("Eval on a catastrophically backtracking pattern = %v, want ErrOracleTimeout", err)
	}
	if elapsed < o.timeout {
		t.Fatalf("Eval returned after %s, before the timeout (%s) elapsed", elapsed, o.timeout)
	}
	if errors.Is(err, ErrOracleBroken) {
		t.Fatal("a timeout is an unevaluated case, not a broken bridge")
	}

	// The subprocess must have been replaced: a normal request afterward
	// should get a normal answer, not the backtracking case's eventual (and
	// by now irrelevant) response.
	want, res, err := o.Eval(seedRule, Fields{"Image": `C:\Windows\rundll32.exe`})
	if err != nil {
		t.Fatalf("Eval after a timeout restart: %v", err)
	}
	if !want || len(res.Fields) != 1 || res.Fields[0] != "Image" {
		t.Fatalf("Eval after a timeout restart = %v, %+v, want a normal match on the seed rule", want, res)
	}
}
