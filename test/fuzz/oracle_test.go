package fuzz

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// known() is a pure function and the closed set of suppressions it
// implements is exactly what KNOWN_DIVERGENCES.md documents. These tests
// exercise it directly so every branch is pinned without needing the pySigma
// venv, which TestKnownAcceptanceDivergences in differential_test.go only
// reaches for a handful of them.

func TestKnownTimeoutIsAlwaysSuppressed(t *testing.T) {
	wrapped := fmt.Errorf("%w after 5s", ErrOracleTimeout)
	if !known(nil, wrapped) {
		t.Fatal("a timed-out oracle request must always be suppressed, regardless of errG")
	}
	if !known(errors.New("anything"), wrapped) {
		t.Fatal("timeout suppression must win even when Signalman also errored")
	}
}

func TestKnownSignalmanLoadDivergences(t *testing.T) {
	cases := []struct {
		name string
		errG string
		want bool
	}{
		{"no taxonomy entry", "no taxonomy entry for windows/process_creation", true},
		{"does not resolve", "rule loaded but logsource windows/process_creation does not resolve", true},
		{"aggregation not supported", "aggregation is not supported", true},
		{"missing id code", "fuzz.yml:1 [missing-id] rule : title required", true},
		{"regexp parse error", "error parsing regexp: missing closing ]", true},
		{"undocumented message", "some other loader complaint entirely", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := known(errors.New(c.errG), nil); got != c.want {
				t.Fatalf("known(%q, nil) = %v, want %v", c.errG, got, c.want)
			}
		})
	}
}

func TestKnownOracleRefusalDivergences(t *testing.T) {
	cases := []struct {
		name string
		errP string
	}{
		{"unsupported modifier", "unsupported-modifier: cidr"},
		{"unsupported feature", "unsupported-feature: value-only expression"},
		{"unsupported value", "unsupported-value: NUL"},
		{"unsupported query", "unsupported-query: NOT outside parentheses"},
		{"expression tree too large", "sqlite3.OperationalError: Expression tree is too large (maximum depth 1000)"},
		{"sigma identifier error", "SigmaIdentifierError: not a UUID"},
		{"full text search", "Full Text Search is not supported"},
		{"keywords", "conversion produced bare keywords"},
		{"ascii only", "wide modifier is only allowed for ascii strings"},
		{"unicode only", "utf16 modifier is only allowed for valid Unicode strings"},
		{"wildcards not allowed", "strings with wildcards is not allowed here"},
		{"sigma regex error", "SigmaRegularExpressionError: bad pattern"},
		{"unknown modifier", "Unknown modifier expandvar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !known(nil, errors.New(c.errP)) {
				t.Fatalf("known(nil, %q) = false, want true", c.errP)
			}
		})
	}
}

// The sqlite backend's generic refusal is deliberately NOT suppressed. It
// names an exception class rather than a limitation, so it would swallow any
// future backend gap, including one nobody has looked at. Each real
// limitation earns its own branch and its own section in
// KNOWN_DIVERGENCES.md.
func TestKnownDoesNotSuppressGenericBackendRefusal(t *testing.T) {
	err := errors.New("SigmaFeatureNotSupportedByBackendError: something new")
	if known(nil, err) {
		t.Fatal("a generic backend refusal must surface, not be suppressed as documented")
	}
}

func TestKnownReturnsFalseWithNoErrors(t *testing.T) {
	if known(nil, nil) {
		t.Fatal("known(nil, nil) must be false: there is nothing to suppress")
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
	if !oracleAvailable() {
		t.Skip("pySigma venv not built: python3 -m venv test/fuzz/.venv && test/fuzz/.venv/bin/pip install -r test/fuzz/requirements.txt")
	}
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	if err := o.proc.cmd.Process.Kill(); err != nil {
		t.Fatalf("killing the oracle subprocess: %v", err)
	}
	_, _ = o.proc.cmd.Process.Wait() // reap so the pipe closes promptly

	if _, _, err := o.Eval(seedRule, map[string]string{"Image": `C:\Windows\rundll32.exe`}); err == nil {
		t.Fatal("Eval after killing the subprocess should report the failure, not silently hang")
	}

	// The restart should have left a working subprocess in place.
	want, res, err := o.Eval(seedRule, map[string]string{"Image": `C:\Windows\rundll32.exe`})
	if err != nil {
		t.Fatalf("Eval after restart: %v", err)
	}
	if !want || len(res.Fields) != 1 || res.Fields[0] != "Image" {
		t.Fatalf("Eval after restart = %v, %+v, want a normal match on the seed rule", want, res)
	}
}

// TestOracleEvalRestartsOnTimeout pins the behavior the uncommitted change to
// Eval's timeout branch adds: on a timeout the hung subprocess is killed and
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
	if !oracleAvailable() {
		t.Skip("pySigma venv not built")
	}
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

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
	ev := map[string]string{"Image": strings.Repeat("a", 40) + "!"}

	start := time.Now()
	_, _, err = o.Eval(rule, ev)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrOracleTimeout) {
		t.Fatalf("Eval on a catastrophically backtracking pattern = %v, want ErrOracleTimeout", err)
	}
	if elapsed < oracleTimeout {
		t.Fatalf("Eval returned after %s, before oracleTimeout (%s) elapsed", elapsed, oracleTimeout)
	}

	// The subprocess must have been replaced: a normal request afterward
	// should get a normal answer, not the backtracking case's eventual (and
	// by now irrelevant) response.
	want, res, err := o.Eval(seedRule, map[string]string{"Image": `C:\Windows\rundll32.exe`})
	if err != nil {
		t.Fatalf("Eval after a timeout restart: %v", err)
	}
	if !want || len(res.Fields) != 1 || res.Fields[0] != "Image" {
		t.Fatalf("Eval after a timeout restart = %v, %+v, want a normal match on the seed rule", want, res)
	}
}
