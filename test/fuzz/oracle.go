package fuzz

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// venvPython is the interpreter the oracle runs in, relative to this package
// directory, which is where go test puts the working directory. The venv is
// gitignored and built from requirements.txt.
const venvPython = "./.venv/bin/python"

// maxOracleLine caps one oracle response. A generated rule can convert to a
// very long query and carry a very long error, and the default scanner
// buffer would turn that into a dead oracle rather than a skipped case.
const maxOracleLine = 4 << 20

// oracleTimeout bounds one request. Python's re engine backtracks, so a
// generated |re pattern can hang the subprocess for longer than the fuzz run
// and is not interruptible from inside Python. A blocked read there stalls a
// fuzz worker permanently, which is how a clean-looking run ends up having
// executed almost nothing.
const oracleTimeout = 5 * time.Second

// ErrOracleTimeout means the subprocess did not answer in time and has been
// replaced. The case is unevaluated, not disagreed on.
var ErrOracleTimeout = errors.New("oracle timed out")

// Oracle wraps a long-lived pySigma subprocess speaking newline-delimited
// JSON. Starting an interpreter per case costs tens of milliseconds, which
// puts the plan's 1e6 executions out of reach.
type Oracle struct {
	mu   sync.Mutex
	proc *oracleProc
}

// oracleProc is one subprocess and the goroutine draining its stdout. A
// timeout replaces the whole struct rather than trying to resynchronize a
// pipe whose next line belongs to an abandoned request.
type oracleProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	in     *bufio.Writer
	lines  chan []byte
	stderr *syncBuilder
}

type oracleReq struct {
	Rule  string            `json:"rule"`
	Event map[string]string `json:"event"`
}

// Result is what the oracle reports besides the verdict. Fields is every
// field the rule reads, used to recognize the documented gaps rather than
// report them as disagreements.
type Result struct {
	Matched bool     `json:"matched"`
	Fields  []string `json:"fields"`
	Error   string   `json:"error"`
	// Degenerate means the oracle's query carries a term that matches every
	// row, which pySigma emits for an empty encoded variant. Signalman drops
	// those variants on purpose; see KNOWN_DIVERGENCES.md.
	Degenerate bool `json:"degenerate"`
}

// syncBuilder collects the subprocess's stderr. exec writes it from its own
// goroutine while Eval may read it, so the writes need a lock.
type syncBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuilder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func StartOracle() (*Oracle, error) {
	p, err := startProc()
	if err != nil {
		return nil, err
	}
	return &Oracle{proc: p}, nil
}

func startProc() (*oracleProc, error) {
	cmd := exec.Command(venvPython, "pysigma_eval.py")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &syncBuilder{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	p := &oracleProc{
		cmd:    cmd,
		stdin:  stdin,
		in:     bufio.NewWriter(stdin),
		lines:  make(chan []byte, 1),
		stderr: stderr,
	}
	go p.drain(stdout)
	return p, nil
}

// drain reads responses so Eval can wait on a channel with a deadline
// instead of blocking in a pipe read it cannot abandon.
func (p *oracleProc) drain(stdout io.Reader) {
	defer close(p.lines)
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64<<10), maxOracleLine)
	for sc.Scan() {
		line := make([]byte, len(sc.Bytes()))
		copy(line, sc.Bytes())
		p.lines <- line
	}
}

func (p *oracleProc) kill() {
	_ = p.stdin.Close()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.cmd.Wait()
}

// Eval returns the oracle's verdict, its report, and any error it raised.
// An error from the oracle is a rejection of the rule, not a broken bridge:
// a dead or hung subprocess is reported as its own error so it cannot be
// mistaken for a rule the oracle declined.
func (o *Oracle) Eval(ruleYAML string, ev map[string]string) (bool, Result, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	b, err := json.Marshal(oracleReq{Rule: ruleYAML, Event: ev})
	if err != nil {
		// A rule or an event that will not marshal is the fuzzer's problem,
		// not the oracle's.
		return false, Result{}, err
	}

	p := o.proc
	if _, err := p.in.Write(append(b, '\n')); err != nil {
		return false, Result{}, o.restart(err)
	}
	if err := p.in.Flush(); err != nil {
		return false, Result{}, o.restart(err)
	}

	timer := time.NewTimer(oracleTimeout)
	defer timer.Stop()

	var line []byte
	select {
	case l, ok := <-p.lines:
		if !ok {
			return false, Result{}, o.restart(errors.New("oracle closed stdout"))
		}
		line = l
	case <-timer.C:
		return false, Result{}, fmt.Errorf("%w after %s", ErrOracleTimeout, oracleTimeout)
	}

	var res Result
	if err := json.Unmarshal(line, &res); err != nil {
		return false, Result{}, o.restart(err)
	}
	if res.Error != "" {
		return false, res, fmt.Errorf("oracle rejected rule: %s", res.Error)
	}
	return res.Matched, res, nil
}

// restart replaces the subprocess and wraps the failure with whatever Python
// wrote to stderr, because a traceback is the only thing that makes this
// class of failure diagnosable after a long fuzz run. Called with the lock
// held.
func (o *Oracle) restart(cause error) error {
	stderr := o.proc.stderr.String()
	o.proc.kill()

	p, err := startProc()
	if err != nil {
		return fmt.Errorf("oracle died (%v) and would not restart: %w", cause, err)
	}
	o.proc = p

	if stderr != "" {
		return fmt.Errorf("oracle restarted after: %w\npython stderr:\n%s", cause, stderr)
	}
	return fmt.Errorf("oracle restarted after: %w", cause)
}

func (o *Oracle) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.proc.kill()
	return nil
}

// known suppresses the documented differences between Signalman's load
// decisions and the oracle's. Every branch here has a section in
// KNOWN_DIVERGENCES.md; a suppression without one is how a differential
// fuzzer quietly stops finding things.
func known(errG, errP error) bool {
	if errors.Is(errP, ErrOracleTimeout) {
		return true // unevaluated, not disagreed on
	}
	if errG != nil {
		msg := errG.Error()
		switch {
		case strings.Contains(msg, "no taxonomy entry"),
			strings.Contains(msg, "does not resolve"):
			return true // the oracle has no taxonomy layer at all
		case strings.Contains(msg, "aggregation is not supported"):
			return true // deliberate scope cut; pySigma converts these
		case strings.Contains(msg, "[missing-id]"):
			return true // verdicts are keyed on the id; pySigma allows none
		case strings.Contains(msg, "error parsing regexp"):
			return true // RE2 rejects what Python's engine accepts
		}
	}
	if errP != nil {
		msg := errP.Error()
		switch {
		case strings.Contains(msg, "unsupported-modifier:"):
			return true // the backend answers these wrongly, so it refuses
		case strings.Contains(msg, "unsupported-feature:"):
			return true // a Sigma form the backend has no query for
		case strings.Contains(msg, "unsupported-value:"):
			return true // a value SQLite cannot carry in a query
		case strings.Contains(msg, "unsupported-query:"):
			return true // the backend generated a query it got wrong
		case strings.Contains(msg, "Expression tree is too large"):
			return true // SQLite's parser depth, not a Sigma question
		case strings.Contains(msg, "SigmaIdentifierError"):
			return true // pySigma requires a UUID id; Signalman requires an id
		case strings.Contains(msg, "Full Text Search"),
			strings.Contains(msg, "keywords"):
			return true // the backend has no value-only expression form
		case strings.Contains(msg, "only allowed for ascii strings"),
			strings.Contains(msg, "only allowed for valid Unicode strings"):
			// pySigma's wide and utf16 modifiers encode to UTF-16 and then
			// decode the result as UTF-8, so they accept ASCII and little
			// else. Signalman encodes the text and compares bytes.
			return true
		case strings.Contains(msg, "strings with wildcards is not allowed"):
			return true // Signalman encodes the wildcard as a literal byte
		case strings.Contains(msg, "SigmaRegularExpressionError"):
			return true // Python's engine rejects what RE2 accepts
		case strings.Contains(msg, "Unknown modifier"):
			return true // a modifier name pySigma does not carry
		case strings.Contains(msg, "SigmaFeatureNotSupportedByBackendError"):
			return true // a Sigma feature the sqlite backend declines
		}
	}
	return false
}
