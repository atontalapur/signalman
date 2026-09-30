package fuzz

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp/syntax"
	"sync"
	"time"

	"github.com/atontalapur/signalman/internal/sigma"
)

// venvPython is the interpreter the oracle runs in, relative to this package
// directory, which is where go test puts the working directory. The venv is
// gitignored and built from requirements.txt.
const venvPython = "./.venv/bin/python"

// maxOracleLine caps one oracle response. A generated rule can convert to a
// very long query and carry a very long error, and the default scanner
// buffer would turn that into a dead oracle rather than a skipped case.
const maxOracleLine = 4 << 20

// oracleStartup bounds the subprocess's warm-up. Importing pySigma takes
// seconds, and on a loaded machine (the race detector, several test packages
// at once) it takes more than the per-request budget. The subprocess says
// when it is ready, so the request deadline bounds evaluation and nothing
// else.
const oracleStartup = 60 * time.Second

// oracleTimeout bounds one request. Python's re engine backtracks, so a
// generated |re pattern can hang the subprocess for longer than the fuzz run
// and is not interruptible from inside Python. A blocked read there stalls a
// fuzz worker permanently, which is how a clean-looking run ends up having
// executed almost nothing.
const oracleTimeout = 5 * time.Second

// ErrOracleTimeout means the subprocess did not answer in time and has been
// replaced. The case is unevaluated, not disagreed on.
var ErrOracleTimeout = errors.New("oracle timed out")

// ErrOracleBroken means the bridge itself failed: the subprocess died,
// closed stdout, or wrote a line that is not a response. Nothing was
// evaluated, and unlike a timeout there is no documented reason for it, so
// the fuzz case fails rather than counting as a rejection.
var ErrOracleBroken = errors.New("oracle bridge broken")

// maxStderr is how much of Python's stderr is kept for diagnosis. One
// subprocess lives for the whole run, so an unbounded buffer grows with
// every warning; the traceback that explains a failure is at the end.
const maxStderr = 64 << 10

// RefusalError is the oracle declining a case for a reason it names with a
// code. Suppression keys on the code, which the oracle assigns from an
// exception class or its own checks, and never on the message, which can
// quote the rule's values.
type RefusalError struct {
	Code string
	Msg  string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("oracle refused rule [%s]: %s", e.Code, e.Msg)
}

// refusalCodes are the oracle refusals KNOWN_DIVERGENCES.md documents. Each
// is emitted by pysigma_eval.py; a code not listed here fails the case.
var refusalCodes = map[string]bool{
	"nul":                    true, // SQLite cannot carry a NUL in a query
	"base64offset-non-ascii": true, // pySigma trims by characters, not bytes
	"unsupported-modifier":   true, // cidr, lt/lte/gt/gte, fieldref
	"value-only":             true, // the backend has no keyword search form
	"regex-shorthand":        true, // \s \w \d name different sets in RE2
	"regex-brace":            true, // RE2 reads non-canonical braces literally
	"regex-newline":          true, // Python's $ matches before a final newline
	"unparenthesized-not":    true, // the backend's NOT a OR b defect
	"id-not-uuid":            true, // pySigma requires a UUID id
	"regex-python-rejects":   true, // Python's engine rejects what RE2 accepts
	"unknown-modifier":       true, // a modifier name pySigma does not carry
	"wide-non-ascii":         true, // pySigma's wide/utf16 accept ASCII only
	"wildcard-in-encoding":   true, // pySigma rejects a wildcard under base64
	"sqlite-depth":           true, // SQLite's parser depth limit
}

// Oracle wraps a long-lived pySigma subprocess speaking newline-delimited
// JSON. Starting an interpreter per case costs tens of milliseconds, which
// puts the plan's 1e6 executions out of reach.
type Oracle struct {
	mu      sync.Mutex
	proc    *oracleProc
	timeout time.Duration
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
	Refusal string   `json:"refusal"`
	// Degenerate means the oracle's query carries a term that matches every
	// row, which pySigma emits for an empty encoded variant. Signalman drops
	// those variants on purpose; see KNOWN_DIVERGENCES.md.
	Degenerate bool `json:"degenerate"`
}

// syncBuilder keeps the tail of the subprocess's stderr. exec writes it
// from its own goroutine while Eval may read it, so the writes need a lock.
type syncBuilder struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuilder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	if over := len(s.b) - maxStderr; over > 0 {
		s.b = append(s.b[:0], s.b[over:]...)
	}
	return len(p), nil
}

func (s *syncBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}

func StartOracle() (*Oracle, error) {
	p, err := startProc()
	if err != nil {
		return nil, err
	}
	return &Oracle{proc: p, timeout: oracleTimeout}, nil
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

	if err := p.awaitReady(); err != nil {
		p.kill()
		return nil, err
	}
	return p, nil
}

// awaitReady consumes the readiness line. A subprocess that dies during
// import reports the traceback here rather than as a timeout on whatever
// request happened to be first.
func (p *oracleProc) awaitReady() error {
	timer := time.NewTimer(oracleStartup)
	defer timer.Stop()

	select {
	case line, ok := <-p.lines:
		if !ok {
			return fmt.Errorf("oracle exited during startup:\n%s", p.stderr.String())
		}
		var res struct {
			Ready bool `json:"ready"`
		}
		if err := json.Unmarshal(line, &res); err != nil || !res.Ready {
			return fmt.Errorf("oracle sent %q before announcing readiness", line)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("oracle did not start within %s", oracleStartup)
	}
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
		return false, Result{}, o.restart(fmt.Errorf("%w: write: %w", ErrOracleBroken, err))
	}
	if err := p.in.Flush(); err != nil {
		return false, Result{}, o.restart(fmt.Errorf("%w: flush: %w", ErrOracleBroken, err))
	}

	timer := time.NewTimer(o.timeout)
	defer timer.Stop()

	var line []byte
	select {
	case l, ok := <-p.lines:
		if !ok {
			return false, Result{}, o.restart(fmt.Errorf("%w: closed stdout", ErrOracleBroken))
		}
		line = l
	case <-timer.C:
		// Replace the subprocess rather than leaving it hung. It still owns
		// an unanswered request, and whenever it finishes, that line would
		// be handed to the next Eval as though it answered that one: from
		// the first timeout onward every verdict would be compared against
		// the previous case's. restart wraps the cause, so the caller can
		// still recognize this with errors.Is.
		return false, Result{}, o.restart(fmt.Errorf("%w after %s", ErrOracleTimeout, o.timeout))
	}

	var res Result
	if err := json.Unmarshal(line, &res); err != nil {
		return false, Result{}, o.restart(fmt.Errorf("%w: bad response: %w", ErrOracleBroken, err))
	}
	if res.Refusal != "" {
		return false, res, &RefusalError{Code: res.Refusal, Msg: res.Error}
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
		// Both wrapped: the caller still needs to see a timeout as a
		// timeout, and a failed restart is a broken bridge either way.
		return fmt.Errorf("%w: oracle failed (%w) and would not restart: %w", ErrOracleBroken, cause, err)
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
//
// Each branch keys on a code or an error type. Error messages quote rule
// values, and rule values are whatever the fuzzer generated, so a message
// match is one a value can trigger.
func known(errG, errP error) bool {
	if errors.Is(errP, ErrOracleBroken) {
		return false // nothing was evaluated, and nobody documented why
	}
	if errors.Is(errP, ErrOracleTimeout) {
		return true // unevaluated, not disagreed on
	}
	var lerr *sigma.LoadError
	if errors.As(errG, &lerr) {
		switch lerr.Code {
		case sigma.CodeNoTaxonomy:
			return true // the oracle has no taxonomy layer at all
		case sigma.CodeAggregation:
			return true // deliberate scope cut; pySigma converts these
		case sigma.CodeMissingID:
			return true // verdicts are keyed on the id; pySigma allows none
		}
		var synErr *syntax.Error
		if errors.As(errG, &synErr) {
			return true // RE2 rejects what Python's engine accepts
		}
	}
	var refusal *RefusalError
	if errors.As(errP, &refusal) {
		return refusalCodes[refusal.Code]
	}
	return false
}
