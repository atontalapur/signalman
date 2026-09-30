// Package fuzz holds the differential fuzzer: generated rules and generated
// events evaluated by both Signalman and pySigma, with disagreements failing
// the test. Loading a rule is not evaluating it, and the only check on the
// frontend's semantics up to now has been the same reading of the Sigma
// specification that produced the code.
package fuzz

import (
	"errors"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// oracleAvailable reports whether the pySigma venv exists. Every test here
// skips without it, so make check stays green on a machine with no Python
// environment built. Which means a green test run proves nothing on its own:
// the gate is the comparison count recorded in docs/corpus-acceptance.md.
func oracleAvailable() bool {
	_, err := os.Stat(venvPython)
	return err == nil
}

const seedRule = `title: seed
id: 00000000-0000-4000-8000-000000000000
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\rundll32.exe'
  condition: selection
`

func TestEvalOnceMatchesAndMisses(t *testing.T) {
	cases := []struct {
		name  string
		image string
		want  bool
	}{
		{"match", `C:\Windows\System32\rundll32.exe`, true},
		{"miss", `C:\Windows\System32\notepad.exe`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EvalOnce([]byte(seedRule), taxonomyDir, map[string]string{"Image": c.image})
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("EvalOnce = %v, want %v", got, c.want)
			}
		})
	}
}

// The oracle keys events by the field names a rule writes. Signalman keys
// them by the names the taxonomy maps those to, which for the security
// logsource is a rename rather than an identity. The bridge has to do that
// rename or every comparison against that logsource is meaningless.
func TestEvalOnceRenamesThroughTaxonomy(t *testing.T) {
	rule := `title: renamed
id: 00000000-0000-4000-8000-000000000001
logsource:
  product: windows
  service: security
  category: process_creation
detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection
`
	got, err := EvalOnce([]byte(rule), taxonomyDir, map[string]string{"Image": `C:\Windows\cmd.exe`})
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("EvalOnce = false, want true: Image should have been mapped to NewProcessName")
	}
}

// A logsource mismatch is a false verdict, not an error, but the fuzzer
// needs the event to belong to the rule's logsource or every case compares
// a false Signalman verdict against an oracle that has no logsource concept
// at all.
func TestEvalOnceAdmitsEventToItsLogsource(t *testing.T) {
	got, err := EvalOnce([]byte(seedRule), taxonomyDir, map[string]string{
		"Image":   `C:\Windows\rundll32.exe`,
		"channel": "wrong-channel",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("EvalOnce = false, want true: the taxonomy match criteria must win over event fields")
	}
}

func TestOracleAgreesOnSeed(t *testing.T) {
	if !oracleAvailable() {
		t.Skip("pySigma venv not built: python3 -m venv test/fuzz/.venv && test/fuzz/.venv/bin/pip install -r test/fuzz/requirements.txt")
	}
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	for _, image := range []string{`C:\Windows\rundll32.exe`, `C:\Windows\notepad.exe`} {
		ev := map[string]string{"Image": image}
		want, res, err := o.Eval(seedRule, ev)
		if err != nil {
			t.Fatalf("oracle: %v", err)
		}
		if len(res.Fields) != 1 || res.Fields[0] != "Image" {
			t.Fatalf("oracle fields = %v, want [Image]", res.Fields)
		}
		got, err := EvalOnce([]byte(seedRule), taxonomyDir, ev)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("image %q: signalman=%v oracle=%v", image, got, want)
		}
	}
}

// The oracle reports the fields a rule reads so a case that lands in the
// three-valued-logic gap can be told apart from a real disagreement. Without
// that, every negated condition over an absent field is a false failure.
func TestOracleReportsAbsentFieldGap(t *testing.T) {
	if !oracleAvailable() {
		t.Skip("pySigma venv not built")
	}
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	rule := `title: negated
id: 00000000-0000-4000-8000-000000000002
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '.exe'
  filter:
    User: 'bob'
  condition: selection and not filter
`
	ev := map[string]string{"Image": "a.exe"}
	want, res, err := o.Eval(rule, ev)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EvalOnce([]byte(rule), taxonomyDir, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got == want {
		t.Fatalf("the oracle no longer diverges on an absent field under negation "+
			"(both say %v). SQL three-valued logic is documented in "+
			"KNOWN_DIVERGENCES.md as the reason the fuzzer suppresses this case; "+
			"if the gap is gone, that suppression should go too.", got)
	}
	if !missingField(res.Fields, ev) {
		t.Fatal("expected the absent-field suppression to cover this case")
	}
}

// The acceptance divergences are a closed set: each is a documented
// difference in what the two implementations agree to load at all, and each
// has a section in KNOWN_DIVERGENCES.md. They are pinned here rather than
// left to the fuzzer because a closed set wants a test, not a search.
func TestKnownAcceptanceDivergences(t *testing.T) {
	if !oracleAvailable() {
		t.Skip("pySigma venv not built")
	}
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	// signalmanRejects records which side is expected to refuse the rule. A
	// divergence disappearing is not automatically good news: if Signalman
	// stops rejecting a rule with no id, that is the verdict-keying invariant
	// breaking, and a test that skipped there would hide exactly the
	// regression it exists to catch. The oracle's side may legitimately move
	// under a version bump, so that direction skips instead.
	cases := []struct {
		name             string
		signalmanRejects bool
		rule             string
	}{
		{"no id", true, `title: t
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: x
  condition: selection
`},
		{"non-uuid id", false, `title: t
id: not-a-uuid
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: x
  condition: selection
`},
		{"unmapped logsource", true, `title: t
id: 00000000-0000-4000-8000-00000000000b
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: x
  condition: selection
`},
		{"keywords", false, `title: t
id: 00000000-0000-4000-8000-00000000000c
logsource:
  product: windows
  category: process_creation
detection:
  keywords:
    - whoami
  condition: keywords
`},
		{"scalar search identifier", false, `title: t
id: 00000000-0000-4000-8000-00000000000d
logsource:
  product: windows
  category: process_creation
detection:
  selection: whoami
  condition: selection
`},
		{"cidr", false, `title: t
id: 00000000-0000-4000-8000-00000000000e
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: 10.0.0.0/8
  condition: selection
`},
		{"numeric comparison", false, `title: t
id: 00000000-0000-4000-8000-00000000000f
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationPort|gt: 1024
  condition: selection
`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, errG := EvalOnce([]byte(c.rule), taxonomyDir, map[string]string{"Image": "x"})
			_, _, errP := o.Eval(c.rule, map[string]string{"Image": "x"})

			// Signalman's side is an invariant this project owns, so a change
			// there fails rather than skips.
			if (errG != nil) != c.signalmanRejects {
				t.Fatalf("Signalman's side of this divergence moved: rejects=%v, want %v (err %v).\n"+
					"That is a change to what this engine loads, not to the oracle.",
					errG != nil, c.signalmanRejects, errG)
			}
			if (errG == nil) == (errP == nil) {
				t.Skipf("the oracle's side changed, this is no longer a divergence: "+
					"signalman=%v oracle=%v. Update KNOWN_DIVERGENCES.md.", errG, errP)
			}
			if !known(errG, errP) {
				t.Fatalf("undocumented acceptance divergence: signalman=%v oracle=%v", errG, errP)
			}
		})
	}
}

// FuzzAgainstPySigma drives values, a modifier chain, a field, and a
// condition shape into a valid rule skeleton, then requires the two engines
// to agree. See generate.go for why the rule is built rather than mutated.
func FuzzAgainstPySigma(f *testing.F) {
	if !oracleAvailable() {
		f.Skip("pySigma venv not built, see test/fuzz/requirements.txt")
	}
	o, err := StartOracle()
	if err != nil {
		f.Skipf("oracle unavailable: %v", err)
	}
	f.Cleanup(func() { _ = o.Close() })
	f.Cleanup(func() {
		FlushStats()
		f.Log(Stats())
	})

	// One seed per condition shape, and one per interesting chain, so
	// baseline coverage starts from cases that reach both engines.
	f.Add(uint8(0), uint8(0), uint8(0), `.exe`, `CORP\alice`, `C:\Windows\rundll32.exe`)
	f.Add(uint8(0), uint8(3), uint8(0), `\rundll32.exe`, `x`, `C:\Windows\rundll32.exe`)
	f.Add(uint8(1), uint8(1), uint8(3), `-sta`, `CORP\alice`, `rundll32 -sta foo`)
	f.Add(uint8(1), uint8(6), uint8(2), `whoami`, `x`, `dobG9hbW`)
	f.Add(uint8(1), uint8(7), uint8(0), `-enc`, `x`, `proc /enc y`)
	f.Add(uint8(1), uint8(4), uint8(1), `^rundll`, `x`, `rundll32`)
	f.Add(uint8(3), uint8(10), uint8(5), `alice`, `CORP`, `CORP\alice`)

	f.Fuzz(func(t *testing.T, fieldSel, modSel, condSel uint8, ruleVal, ruleVal2, eventVal string) {
		if ruleVal == "" || ruleVal2 == "" {
			recordOutcome(&statSkipped)
			t.Skip() // an empty rule value is a load error on both sides
		}
		if !utf8.ValidString(ruleVal) || !utf8.ValidString(ruleVal2) || !utf8.ValidString(eventVal) {
			recordOutcome(&statSkipped)
			// KNOWN_DIVERGENCES.md: yaml.Marshal renders a value that is not
			// valid UTF-8 as a !!binary node, which pySigma reads as bytes
			// and refuses. The bridge cannot express these at all.
			t.Skip()
		}
		if strings.HasPrefix(modChains[int(modSel)%len(modChains)], "re") && !reSafe(ruleVal) {
			recordOutcome(&statSkipped)
			t.Skip() // KNOWN_DIVERGENCES.md: RE2 against a backtracking engine
		}

		ruleYAML, ev, err := buildRule(fieldSel, modSel, condSel, ruleVal, ruleVal2, eventVal)
		if err != nil {
			recordOutcome(&statSkipped)
			t.Skip() // a value yaml.Marshal will not render is not a case
		}
		if !bridgeable(ruleYAML, ev) {
			recordOutcome(&statSkipped)
			t.Skip() // KNOWN_DIVERGENCES.md: the JSON bridge needs valid UTF-8
		}

		got, errG := EvalOnce([]byte(ruleYAML), taxonomyDir, ev)
		want, res, errP := o.Eval(ruleYAML, ev)

		if errors.Is(errP, ErrOracleTimeout) {
			recordOutcome(&statTimeout)
			t.Skip()
		}
		if (errG == nil) != (errP == nil) {
			if known(errG, errP) {
				recordOutcome(&statSuppressed)
				t.Skip()
			}
			t.Fatalf("acceptance mismatch: signalman=%v oracle=%v\nrule:\n%s", errG, errP, ruleYAML)
		}
		if errG != nil {
			recordOutcome(&statRejected)
			return
		}
		if got != want {
			if missingField(res.Fields, ev) {
				recordOutcome(&statSuppressed)
				t.Skip() // KNOWN_DIVERGENCES.md: SQL three-valued logic
			}
			if res.Degenerate {
				recordOutcome(&statSuppressed)
				t.Skip() // KNOWN_DIVERGENCES.md: empty encoded variants
			}
			t.Fatalf("verdict mismatch: signalman=%v oracle=%v\nrule:\n%s\nevent: %v",
				got, want, ruleYAML, ev)
		}
		recordOutcome(&statCompared)
	})
}
