package fuzz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vendorLiterals are the pySigma names and phrases pysigma_eval.py's
// refusal_code matches on, as an exception class plus the fixed start of
// its message. Suppressing on another project's prose is a standing bet
// that the prose does not change: a version bump that rewords one of these
// turns a documented divergence into a bare fuzz failure, with nothing
// pointing at the reword as the cause.
//
// This test makes the bet visible at bump time instead. It is not a style
// check: every literal here gates a suppression, and a literal that no longer
// appears in the installed source means that suppression is already dead.
// SQLite's own messages ("Expression tree is too large") are deliberately not
// here: they come from the C library through the sqlite3 module, not from any
// file this walk can read.
var vendorLiterals = []string{
	"Wide modifier only allowed for ascii strings",             // pySigma wide modifier
	"modifier only allowed for valid Unicode strings",          // pySigma utf16 modifiers
	"Base64 encoding of strings with wildcards is not allowed", // pySigma base64 modifiers
	"Unknown modifier",                  // pySigma modifier lookup
	"class SigmaIdentifierError",        // pySigma rule id validation
	"class SigmaRegularExpressionError", // pySigma regex validation
	"class SigmaModifierError",          // raised for an unknown modifier
	"class SigmaValueError",             // raised by the wide, utf16 and base64 modifiers
}

func TestSuppressionLiteralsStillExistInVendor(t *testing.T) {
	requireOracle(t)

	roots, err := filepath.Glob(filepath.Join(".venv", "lib", "python*", "site-packages", "sigma"))
	if err != nil || len(roots) == 0 {
		t.Skipf("pySigma source not found under .venv: %v", err)
	}

	var sb strings.Builder
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || filepath.Ext(path) != ".py" {
				return nil //nolint:nilerr // an unreadable file is not this test's business
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil //nolint:nilerr
			}
			sb.Write(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	source := sb.String()
	if source == "" {
		t.Skip("no pySigma source read")
	}

	for _, lit := range vendorLiterals {
		if !strings.Contains(source, lit) {
			t.Errorf("suppression literal %q no longer appears in the installed pySigma source.\n"+
				"Either the package reworded it, in which case update known() in oracle.go and the\n"+
				"matching section of KNOWN_DIVERGENCES.md, or the limitation is gone and the\n"+
				"suppression should be deleted.", lit)
		}
	}
}
