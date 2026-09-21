package sigma

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func loadTax(t *testing.T) *Taxonomy {
	t.Helper()
	tax, err := LoadTaxonomy("testdata/taxonomy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return tax
}

func TestTaxonomyResolve(t *testing.T) {
	tax := loadTax(t)
	e, ok := tax.Resolve(LogSource{Product: "windows", Category: "process_creation"})
	if !ok {
		t.Fatal("expected the sysmon entry to resolve")
	}
	if e.Fields["Image"] != "Image" {
		t.Fatalf("field mapping = %v", e.Fields)
	}
	if _, ok := tax.Resolve(LogSource{Product: "linux", Category: "process_creation"}); ok {
		t.Fatal("an unmapped logsource must not resolve")
	}
}

func TestTaxonomyResolveIsExactOnAllThreeComponents(t *testing.T) {
	tax := loadTax(t)

	// Same product and category, different service: two distinct entries
	// with different field mappings. A rule that names the service must get
	// the service entry, and one that omits it must get the entry that also
	// omits it. Blank is a value, not a wildcard.
	sysmon, ok := tax.Resolve(LogSource{Product: "windows", Category: "process_creation"})
	if !ok {
		t.Fatal("sysmon entry")
	}
	security, ok := tax.Resolve(LogSource{Product: "windows", Category: "process_creation", Service: "security"})
	if !ok {
		t.Fatal("security entry")
	}
	if sysmon.Fields["Image"] != "Image" || security.Fields["Image"] != "NewProcessName" {
		t.Fatalf("the two entries must not collapse: %q vs %q",
			sysmon.Fields["Image"], security.Fields["Image"])
	}
	if _, ok := tax.Resolve(LogSource{Product: "windows", Category: "process_creation", Service: "nope"}); ok {
		t.Fatal("an unknown service must not fall back to the blank-service entry")
	}
	if _, ok := tax.Resolve(LogSource{Product: "windows"}); ok {
		t.Fatal("a rule that omits the category must not match a category entry")
	}
}

func TestTaxonomySecondCategoryResolvesIndependently(t *testing.T) {
	tax := loadTax(t)
	net, ok := tax.Resolve(LogSource{Product: "windows", Category: "network_connection"})
	if !ok {
		t.Fatal("network_connection entry")
	}
	if net.Fields["DestinationIp"] != "DestinationIp" {
		t.Fatalf("field mapping = %v", net.Fields)
	}
	if _, ok := net.Match["event_id"]; !ok {
		t.Fatal("the entry carries its own match criteria")
	}
}

func TestTaxonomyMatcher(t *testing.T) {
	tax := loadTax(t)
	e, _ := tax.Resolve(LogSource{Product: "windows", Category: "process_creation"})
	m := tax.MatcherFor(e)

	good := &event.Event{Fields: map[string]event.Value{
		"channel":  event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id": event.Int(1),
	}}
	wrongID := &event.Event{Fields: map[string]event.Value{
		"channel":  event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id": event.Int(3),
	}}
	if !m.Matches(good) {
		t.Fatal("matching channel and event id should match")
	}
	if m.Matches(wrongID) {
		t.Fatal("a different event id must not match")
	}
	if m.Matches(&event.Event{Fields: map[string]event.Value{}}) {
		t.Fatal("an event with neither field must not match")
	}
}

func TestTaxonomyZeroMatcherMatchesEverything(t *testing.T) {
	// An entry with no match criteria binds every event of that logsource.
	// The zero LogSourceMatcher is the honest representation of that, and
	// the evaluator relies on it rather than on a nil check of its own.
	var m LogSourceMatcher
	if !m.Matches(&event.Event{}) {
		t.Fatal("a matcher with no criteria admits every event")
	}
}

func TestTaxonomyVersionIsStableAndContentSensitive(t *testing.T) {
	a := loadTax(t)
	b := loadTax(t)
	if a.Version != b.Version {
		t.Fatal("TaxonomyV must be stable across loads of identical content")
	}
	if a.Version == "" {
		t.Fatal("TaxonomyV must not be empty")
	}

	// One changed match value has to move the version, because it can change
	// which events a rule sees without changing the rule.
	dir := t.TempDir()
	src, err := os.ReadFile("testdata/taxonomy/sysmon.yml")
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(src), "event_id: 1", "event_id: 2", 1)
	if edited == string(src) {
		t.Fatal("fixture no longer carries the value this test edits")
	}
	if err := os.WriteFile(filepath.Join(dir, "sysmon.yml"), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := LoadTaxonomy(dir)
	if err != nil {
		t.Fatal(err)
	}

	same := t.TempDir()
	if err := os.WriteFile(filepath.Join(same, "sysmon.yml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	unchanged, err := LoadTaxonomy(same)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Version == unchanged.Version {
		t.Fatal("TaxonomyV must change when a match value changes")
	}
}

func TestTaxonomyRejectsDuplicateLogSourceNamingBothFiles(t *testing.T) {
	dir := t.TempDir()
	body := "logsource:\n  product: windows\n  category: process_creation\nmatch:\n  event_id: 1\nfields: {}\n"
	for _, name := range []string{"a.yml", "b.yml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := LoadTaxonomy(dir)
	if err == nil {
		t.Fatal("two entries for one logsource must fail to load")
	}
	for _, want := range []string{"a.yml", "b.yml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestTaxonomyRejectsEmptyDirAndBadYAML(t *testing.T) {
	if _, err := LoadTaxonomy(t.TempDir()); err == nil {
		t.Fatal("an empty taxonomy directory must be an error")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yml"), []byte("logsource: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTaxonomy(dir); err == nil {
		t.Fatal("malformed yaml must be an error")
	}
}

func TestTaxonomyRejectsAnEntryWithNoLogSource(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blank.yml"),
		[]byte("match:\n  event_id: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTaxonomy(dir); err == nil {
		t.Fatal("an entry with no logsource at all must be an error")
	}
}
