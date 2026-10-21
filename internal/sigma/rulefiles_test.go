package sigma

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIsFixture(t *testing.T) {
	cases := map[string]bool{
		"rules/proc_dump.yml":       false,
		"rules/proc_dump.yaml":      false,
		"rules/proc_dump.test.yml":  true,
		"rules/proc_dump.test.yaml": true,
		"rules/test.yml":            false,
		"rules/latest.yml":          false,
	}
	for path, want := range cases {
		if got := IsFixture(path); got != want {
			t.Errorf("IsFixture(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestFixturePathSitsBesideTheRule(t *testing.T) {
	cases := map[string]string{
		"rules/proc_dump.yml":  "rules/proc_dump.test.yml",
		"rules/proc_dump.yaml": "rules/proc_dump.test.yaml",
	}
	for rule, want := range cases {
		if got := FixturePath(rule); got != want {
			t.Errorf("FixturePath(%q) = %q, want %q", rule, got, want)
		}
	}
}

func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuleFilesSkipsFixturesAndSorts(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "b.yml", "b.test.yml", "a.yaml", "sub/c.yml", "notes.txt")

	got, err := RuleFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(dir, "a.yaml"),
		filepath.Join(dir, "b.yml"),
		filepath.Join(dir, "sub/c.yml"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRuleFilesTakesFilesAndDirsAndDedupes(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "a.yml", "a.test.yml", "sub/b.yml")

	// A shell glob such as rules/*.yml hands over the fixtures too. They are
	// never rules, so naming one explicitly still skips it.
	got, err := RuleFiles(filepath.Join(dir, "sub"), filepath.Join(dir, "a.yml"),
		filepath.Join(dir, "a.test.yml"), filepath.Join(dir, "a.yml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "a.yml"), filepath.Join(dir, "sub/b.yml")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRuleFilesDedupesOneFileUnderTwoSpellings(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "a.yml")
	t.Chdir(dir)

	// The same file, relative and absolute, is one rule file, not a
	// duplicate id. The first spelling given is the one kept for display.
	got, err := RuleFiles("a.yml", filepath.Join(dir, "a.yml"), ".")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.yml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRuleFilesMissingPathIsAnError(t *testing.T) {
	if _, err := RuleFiles("testdata/does_not_exist"); err == nil {
		t.Fatal("a missing path is an operator error")
	}
}

func TestLoadRuleSetIgnoresFixtureFiles(t *testing.T) {
	tax := loadTax(t)
	dir := t.TempDir()
	src, err := os.ReadFile("testdata/rules/proc_dump.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proc_dump.yml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := "rule: proc_dump.yml\ncases: []\n"
	if err := os.WriteFile(filepath.Join(dir, "proc_dump.test.yml"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, errs, err := LoadRuleSet(dir, tax)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 1 || len(errs) != 0 {
		t.Fatalf("a fixture file is not a rule: got %d rules, rejections %+v", len(rs.Rules), errs)
	}
}

func TestLoadRuleFilesMatchesLoadRuleSet(t *testing.T) {
	tax := loadTax(t)
	paths, err := RuleFiles("testdata/rules")
	if err != nil {
		t.Fatal(err)
	}
	a, aerrs := LoadRuleFiles(paths, tax)
	b, berrs, err := LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != b.Version || len(a.Rules) != len(b.Rules) || len(aerrs) != len(berrs) {
		t.Fatalf("LoadRuleFiles and LoadRuleSet disagree: %s/%d/%d vs %s/%d/%d",
			a.Version, len(a.Rules), len(aerrs), b.Version, len(b.Rules), len(berrs))
	}
}
