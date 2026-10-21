package aho

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

// naive is the specification: pattern i is reported iff it occurs in text.
func naive(pats []string, text []byte) []int32 {
	var out []int32
	for i, p := range pats {
		if bytes.Contains(text, []byte(p)) {
			out = append(out, int32(i))
		}
	}
	return out
}

func distinct(hits []int32) []int32 {
	sort.Slice(hits, func(a, b int) bool { return hits[a] < hits[b] })
	out := hits[:0]
	for i, h := range hits {
		if i == 0 || h != hits[i-1] {
			out = append(out, h)
		}
	}
	return out
}

func equal(a, b []int32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScanFindsOverlappingAndNestedPatterns(t *testing.T) {
	pats := []string{"he", "she", "his", "hers", `\cmd.exe`, "e"}
	m, err := New(pats)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"ushers", `c:\windows\cmd.exe`, "", "xyz", "hishe"} {
		got := distinct(m.Scan([]byte(text), nil))
		want := naive(pats, []byte(text))
		if !equal(got, want) {
			t.Fatalf("Scan(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestScanAppendsToTheBuffer(t *testing.T) {
	m, err := New([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	got := m.Scan([]byte("aa"), []int32{9})
	if !equal(got, []int32{9, 0, 0}) {
		t.Fatalf("Scan = %v, want one hit per occurrence after the existing element", got)
	}
}

func TestNewRejectsEmptyAndDuplicatePatterns(t *testing.T) {
	if _, err := New([]string{"a", ""}); err == nil {
		t.Fatal("an empty pattern matches everywhere and must be rejected")
	}
	if _, err := New([]string{"a", "a"}); err == nil {
		t.Fatal("a duplicate pattern must be rejected")
	}
}

func TestScanAgreesWithNaiveOnRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alpha := []byte("abc\\.é")
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[rng.Intn(len(alpha))]
		}
		return string(b)
	}
	for round := 0; round < 300; round++ {
		seen := map[string]bool{}
		var pats []string
		for len(pats) < 1+rng.Intn(20) {
			w := word(1 + rng.Intn(5))
			if !seen[w] {
				seen[w] = true
				pats = append(pats, w)
			}
		}
		m, err := New(pats)
		if err != nil {
			t.Fatal(err)
		}
		for k := 0; k < 20; k++ {
			text := []byte(word(rng.Intn(40)))
			if got, want := distinct(m.Scan(text, nil)), naive(pats, text); !equal(got, want) {
				t.Fatalf("patterns %q text %q: got %v want %v", pats, text, got, want)
			}
		}
	}
}

func FuzzScan(f *testing.F) {
	f.Add("he\x00she\x00hers", "ushers")
	f.Add("a\x00ab\x00abc", "xabcabx")
	f.Fuzz(func(t *testing.T, joined, text string) {
		seen := map[string]bool{}
		var pats []string
		for _, p := range bytes.Split([]byte(joined), []byte{0}) {
			if len(p) > 0 && !seen[string(p)] {
				seen[string(p)] = true
				pats = append(pats, string(p))
			}
		}
		if len(pats) == 0 {
			return
		}
		m, err := New(pats)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := distinct(m.Scan([]byte(text), nil)), naive(pats, []byte(text)); !equal(got, want) {
			t.Fatalf("patterns %q text %q: got %v want %v", pats, text, got, want)
		}
	})
}

func BenchmarkScan(b *testing.B) {
	pats := []string{`\rundll32.exe`, "comsvcs", "minidump", `\powershell.exe`, "-enc", "invoke-", "mimikatz"}
	m, err := New(pats)
	if err != nil {
		b.Fatal(err)
	}
	text := []byte(`rundll32.exe c:\windows\system32\comsvcs.dll, minidump 624 c:\t.dmp full`)
	var hits []int32
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		hits = m.Scan(text, hits[:0])
	}
}
