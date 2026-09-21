package match

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestUTF16LE(t *testing.T) {
	got := UTF16LE("ab")
	want := "a\x00b\x00"
	if got != want {
		t.Fatalf("UTF16LE = %q want %q", got, want)
	}
	if UTF16BE("ab") != "\x00a\x00b" {
		t.Fatalf("UTF16BE = %q", UTF16BE("ab"))
	}
	if !strings.HasPrefix(UTF16("a"), "\xff\xfe") {
		t.Fatal("utf16 carries a little endian BOM")
	}
}

func TestUTF16SurrogatePair(t *testing.T) {
	// U+1F600 is outside the BMP, so it encodes as two UTF-16 units.
	if got := UTF16LE("\U0001F600"); len(got) != 4 {
		t.Fatalf("UTF16LE of an astral rune = %q, want 4 bytes", got)
	}
}

func TestBase64(t *testing.T) {
	if Base64("hello") != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Fatal("base64 must be standard encoding with padding")
	}
}

func TestBase64OffsetsFindEmbeddedPlaintext(t *testing.T) {
	plain := "MiniDump"
	offs := Base64Offsets(plain)
	// Every alignment of the plaintext inside a longer buffer must be found
	// by at least one of the three offset encodings.
	for pad := 0; pad < 3; pad++ {
		full := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("X", pad) + plain + "TAIL"))
		found := false
		for _, o := range offs {
			if o != "" && strings.Contains(full, o) {
				found = true
			}
		}
		if !found {
			t.Fatalf("pad %d: none of %q found in %q", pad, offs, full)
		}
	}
}

func TestBase64OffsetsAreSubstringsAtTheirAlignment(t *testing.T) {
	// Soundness: whenever an alignment yields a non-empty encoding, that
	// encoding must really appear in a buffer holding the plaintext at that
	// alignment. A short plaintext at a shifted alignment determines no
	// complete base64 character, so an empty offset is correct there and
	// pySigma produces one too.
	for n := 1; n <= 12; n++ {
		plain := "abcdefghijkl"[:n]
		offs := Base64Offsets(plain)
		for pad := 0; pad < 3; pad++ {
			full := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("X", pad) + plain + "TAIL"))
			if o := offs[pad]; o != "" && !strings.Contains(full, o) {
				t.Errorf("len %d pad %d: offset %q not in %q", n, pad, o, full)
			}
		}
	}
}

func TestBase64OffsetsFindAnyAlignmentOfARealisticValue(t *testing.T) {
	// Completeness at the lengths rules actually use: every alignment of a
	// plaintext of four bytes or more is found by one of the three offsets.
	for n := 4; n <= 12; n++ {
		plain := "abcdefghijkl"[:n]
		offs := Base64Offsets(plain)
		for pad := 0; pad < 3; pad++ {
			full := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("X", pad) + plain + "TAIL"))
			found := false
			for _, o := range offs {
				if o != "" && strings.Contains(full, o) {
					found = true
				}
			}
			if !found {
				t.Errorf("len %d pad %d: none of %q found in %q", n, pad, offs, full)
			}
		}
	}
}

func TestWinDashHasFiveVariants(t *testing.T) {
	got, err := WinDashVariants("-Enc")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-Enc", "/Enc", "–Enc", "—Enc", "―Enc"}
	if len(got) != len(want) {
		t.Fatalf("got %d variants %q, want 5", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("variant %d = %q want %q", i, got[i], want[i])
		}
	}
}

func TestWinDashLeavesNonDashAlone(t *testing.T) {
	got, err := WinDashVariants("Enc")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "Enc" {
		t.Fatalf("got %q, want the input unchanged", got)
	}
}

func TestWinDashExpandsEveryPosition(t *testing.T) {
	got, err := WinDashVariants("-nop -w hidden -enc")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 125 {
		t.Fatalf("got %d variants, want 125 for three dash positions", len(got))
	}
	seen := map[string]bool{}
	for _, v := range got {
		if seen[v] {
			t.Fatalf("duplicate variant %q", v)
		}
		seen[v] = true
	}
	for _, want := range []string{
		"-nop -w hidden -enc",
		"/nop /w hidden /enc",
		"–nop –w hidden –enc",
	} {
		if !seen[want] {
			t.Fatalf("variant %q missing", want)
		}
	}
}

func TestWinDashIgnoresInnerDash(t *testing.T) {
	// A dash between two word characters is not a switch introducer, so
	// pySigma leaves it alone and so must this.
	got, err := WinDashVariants("well-known")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "well-known" {
		t.Fatalf("got %q, want the input unchanged", got)
	}
}

func TestWinDashCapsExpansion(t *testing.T) {
	_, err := WinDashVariants("-a -b -c -d -e -f")
	if err == nil {
		t.Fatal("six dash positions must be an error, not 15625 variants")
	}
}
