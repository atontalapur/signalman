package match

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
)

// UTF16LE encodes as little endian UTF-16 with no BOM. Chained before
// base64, which is the order the modifier list is written in and the order
// that matters.
func UTF16LE(s string) string { return utf16Bytes(s, true, false) }

// UTF16BE encodes as big endian UTF-16 with no BOM.
func UTF16BE(s string) string { return utf16Bytes(s, false, false) }

// UTF16 encodes as little endian UTF-16 with a BOM.
func UTF16(s string) string { return utf16Bytes(s, true, true) }

func utf16Bytes(s string, little, bom bool) string {
	units := utf16.Encode([]rune(s))
	var b strings.Builder
	b.Grow(len(units)*2 + 2)
	write := func(u uint16) {
		if little {
			b.WriteByte(byte(u))
			b.WriteByte(byte(u >> 8))
		} else {
			b.WriteByte(byte(u >> 8))
			b.WriteByte(byte(u))
		}
	}
	if bom {
		write(0xFEFF)
	}
	for _, u := range units {
		write(u)
	}
	return b.String()
}

// Base64 is standard encoding with padding, which is what the |base64
// modifier means.
func Base64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Base64Offsets returns the three encodings of s that correspond to the
// three possible byte alignments of the plaintext inside a longer buffer.
// The leading and trailing characters of each encoding are trimmed because
// they carry bits of the neighbouring plaintext, which is unknown.
//
// The start and end offsets are the ones pySigma uses, but the trim is
// indexed by the plaintext's length in bytes, not in characters. base64
// works on bytes, so byte length is the right index; pySigma uses the
// character count and so trims a multi-byte plaintext wrongly. The two agree
// on ASCII and nowhere else, which is why the differential fuzzer's oracle
// declines base64offset on a non-ASCII value. See
// test/fuzz/KNOWN_DIVERGENCES.md.
func Base64Offsets(s string) [3]string {
	starts := [3]int{0, 2, 3}
	ends := [3]int{0, -3, -2} // indexed by (len(s)+i)%3; 0 means no trim
	var out [3]string
	for i := 0; i < 3; i++ {
		enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(" ", i) + s))
		end := len(enc)
		if e := ends[(len(s)+i)%3]; e != 0 {
			end += e
		}
		if starts[i] >= end {
			out[i] = ""
			continue
		}
		out[i] = enc[starts[i]:end]
	}
	return out
}

// winDashChars are the five characters a Windows command line parser accepts
// where a rule author wrote a hyphen. Five, not two, which is the usual
// mistake.
var winDashChars = []string{"-", "/", "–", "—", "―"}

// winDashPos finds the dashes that introduce a switch: a hyphen or slash
// preceded by a non-word character and followed by a word character. A dash
// inside a word ("well-known") is not a switch and is left alone. This is
// pySigma's rule.
var winDashPos = regexp.MustCompile(`\B[-/]\b`)

// maxWinDashPositions caps the fan-out. Five positions is already 3125
// matchers for one detection value; past that the rule is almost certainly
// a mistake and the expansion would cost more than the rule is worth.
const maxWinDashPositions = 5

// WinDashVariants returns the cartesian product of the five dash characters
// over every switch-introducing dash in s. The input itself is always the
// first variant.
func WinDashVariants(s string) ([]string, error) {
	pos := winDashPos.FindAllStringIndex(s, -1)
	if len(pos) == 0 {
		return []string{s}, nil
	}
	if len(pos) > maxWinDashPositions {
		return nil, fmt.Errorf("windash: %d dash positions in %q exceeds the limit of %d",
			len(pos), s, maxWinDashPositions)
	}

	// Split s into the fixed segments between dash positions, so a variant
	// is one segment, one dash character, the next segment, and so on.
	segs := make([]string, 0, len(pos)+1)
	prev := 0
	for _, p := range pos {
		segs = append(segs, s[prev:p[0]])
		prev = p[1]
	}
	segs = append(segs, s[prev:])

	out := []string{""}
	for i, seg := range segs {
		if i == len(segs)-1 {
			for j := range out {
				out[j] += seg
			}
			break
		}
		next := make([]string, 0, len(out)*len(winDashChars))
		for _, pre := range out {
			for _, d := range winDashChars {
				next = append(next, pre+seg+d)
			}
		}
		out = next
	}
	return out, nil
}
