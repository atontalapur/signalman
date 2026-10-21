package ch

// These tests check, without a ClickHouse server, that each piece the SQL
// is built from means what v1 means. The SQL side is modelled on the
// ClickHouse documentation for the functions used; the integration test is
// what checks the model against a real server.

import (
	"encoding/hex"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

func TestEncode(t *testing.T) {
	ev := &event.Event{
		Seq: 7, Partition: 2, Source: "s",
		EventTime: msTime(1500).Add(999), IngestAt: msTime(1600),
		Fields: map[string]event.Value{
			"S":     event.String("MiXed"),
			"I":     event.Int(-42),
			"B":     event.Bool(true),
			"N":     event.Null(),
			"E":     event.String(""),
			"L":     event.List(event.String(" 8 "), event.Null(), event.List(event.String("nested")), event.Int(9)),
			"Empty": event.List(),
			"Bad":   event.String("a\xffb"),
			"Num":   event.String("+5"),
			"Hex":   event.String("0x10"),
			"Big":   event.String("9223372036854775808"),
			"IP4":   event.String("10.1.2.3"),
			"IP6":   event.String("2001:db8::1"),
			"Zone":  event.String("fe80::1%eth0"),
			"Lead":  event.String("010.1.2.3"),
			"Kel":   event.String("\u212a"),
		},
		Raw: []byte(`{"raw":1}`),
	}
	r := Encode(ev)
	if r.Seq != 7 || r.Partition != 2 || r.Source != "s" || r.Raw != `{"raw":1}` {
		t.Fatalf("header: %+v", r)
	}
	if !r.EventTime.Equal(msTime(1500)) {
		t.Fatalf("event time %v not truncated to the millisecond", r.EventTime)
	}
	wantPresent := []string{"B", "Bad", "Big", "E", "Empty", "Hex", "I", "IP4", "IP6", "Kel", "L", "Lead", "Num", "S", "Zone"}
	if !reflect.DeepEqual(r.Present, wantPresent) {
		t.Fatalf("present = %q", r.Present)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"folded S", r.Folded["S"], []string{"mixed"}},
		{"text S", r.Text["S"], []string{"MiXed"}},
		{"folded I", r.Folded["I"], []string{"-42"}},
		{"folded B", r.Folded["B"], []string{"true"}},
		{"folded E", r.Folded["E"], []string{""}},
		{"folded N", r.Folded["N"], []string(nil)},
		{"folded L", r.Folded["L"], []string{" 8 ", "9"}},
		{"folded Empty", r.Folded["Empty"], []string(nil)},
		{"text Bad", r.Text["Bad"], []string{"a\ufffdb"}},
		{"folded Bad", r.Folded["Bad"], []string{"a\ufffdb"}},
		{"ints I", r.Ints["I"], []int64{-42}},
		{"ints L", r.Ints["L"], []int64{8, 9}},
		{"ints Num", r.Ints["Num"], []int64{5}},
		{"ints Hex", r.Ints["Hex"], []int64(nil)},
		{"ints Big", r.Ints["Big"], []int64(nil)},
		{"ints B", r.Ints["B"], []int64(nil)},
		{"ips IP4", r.IPs["IP4"], []string{"40a010203"}},
		{"ips IP6", r.IPs["IP6"], []string{"620010db8000000000000000000000001"}},
		{"ips Zone", r.IPs["Zone"], []string(nil)},
		{"ips Lead", r.IPs["Lead"], []string(nil)},
		{"eqfold Kel", r.EqFold["Kel"], []string{"K"}},
		{"folded Kel", r.Folded["Kel"], []string{"k"}},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s = %#v, want %#v", c.name, c.got, c.want)
		}
	}
}

// decodeLit reads one literal the compiler wrote, plain or unhex, from the
// start of s and returns its value and the rest of s.
func decodeLit(t testing.TB, s string) (string, string) {
	t.Helper()
	if rest, ok := strings.CutPrefix(s, "unhex('"); ok {
		end := strings.Index(rest, "')")
		b, err := hex.DecodeString(rest[:end])
		if err != nil {
			t.Fatalf("bad hex in %q", s)
		}
		return string(b), rest[end+2:]
	}
	if rest, ok := strings.CutPrefix(s, "'"); ok {
		end := strings.IndexByte(rest, '\'')
		return rest[:end], rest[end+1:]
	}
	t.Fatalf("no literal at %q", s)
	return "", ""
}

// evalShape evaluates one wildcard test, as wildcardSQL writes it, on x.
func evalShape(t testing.TB, expr, x string) bool {
	t.Helper()
	switch {
	case expr == "1":
		return true
	case strings.HasPrefix(expr, "startsWith(x, "):
		lit, rest := decodeLit(t, strings.TrimPrefix(expr, "startsWith(x, "))
		mustBe(t, rest, ")")
		return strings.HasPrefix(x, lit)
	case strings.HasPrefix(expr, "endsWith(x, "):
		lit, rest := decodeLit(t, strings.TrimPrefix(expr, "endsWith(x, "))
		mustBe(t, rest, ")")
		return strings.HasSuffix(x, lit)
	case strings.HasPrefix(expr, "position(x, "):
		lit, rest := decodeLit(t, strings.TrimPrefix(expr, "position(x, "))
		mustBe(t, rest, ") > 0")
		return strings.Contains(x, lit)
	case strings.HasPrefix(expr, "x LIKE "):
		pat, rest := decodeLit(t, strings.TrimPrefix(expr, "x LIKE "))
		mustBe(t, rest, "")
		return likeRef(x, pat)
	}
	t.Fatalf("unknown shape %q", expr)
	return false
}

func mustBe(t testing.TB, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("trailing %q, want %q", got, want)
	}
}

// likeRef is LIKE as the ClickHouse documentation defines it on valid
// UTF-8: % is any run of code points, _ is one code point, and a backslash
// escapes %, _, or \ and is literal before anything else.
func likeRef(s, pattern string) bool {
	type tok struct {
		kind byte // 'l' literal, '%', '_'
		r    rune
	}
	var toks []tok
	pr := []rune(pattern)
	for i := 0; i < len(pr); i++ {
		switch c := pr[i]; {
		case c == '\\' && i+1 < len(pr) && (pr[i+1] == '%' || pr[i+1] == '_' || pr[i+1] == '\\'):
			i++
			toks = append(toks, tok{'l', pr[i]})
		case c == '%' || c == '_':
			toks = append(toks, tok{kind: byte(c)})
		default:
			toks = append(toks, tok{'l', c})
		}
	}
	in := []rune(s)
	// dp[j] reports whether toks[:i] matches in[:j].
	dp := make([]bool, len(in)+1)
	dp[0] = true
	for _, tk := range toks {
		next := make([]bool, len(in)+1)
		for j := 0; j <= len(in); j++ {
			switch tk.kind {
			case '%':
				next[j] = dp[j] || (j > 0 && next[j-1])
			case '_':
				next[j] = j > 0 && dp[j-1]
			default:
				next[j] = j > 0 && dp[j-1] && in[j-1] == tk.r
			}
		}
		dp = next
	}
	return dp[len(in)]
}

func TestLikeRef(t *testing.T) {
	cases := []struct {
		s, p string
		want bool
	}{
		{"abc", "a%", true}, {"abc", "a_c", true}, {"abc", "a_", false},
		{"a%c", `a\%c`, true}, {"abc", `a\%c`, false}, {`a\c`, `a\c`, true},
		{`a\c`, `a\\c`, true}, {"¥", "_", true}, {"a\nb", "a%b", true},
	}
	for _, c := range cases {
		if got := likeRef(c.s, c.p); got != c.want {
			t.Errorf("likeRef(%q, %q) = %v", c.s, c.p, got)
		}
	}
}

// checkWildcard compares the compiled test against the purpose-built
// matcher for one pattern and one event text.
func checkWildcard(t *testing.T, pattern, text string) {
	w := match.CompileWildcard(pattern)
	want := w.MatchString(text)
	folded := strings.ToLower(text)
	if !utf8.ValidString(folded) {
		t.Fatalf("folded text %q is not valid UTF-8", folded)
	}
	parts := w.Parts()
	var got bool
	if lit, ok := exactLiteral(parts); ok {
		got = folded == lit
	} else {
		got = evalShape(t, wildcardSQL("x", parts), folded)
	}
	if got != want {
		t.Fatalf("pattern %q text %q: sql %v, matcher %v (parts %+v)", pattern, text, got, want, parts)
	}
}

func FuzzWildcardSQL(f *testing.F) {
	for _, s := range [][2]string{
		{`*\cmd.exe`, `C:\Windows\CMD.EXE`}, {"a*b?c", "aXXbYc"}, {"50%*", "50%off"},
		{`a\*b`, "a*b"}, {"*", ""}, {"?", "é"}, {"a_b", "aXb"}, {"İ*", "i̇x"},
		{`dir\`, `DIR\`}, {"*\u212a*", "k"}, {"a*", "a\xffb"}, {"?", "\xff"},
		{`x\\*`, `x\yz`}, {"%", "%"}, {"*a*b*", "xaybz"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, text string) {
		checkWildcard(t, pattern, text)
	})
}

// The regex the SQL runs, read by Go as RE2 would read it under
// ClickHouse's dot_nl, on the stored text, agrees with v1's regex on the
// event text.
func checkRegex(t *testing.T, pattern, text string, insensitive bool) {
	m, err := match.Plan(reMods(insensitive), []event.Value{event.String(pattern)})
	if err != nil {
		return // not a regex v1 would load
	}
	re := m.Values[0].Regex
	want := re.MatchString(text)
	out, err := re2Pattern(re.String())
	if err != nil {
		t.Fatalf("%q: %v", re.String(), err)
	}
	for i := 0; i < len(out); i++ {
		if out[i] >= utf8.RuneSelf || out[i] == 0 || out[i] == '.' {
			t.Fatalf("%q renders with byte %q: %q", pattern, out[i], out)
		}
	}
	got := regexp.MustCompile("(?s)" + out).MatchString(runeSafe(text))
	if got != want {
		t.Fatalf("pattern %q text %q: rendered %q says %v, v1 says %v", re.String(), text, out, got, want)
	}
}

func reMods(insensitive bool) []string {
	if insensitive {
		return []string{"re", "i"}
	}
	return []string{"re"}
}

func FuzzRE2Pattern(f *testing.F) {
	seeds := []struct {
		p, s string
		i    bool
	}{
		{"a.c", "a\nc", false}, {"^a.*b$", "a\nb", false}, {"(?s)a.b", "a\nb", false},
		{"K", "\u212a", true}, {`\p{Lu}+`, "ÀB", false}, {"[^a]", "\xff", false},
		{"^.$", "\xff", false}, {`(?m)^b$`, "a\nb\n", false}, {`a$`, "a\n", false},
		{`\bfoo\b`, "a foo.", false}, {"(?i)straße", "STRASSE", false},
		{"(?P<x>ab)+?", "abab", false}, {"(?U)a+", "aaa", false}, {`[[:alpha:]]{2,3}`, "ab1", false},
		{`\x{1F600}`, "\U0001F600", false}, {"ǅ", "ǆ", true}, {`\Qa.b\E`, "a.b", false},
	}
	for _, s := range seeds {
		f.Add(s.p, s.s, s.i)
	}
	f.Fuzz(func(t *testing.T, pattern, text string, insensitive bool) {
		if len(pattern) > 64 {
			return // large counted repeats make the oracle slow, not wrong
		}
		checkRegex(t, pattern, text, insensitive)
	})
}

// FoldKey equality is strings.EqualFold, which is what fieldref compares.
func FuzzFoldKey(f *testing.F) {
	for _, s := range [][2]string{
		{"k", "\u212a"}, {"s", "\u017f"}, {"ß", "ẞ"}, {"İ", "i"}, {"\xff", "\xfe"},
		{"\xff", "\ufffd"}, {"ǅ", "ǆ"}, {"abc", "ABD"}, {"", ""},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		for _, other := range []string{b, strings.ToUpper(a), strings.ToLower(a), strings.ToTitle(a)} {
			want := strings.EqualFold(a, other)
			if got := FoldKey(a) == FoldKey(other); got != want {
				t.Fatalf("FoldKey(%q) == FoldKey(%q) is %v, EqualFold is %v", a, other, got, want)
			}
		}
	})
}

// The cidr range over stored keys is match.CIDR.
func FuzzCIDR(f *testing.F) {
	for _, s := range [][2]string{
		{"10.0.0.0/8", "10.1.2.3"}, {"10.0.0.0/8", "11.0.0.0"}, {"0.0.0.0/0", "1.2.3.4"},
		{"::/0", "1.2.3.4"}, {"::ffff:0:0/96", "1.2.3.4"}, {"::ffff:0:0/96", "::ffff:1.2.3.4"},
		{"2001:db8::/32", "2001:db8::1"}, {"fe80::/10", "fe80::1%eth0"}, {"10.1.2.3/32", "10.1.2.3"},
		{"1.2.3.4/24", " 1.2.3.4"}, {"::/128", "::"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, prefix, addr string) {
		m, err := match.CIDR(prefix)
		if err != nil {
			return
		}
		want := m.Match(event.String(addr), nil)
		p := netip.MustParsePrefix(prefix).Masked()
		lo, hi := prefixRange(p)
		key, ok := IPKey(addr)
		got := ok && key >= lo && key <= hi
		if got != want {
			t.Fatalf("cidr %q addr %q: range [%s, %s] key %q says %v, v1 says %v", prefix, addr, lo, hi, key, got, want)
		}
	})
}

// The ints column holds exactly the values match.Compare compares.
func FuzzInts(f *testing.F) {
	for _, s := range []string{"7", " 7 ", "+7", "-0", "0x7", "7.0", "9223372036854775807", "9223372036854775808", "\u00a07", "1_000", ""} {
		f.Add(s, int64(7))
	}
	f.Fuzz(func(t *testing.T, s string, n int64) {
		ev := &event.Event{Fields: map[string]event.Value{"F": event.String(s)}}
		ints := Encode(ev).Ints["F"]
		for _, op := range []string{"lt", "lte", "gt", "gte"} {
			m, err := match.Compare(op, n)
			if err != nil {
				t.Fatal(err)
			}
			want := m.Match(ev.Field("F"), ev)
			got := false
			for _, x := range ints {
				switch op {
				case "lt":
					got = got || x < n
				case "lte":
					got = got || x <= n
				case "gt":
					got = got || x > n
				case "gte":
					got = got || x >= n
				}
			}
			if got != want {
				t.Fatalf("%q %s %d: ints %v say %v, v1 says %v", s, op, n, ints, got, want)
			}
		}
	})
}

// TTL and partitioning read ingest_time, which the pipeline sets. event_time
// comes from the source: an old or skewed value would be TTL-deleted on
// arrival, and a batch spread over more than 100 days would be refused.
func TestCreateTableKeysRetentionOnIngestTime(t *testing.T) {
	ddl, err := CreateTableSQL(DefaultTable)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PARTITION BY toYYYYMMDD(ingest_time)",
		"TTL toDateTime(ingest_time) + INTERVAL 90 DAY",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("DDL lacks %q:\n%s", want, ddl)
		}
	}
	for _, line := range strings.Split(ddl, "\n") {
		if (strings.HasPrefix(line, "PARTITION BY") || strings.HasPrefix(line, "TTL")) && strings.Contains(line, "event_time") {
			t.Errorf("retention reads event_time: %s", line)
		}
	}
}
