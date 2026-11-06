package ch

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// uh is the unhex form a literal outside the plain character set takes.
func uh(s string) string { return "unhex('" + hex.EncodeToString([]byte(s)) + "')" }

func mustRE2(t *testing.T, goPattern string) string {
	t.Helper()
	p, err := re2Pattern(goPattern)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// One golden per node type and per modifier the frontend accepts.
func TestCompileGolden(t *testing.T) {
	tax := testTaxonomy(t)
	pos := func(lit string) string { return "position(x, " + lit + ") > 0" }
	exists := func(body, arr string) string { return "arrayExists(x -> " + body + ", " + arr + ")" }
	cases := []struct {
		name, det, want string
	}{
		// Equality and case folding: the rule value is folded with
		// strings.ToLower at compile time, the event at write time.
		{"equals", "s:\n  Image: abc\ncondition: s",
			"has(f_folded['Image'], 'abc')"},
		{"equals folds case", "s:\n  Image: ABC\ncondition: s",
			"has(f_folded['Image'], 'abc')"},
		{"equals backslash", "s:\n  Image: 'C:\\x.exe'\ncondition: s",
			"has(f_folded['Image'], " + uh(`c:\x.exe`) + ")"},
		{"empty string", "s:\n  Image: ''\ncondition: s",
			"has(f_folded['Image'], '')"},
		{"int value", "s:\n  EventID: 4688\ncondition: s",
			"has(f_folded['EventID'], '4688')"},
		{"bool value", "s:\n  Flag: true\ncondition: s",
			"has(f_folded['Flag'], 'true')"},
		{"value list is OR", "s:\n  Image: [a, b]\ncondition: s",
			"hasAny(f_folded['Image'], ['a', 'b'])"},
		{"escaped star is literal", "s:\n  Image: 'a\\*b'\ncondition: s",
			"has(f_folded['Image'], " + uh("a*b") + ")"},

		// Wildcards: the common shapes are byte functions, the rest LIKE.
		{"contains", "s:\n  Image|contains: abc\ncondition: s",
			exists(pos("'abc'"), "f_folded['Image']")},
		{"startswith", "s:\n  Image|startswith: 'C:\\Win'\ncondition: s",
			exists("startsWith(x, "+uh(`c:\win`)+")", "f_folded['Image']")},
		{"endswith", "s:\n  Image|endswith: '\\cmd.exe'\ncondition: s",
			exists("endsWith(x, "+uh(`\cmd.exe`)+")", "f_folded['Image']")},
		{"endswith trailing backslash", "s:\n  Image|endswith: 'dir\\'\ncondition: s",
			exists("endsWith(x, "+uh(`dir\`)+")", "f_folded['Image']")},
		{"wildcard star and question", "s:\n  Image: 'a*b?c'\ncondition: s",
			exists("x LIKE 'a%b_c'", "f_folded['Image']")},
		{"like metacharacters escaped", "s:\n  Image: '50%*off_?'\ncondition: s",
			exists("x LIKE "+uh(`50\%%off\__`), "f_folded['Image']")},
		{"like backslash escaped", "s:\n  Image: 'a\\b*c?'\ncondition: s",
			exists("x LIKE "+uh(`a\\b%c_`), "f_folded['Image']")},
		{"bare star", "s:\n  Image: '*'\ncondition: s",
			exists("1", "f_folded['Image']")},
		{"contains with inner wildcard", "s:\n  Image|contains: 'a*b'\ncondition: s",
			exists("x LIKE '%a%b%'", "f_folded['Image']")},
		{"exact and wildcard values mixed", "s:\n  Image: [a, 'b*']\ncondition: s",
			"(has(f_folded['Image'], 'a')) OR (" + exists("startsWith(x, 'b')", "f_folded['Image']") + ")"},
		{"all", "s:\n  CommandLine|contains|all: [a, b]\ncondition: s",
			"(" + exists(pos("'a'"), "f_folded['CommandLine']") + ") AND (" + exists(pos("'b'"), "f_folded['CommandLine']") + ")"},

		// Regex runs on the unfolded text column.
		{"re", "s:\n  CommandLine|re: 'a.c'\ncondition: s",
			exists("match(x, "+uh(mustRE2(t, "a.c"))+")", "f_text['CommandLine']")},
		{"re|i", "s:\n  CommandLine|re|i: 'a.c'\ncondition: s",
			exists("match(x, "+uh(mustRE2(t, "(?i)a.c"))+")", "f_text['CommandLine']")},

		// cidr is a range over fixed-width hex keys.
		{"cidr v4", "s:\n  Ip|cidr: '10.1.2.3/16'\ncondition: s",
			exists("x >= '40a010000' AND x <= '40a01ffff'", "f_ips['Ip']")},
		{"cidr v6", "s:\n  Ip|cidr: '2001:db8::/32'\ncondition: s",
			exists("x >= '620010db8000000000000000000000000' AND x <= '620010db8ffffffffffffffffffffffff'", "f_ips['Ip']")},

		// Numeric comparisons run on the Go-parsed ints column.
		{"lt", "s:\n  Port|lt: 1024\ncondition: s", exists("x < toInt64('1024')", "f_ints['Port']")},
		{"lte", "s:\n  Port|lte: 1024\ncondition: s", exists("x <= toInt64('1024')", "f_ints['Port']")},
		{"gt", "s:\n  Port|gt: -5\ncondition: s", exists("x > toInt64('-5')", "f_ints['Port']")},
		{"gte", "s:\n  Port|gte: ' 7 '\ncondition: s", exists("x >= toInt64('7')", "f_ints['Port']")},

		// Encodings are expanded at compile time, then folded like any value.
		{"base64", "s:\n  C|base64: abc\ncondition: s",
			"has(f_folded['C'], 'ywjj')"},
		{"base64offset", "s:\n  C|base64offset|contains: abc\ncondition: s",
			exists("("+pos("'ywjj'")+") OR ("+pos("'fiy'")+") OR ("+pos("'hym'")+")", "f_folded['C']")},
		{"utf16le", "s:\n  C|utf16le|base64|contains: ab\ncondition: s",
			exists(pos("'yqbiaa=='"), "f_folded['C']")},
		{"wide", "s:\n  C|wide|contains: a\ncondition: s",
			exists(pos(uh("a\x00")), "f_folded['C']")},
		{"utf16be", "s:\n  C|utf16be|contains: a\ncondition: s",
			exists(pos(uh("\x00a")), "f_folded['C']")},
		{"utf16", "s:\n  C|utf16|contains: a\ncondition: s",
			exists(pos(uh("\ufffd\ufffda\x00")), "f_folded['C']")},
		{"windash", "s:\n  C|windash|contains: ' -a'\ncondition: s",
			exists("("+pos("' -a'")+") OR ("+pos("' /a'")+") OR ("+pos(uh(" \u2013a"))+") OR ("+pos(uh(" \u2014a"))+") OR ("+pos(uh(" \u2015a"))+")", "f_folded['C']")},

		// Null and absence.
		{"null", "s:\n  Image: null\ncondition: s", "NOT has(f_present, 'Image')"},
		{"not null", "s:\n  Image: null\ncondition: not s", "NOT (NOT has(f_present, 'Image'))"},

		{"fieldref", "s:\n  A|fieldref: B\ncondition: s", "hasAny(f_eqfold['A'], f_eqfold['B'])"},

		// Keywords search every text value of every field.
		{"keyword", "k:\n  - evil\ncondition: k",
			exists(pos("'evil'"), "arrayFlatten(mapValues(f_folded))")},
		{"keywords are OR", "k:\n  - a\n  - B\ncondition: k",
			"(" + exists(pos("'a'"), "arrayFlatten(mapValues(f_folded))") + ") OR (" + exists(pos("'b'"), "arrayFlatten(mapValues(f_folded))") + ")"},

		// Boolean structure.
		{"and of keys", "s:\n  A: a\n  B: b\ncondition: s",
			"(has(f_folded['A'], 'a')) AND (has(f_folded['B'], 'b'))"},
		{"list of maps is OR", "s:\n  - A: a\n  - B: b\ncondition: s",
			"(has(f_folded['A'], 'a')) OR (has(f_folded['B'], 'b'))"},
		{"and not", "a:\n  A: a\nb:\n  B: b\ncondition: a and not b",
			"(has(f_folded['A'], 'a')) AND (NOT (has(f_folded['B'], 'b')))"},
		{"or", "a:\n  A: a\nb:\n  B: b\ncondition: a or b",
			"(has(f_folded['A'], 'a')) OR (has(f_folded['B'], 'b'))"},
		{"1 of", "sel_a:\n  A: a\nsel_b:\n  B: b\ncondition: 1 of sel_*",
			"(has(f_folded['A'], 'a')) OR (has(f_folded['B'], 'b'))"},
		{"all of them", "sel_a:\n  A: a\nsel_b:\n  B: b\ncondition: all of them",
			"(has(f_folded['A'], 'a')) AND (has(f_folded['B'], 'b'))"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := loadDetection(t, tax, c.det)
			got, err := CompileRule(r)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got\n  %s\nwant\n  %s", got, c.want)
			}
		})
	}
}

func TestCompileRuleIncludesTheLogSource(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../../engine/v1/testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	r, lerr := sigma.LoadRule("../../engine/v1/testdata/rules/network.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	got, err := CompileRule(r)
	if err != nil {
		t.Fatal(err)
	}
	want := "((has(f_folded['channel'], 'microsoft-windows-sysmon/operational')) AND (has(f_folded['event_id'], '3'))) AND (has(f_folded['DestinationPort'], '4444'))"
	if got != want {
		t.Fatalf("got\n  %s\nwant\n  %s", got, want)
	}
}

func TestHuntQuery(t *testing.T) {
	r := loadDetection(t, testTaxonomy(t), "s:\n  A: a\ncondition: s")
	q, err := HuntQuery(DefaultTable, r, Window{From: msTime(1000), To: msTime(2000)})
	if err != nil {
		t.Fatal(err)
	}
	want := "SELECT DISTINCT partition, seq FROM events WHERE toUnixTimestamp64Milli(event_time) >= 1000" +
		" AND toUnixTimestamp64Milli(event_time) < 2000 AND (has(f_folded['A'], 'a')) ORDER BY partition, seq"
	if q != want {
		t.Fatalf("got\n  %s\nwant\n  %s", q, want)
	}
	for _, bad := range []string{"", "events; DROP TABLE x", "a.b.c", "`events`", "1events", "events--"} {
		if _, err := HuntQuery(bad, r, Window{}); err == nil {
			t.Errorf("table %q accepted", bad)
		}
		if _, err := CreateTableSQL(bad); err == nil {
			t.Errorf("CreateTableSQL(%q) accepted", bad)
		}
	}
	if _, err := HuntQuery("db.events_1", r, Window{}); err != nil {
		t.Fatal(err)
	}
}

func TestRE2PatternGolden(t *testing.T) {
	cases := map[string]string{
		`a.c`:                `(?:(?:\x{61})[^\x{a}](?:\x{63}))`,
		`(?s)a.`:             `(?:(?:\x{61})[\x{0}-\x{10ffff}])`,
		`(?i)k`:              `(?:[\x{4b}\x{6b}\x{212a}])`,
		`^a$`:                `(?:\A(?:\x{61})\z)`,
		`(?m)^a$`:            `(?:(?m:^)(?:\x{61})(?m:$))`,
		`(?P<n>a)+`:          `(?:(?:(?:\x{61})))+`,
		`[a-c]{2,}`:          `(?:[\x{61}-\x{63}]){2,}`,
		`a{3}?`:              `(?:(?:\x{61})){3}?`,
		`\bx\B`:              `(?:\b(?:\x{78})\B)`,
		`a|b*`:               `(?:(?:\x{61})|(?:(?:\x{62}))*)`,
		`[^\x00-\x{10FFFF}]`: `[^\x{0}-\x{10ffff}]`,
	}
	for in, want := range cases {
		if got := mustRE2(t, in); got != want {
			t.Errorf("re2Pattern(%q) = %q, want %q", in, got, want)
		}
	}
}

// Each construct the compiler refuses, with its code.
func TestCompileRejections(t *testing.T) {
	pred := &ast.Pred{Field: "A", Desc: "A a", Vals: []event.Value{event.String("a")}}
	cases := []struct {
		name string
		n    ast.Node
		code string
	}{
		{"ident", &ast.Ident{Name: "sel"}, CodeUnbound},
		{"quant", &ast.Quant{Count: ast.QuantAll, Them: true}, CodeUnbound},
		{"nested ident", &ast.And{Children: []ast.Node{pred, &ast.Not{Child: &ast.Ident{Name: "x"}}}}, CodeUnbound},
		{"nil", nil, CodeUnknownNode},
		{"nil child", &ast.Or{Children: []ast.Node{pred, nil}}, CodeUnknownNode},
		{"pred without source", &ast.Pred{Field: "A", Desc: "opaque"}, CodeNoSource},
		{"keyword without value", &ast.Pred{Desc: "kw", Keyword: true}, CodeNoSource},
		{"pred the planner rejects", &ast.Pred{Field: "A", Mods: []string{"bogus"}, Vals: []event.Value{event.String("a")}}, CodePlan},
		{"pred with list value", &ast.Pred{Field: "A", Vals: []event.Value{event.List(event.String("a"))}}, CodePlan},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compile(c.n)
			var rj *Rejection
			if !errors.As(err, &rj) || rj.Code != c.code {
				t.Fatalf("err = %v, want code %s", err, c.code)
			}
		})
	}
}

func TestRejectsAQueryOverTheSizeLimit(t *testing.T) {
	// Two values at the five-dash windash limit: 6250 contains variants.
	det := "s:\n  C|windash|contains:\n    - ' -a -b -c -d -e'\n    - ' -f -g -h -i -j'\ncondition: s"
	r := loadDetection(t, testTaxonomy(t), det)
	_, err := CompileRule(r)
	var rj *Rejection
	if !errors.As(err, &rj) || rj.Code != CodeTooLarge || rj.RuleID != r.ID {
		t.Fatalf("err = %v, want %s carrying the rule id", err, CodeTooLarge)
	}
}

// A WHERE clause just under the limit passes CompileRule, but the SELECT
// around it pushes the statement over. HuntQuery must reject it, since the
// server checks the whole query, not the WHERE clause.
func TestHuntQueryRejectsAStatementOverTheSizeLimit(t *testing.T) {
	tax := testTaxonomy(t)
	sized := func(n int) *sigma.Rule {
		return loadDetection(t, tax, "s:\n  A: '"+strings.Repeat("a", n)+"'\ncondition: s")
	}
	where, err := CompileRule(sized(1))
	if err != nil {
		t.Fatal(err)
	}
	n := MaxQueryBytes - (len(where) - 1) - 4
	r := sized(n)
	if where, err = CompileRule(r); err != nil || len(where) > MaxQueryBytes {
		t.Fatalf("setup: WHERE is %d bytes, err %v; want just under %d", len(where), err, MaxQueryBytes)
	}
	_, err = HuntQuery(DefaultTable, r, Window{From: msTime(1000), To: msTime(2000)})
	var rj *Rejection
	if !errors.As(err, &rj) || rj.Code != CodeTooLarge || rj.RuleID != r.ID {
		t.Fatalf("err = %v, want %s carrying the rule id", err, CodeTooLarge)
	}
}

func TestRE2PatternRejectsWhatGoCannotParse(t *testing.T) {
	if _, err := re2Pattern("("); err == nil {
		t.Fatal("an unparseable pattern must fail")
	}
}

// Values and field names that would break a naive query: quotes,
// backslashes, NUL, comment and statement separators, non-UTF-8. None of
// their bytes may reach the query text outside hex.
func TestCompileIsInjectionProof(t *testing.T) {
	tax := testTaxonomy(t)
	nasty := []string{
		`'`, `''`, `\`, `\'`, `'; DROP TABLE events; --`, "a\x00b", "\x00",
		`\x27`, `%' OR 1=1 OR '`, "line\nbreak", "\xff\xfe", "tab\there", "`back`", `"dq"`,
		"/* c */", "}{", "-- c",
	}
	for _, v := range nasty {
		yv := yamlQuote(v)
		for _, mods := range []string{"", "|contains", "|startswith", "|endswith", "|re", "|windash", "|base64offset|contains"} {
			if mods == "|re" && v == `\` {
				continue // not a regex
			}
			det := "s:\n  " + yamlQuote("F'"+v+mods) + ": " + yv + "\nk:\n  - " + yv + "\nr:\n  A|fieldref: " + yv + "\ncondition: s or k or r"
			r := loadDetection(t, tax, det)
			sql, err := CompileRule(r)
			if err != nil {
				t.Fatalf("%q %s: %v", v, mods, err)
			}
			assertSafeSQL(t, sql)
		}
	}
}

// yamlQuote writes s as a YAML double-quoted scalar with every byte escaped
// that YAML would otherwise interpret.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteString(`\` + string(r))
		case r < 0x20 || r == 0xfffd:
			b.WriteString(`\x` + hex.EncodeToString([]byte{byte(r)}))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// assertSafeSQL checks the query text is drawn from a fixed alphabet: every
// quoted literal is plain, and nothing outside a literal is anything but
// identifiers, numbers, operators, and the punctuation the compiler writes.
func assertSafeSQL(t *testing.T, sql string) {
	t.Helper()
	in := false
	start := 0
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if c == '\'' {
			if in && !plain(sql[start:i]) {
				t.Fatalf("literal %q is not plain in %s", sql[start:i], sql)
			}
			in = !in
			start = i + 1
			continue
		}
		if in {
			continue
		}
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ()[],_<>=->", rune(c)) {
			t.Fatalf("byte %q outside a literal in %s", c, sql)
		}
	}
	if in {
		t.Fatalf("unterminated literal in %s", sql)
	}
}
