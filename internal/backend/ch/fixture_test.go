package ch

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

// The integration test's fixture and rules, checked here without a server:
// every rule loads and compiles, and the replay oracle finds something for
// most of them, so a green integration run compares real answers rather
// than empty sets.
func TestHuntFixture(t *testing.T) {
	tax := testTaxonomy(t)
	evs := fixture()
	w := Window{From: msTime(1000), To: msTime(1000 + int64(len(evs)) - 2)}
	empty := 0
	for _, det := range huntRules {
		r := loadDetection(t, tax, det)
		if _, err := HuntQuery(DefaultTable, r, w); err != nil {
			t.Fatalf("%s: %v", det, err)
		}
		hits := replay(r, evs, w)
		if len(hits) == 0 {
			empty++
			t.Logf("no hit: %q", det)
		}
		for _, h := range hits {
			if h.Seq > uint64(len(evs)-2) {
				t.Fatalf("%s: hit %v is outside the window", det, h)
			}
		}
	}
	if empty*3 > len(huntRules) {
		t.Fatalf("%d of %d hunt rules match nothing in the fixture", empty, len(huntRules))
	}
	t.Logf("%d hunt rules, %d with no hit", len(huntRules), empty)
}

// fixture is one event per awkward value, at event times 1000, 1001, ...
// ms. The window leaves the last two out.
func fixture() []*event.Event {
	s, i, b, n, l := event.String, event.Int, event.Bool, event.Null, event.List
	fields := []map[string]event.Value{
		{"Image": s(`C:\Windows\System32\CMD.EXE`), "CommandLine": s(`cmd.exe /c "whoami"`)},
		{"Image": s(`C:\x\rundll32.exe`), "CommandLine": s("rundll32 comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full")},
		{"CommandLine": s("line one\nline two"), "Image": s("")},
		{"CommandLine": s("İstanbul \u212aelvin ſtraße ǅ"), "User": s("ADMIN")},
		{"CommandLine": s("bad \xff\xfe utf8"), "User": s("admin")},
		{"CommandLine": s("nul\x00byte 'quote' \\back\\"), "Image": n()},
		{"Tags": l(s("Alpha"), n(), l(s("nested")), i(7), b(true)), "Port": s(" 8080 ")},
		{"Port": i(443), "DestinationIp": s("10.1.2.3"), "SourceIp": s("10.1.2.3")},
		{"Port": s("+22"), "DestinationIp": s("::ffff:10.1.2.3"), "SourceIp": s("10.1.2.4")},
		{"Port": s("0x16"), "DestinationIp": s("2001:db8::1"), "SourceIp": s("2001:DB8::1")},
		{"Port": s("9223372036854775808"), "DestinationIp": s("fe80::1%eth0")},
		{"Port": b(true), "DestinationIp": s("010.1.2.3"), "Flag": b(false)},
		{"A": s("Kelvin \u212a"), "B": s("kelvin k")},
		{"A": s("x"), "B": l(s("y"), s("X"))},
		{"CommandLine": s("powershell -enc SQBFAFgA"), "Image": s(`C:\pwsh.exe`)},
		{"CommandLine": s("certutil \u2013urlcache /f http://e"), "Image": s(`C:\certutil.exe`)},
		{"CommandLine": s("50% off_sale"), "Image": s("a*b?c")},
		{"Image": s("outside window"), "CommandLine": s("whoami")},
		{"Image": s("outside window 2"), "CommandLine": s("whoami")},
	}
	evs := make([]*event.Event, len(fields))
	for k, f := range fields {
		evs[k] = &event.Event{
			Seq:       uint64(k + 1),
			Partition: int32(k % 2),
			Source:    "fixture",
			EventTime: msTime(1000 + int64(k)),
			IngestAt:  msTime(5000),
			Fields:    f,
			Raw:       []byte("{}"),
		}
	}
	return evs
}

// huntRules is one rule per node type and modifier, aimed at the fixture.
var huntRules = []string{
	"s:\n  Image|endswith: '\\cmd.exe'\ncondition: s",
	"s:\n  Image: 'c:\\windows\\system32\\cmd.exe'\ncondition: s",
	"s:\n  Image: ''\ncondition: s",
	"s:\n  Image: null\ncondition: s",
	"s:\n  Image: null\ncondition: not s",
	"s:\n  CommandLine|contains|all: [comsvcs, minidump]\ncondition: s",
	"s:\n  CommandLine|startswith: 'LINE'\ncondition: s",
	"s:\n  CommandLine: 'line*two'\ncondition: s",
	"s:\n  CommandLine: 'line?one*'\ncondition: s",
	"s:\n  CommandLine|contains: 'istanbul'\ncondition: s",
	"s:\n  CommandLine|contains: 'İstanbul'\ncondition: s",
	"s:\n  CommandLine|contains: 'kelvin'\ncondition: s",
	"s:\n  CommandLine|contains: 'STRASSE'\ncondition: s",
	"s:\n  CommandLine|contains: 'ǆ'\ncondition: s",
	"s:\n  CommandLine|contains: \"\\uFFFD\\uFFFD\"\ncondition: s",
	"s:\n  CommandLine|contains: \"nul\\0byte 'quote' \\\\back\\\\\"\ncondition: s",
	"s:\n  CommandLine|contains: '50%'\ncondition: s",
	"s:\n  CommandLine: '50\\% off_*'\ncondition: s",
	"s:\n  Image: 'a\\*b\\?c'\ncondition: s",
	"s:\n  Image: 'a*b?c'\ncondition: s",
	"s:\n  CommandLine|re: 'line.line'\ncondition: s",
	"s:\n  CommandLine|re: '(?s)one.line'\ncondition: s",
	"s:\n  CommandLine|re: 'two$'\ncondition: s",
	"s:\n  CommandLine|re: '(?m)one$'\ncondition: s",
	"s:\n  CommandLine|re|i: 'KELVIN'\ncondition: s",
	"s:\n  CommandLine|re|i: 'STRA(SS|ß)E'\ncondition: s",
	"s:\n  CommandLine|re: '\\p{Lu}stanbul'\ncondition: s",
	"s:\n  CommandLine|re: 'bad ..? utf8'\ncondition: s",
	"s:\n  CommandLine|re: '^[^a-z]'\ncondition: s",
	"s:\n  CommandLine|re: '(?P<w>who)ami'\ncondition: s",
	"s:\n  CommandLine|re: '\\x00'\ncondition: s",
	"s:\n  User|re: '^admin$'\ncondition: s",
	"s:\n  Tags: alpha\ncondition: s",
	"s:\n  Tags: 7\ncondition: s",
	"s:\n  Tags: 'true'\ncondition: s",
	"s:\n  Tags: nested\ncondition: s",
	"s:\n  Port|gte: 8080\ncondition: s",
	"s:\n  Port|lt: 23\ncondition: s",
	"s:\n  Port|gt: 0\ncondition: s",
	"s:\n  Port|lte: -1\ncondition: s",
	"s:\n  Port: 443\ncondition: s",
	"s:\n  DestinationIp|cidr: '10.0.0.0/8'\ncondition: s",
	"s:\n  DestinationIp|cidr: '::ffff:0:0/96'\ncondition: s",
	"s:\n  DestinationIp|cidr: '2001:db8::/32'\ncondition: s",
	"s:\n  DestinationIp|cidr: 'fe80::/10'\ncondition: s",
	"s:\n  DestinationIp|fieldref: SourceIp\ncondition: s",
	"s:\n  A|fieldref: B\ncondition: s",
	"s:\n  Flag: false\ncondition: s",
	"s:\n  CommandLine|utf16le|base64offset|contains: 'IEX'\ncondition: s",
	"s:\n  CommandLine|base64|contains: 'x'\ncondition: s",
	"s:\n  CommandLine|wide|contains: 'a'\ncondition: s",
	"s:\n  CommandLine|windash|contains: ' -urlcache'\ncondition: s",
	"k:\n  - whoami\ncondition: k",
	"k:\n  - nested\n  - 'alpha'\ncondition: k",
	"k:\n  - 443\ncondition: k",
	"a:\n  Image|endswith: '.exe'\nb:\n  CommandLine|contains: whoami\ncondition: a and not b",
	"sel_a:\n  Port: 443\nsel_b:\n  Flag: false\ncondition: 1 of sel_*",
	"sel_a:\n  Port|gt: 0\nsel_b:\n  DestinationIp|cidr: '10.0.0.0/8'\ncondition: all of sel_*",
	"s:\n  - Image: ''\n  - User: admin\ncondition: s",
}
