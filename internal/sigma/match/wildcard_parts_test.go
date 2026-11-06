package match

import (
	"reflect"
	"testing"
)

func TestWildcardParts(t *testing.T) {
	lit := func(s string) WildcardPart { return WildcardPart{Kind: PartLiteral, Lit: s} }
	anyP := WildcardPart{Kind: PartAny}
	one := WildcardPart{Kind: PartOne}
	cases := []struct {
		pat  string
		want []WildcardPart
	}{
		{`C:\Windows`, []WildcardPart{lit(`c:\windows`)}},
		{`*\CMD.exe`, []WildcardPart{anyP, lit(`\cmd.exe`)}},
		{`a**b`, []WildcardPart{lit("a"), anyP, lit("b")}},
		{`a?*?b`, []WildcardPart{lit("a"), one, anyP, one, lit("b")}},
		{`x\*y\?z\\`, []WildcardPart{lit(`x*y?z\`)}},
		{`\`, []WildcardPart{lit(`\`)}},
		{``, nil},
		{`*`, []WildcardPart{anyP}},
	}
	for _, c := range cases {
		if got := CompileWildcard(c.pat).Parts(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parts(%q) = %+v, want %+v", c.pat, got, c.want)
		}
	}
}
