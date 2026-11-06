package differ

import (
	"reflect"
	"testing"

	"github.com/atontalapur/signalman/internal/pipe"
)

func rec(engine, rulesetV, taxonomyV string, verdicts ...pipe.RuleVerdict) *pipe.EventVerdicts {
	ev := &pipe.EventVerdicts{Partition: 2, Seq: 40, Engine: engine, RuleSetV: rulesetV, TaxonomyV: taxonomyV, Verdicts: verdicts}
	if engine == "v1" {
		ev.Shadow = "v2"
	}
	return ev
}

func rv(id string, matched bool) pipe.RuleVerdict {
	return pipe.RuleVerdict{RuleID: id, Matched: matched}
}

func side(matched bool, rulesetV, taxonomyV string) *Side {
	return &Side{Matched: matched, RuleSetV: rulesetV, TaxonomyV: taxonomyV}
}

func TestCompareClassifiesEveryDisagreement(t *testing.T) {
	cases := []struct {
		name   string
		v1, v2 *pipe.EventVerdicts
		want   []Divergence
	}{
		{
			name: "agreement is not a divergence",
			v1:   rec("v1", "R", "T", rv("a", true), rv("b", false)),
			v2:   rec("v2", "R", "T", rv("a", true), rv("b", false)),
		},
		{
			name: "v1 matched and v2 did not: a missed detection",
			v1:   rec("v1", "R", "T", rv("a", true), rv("b", false)),
			v2:   rec("v2", "R", "T", rv("a", false), rv("b", false)),
			want: []Divergence{{Partition: 2, Seq: 40, RuleID: "a", Class: ClassFalseNegative, V1: side(true, "R", "T"), V2: side(false, "R", "T")}},
		},
		{
			name: "v2 matched and v1 did not: noise",
			v1:   rec("v1", "R", "T", rv("a", false), rv("b", false)),
			v2:   rec("v2", "R", "T", rv("a", false), rv("b", true)),
			want: []Divergence{{Partition: 2, Seq: 40, RuleID: "b", Class: ClassFalsePositive, V1: side(false, "R", "T"), V2: side(true, "R", "T")}},
		},
		{
			name: "a disagreement under different RuleSetV is version skew, excluded",
			v1:   rec("v1", "R1", "T", rv("a", true)),
			v2:   rec("v2", "R2", "T", rv("a", false)),
			want: []Divergence{{Partition: 2, Seq: 40, RuleID: "a", Class: ClassVersionSkew, Excluded: true, V1: side(true, "R1", "T"), V2: side(false, "R2", "T")}},
		},
		{
			name: "a TaxonomyV difference under one RuleSetV is not excluded",
			v1:   rec("v1", "R", "T1", rv("a", true)),
			v2:   rec("v2", "R", "T2", rv("a", false)),
			want: []Divergence{{Partition: 2, Seq: 40, RuleID: "a", Class: ClassFalseNegative, V1: side(true, "R", "T1"), V2: side(false, "R", "T2")}},
		},
		{
			name: "agreement under different RuleSetV is not a divergence",
			v1:   rec("v1", "R1", "T", rv("a", true)),
			v2:   rec("v2", "R2", "T", rv("a", true)),
		},
		{
			name: "a rule only one engine evaluated, same RuleSetV: missing verdict",
			v1:   rec("v1", "R", "T", rv("a", false), rv("b", true), rv("c", false)),
			v2:   rec("v2", "R", "T", rv("a", false), rv("c", false), rv("d", false)),
			want: []Divergence{
				{Partition: 2, Seq: 40, RuleID: "b", Class: ClassMissing, Missing: "v2", V1: side(true, "R", "T")},
				{Partition: 2, Seq: 40, RuleID: "d", Class: ClassMissing, Missing: "v1", V2: side(false, "R", "T")},
			},
		},
		{
			name: "a rule only one engine evaluated, different RuleSetV: version skew",
			v1:   rec("v1", "R1", "T", rv("a", false), rv("b", true)),
			v2:   rec("v2", "R2", "T", rv("a", false)),
			want: []Divergence{{Partition: 2, Seq: 40, RuleID: "b", Class: ClassVersionSkew, Excluded: true, Missing: "v2", V1: side(true, "R1", "T")}},
		},
		{
			name: "no v2 record: every rule is missing from v2",
			v1:   rec("v1", "R", "T", rv("b", true), rv("a", false)),
			want: []Divergence{
				{Partition: 2, Seq: 40, RuleID: "a", Class: ClassMissing, Missing: "v2", V1: side(false, "R", "T")},
				{Partition: 2, Seq: 40, RuleID: "b", Class: ClassMissing, Missing: "v2", V1: side(true, "R", "T")},
			},
		},
		{
			name: "no v1 record: every rule is missing from v1",
			v2:   rec("v2", "R", "T", rv("a", false)),
			want: []Divergence{{Partition: 2, Seq: 40, RuleID: "a", Class: ClassMissing, Missing: "v1", V2: side(false, "R", "T")}},
		},
		{
			name: "rule order inside a record does not matter",
			v1:   rec("v1", "R", "T", rv("b", false), rv("a", true)),
			v2:   rec("v2", "R", "T", rv("a", false), rv("b", false)),
			want: []Divergence{{Partition: 2, Seq: 40, RuleID: "a", Class: ClassFalseNegative, V1: side(true, "R", "T"), V2: side(false, "R", "T")}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Compare(c.v1, c.v2)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestOnlyTheZeroBudgetClassesCount(t *testing.T) {
	for c, want := range map[Class]bool{
		ClassFalseNegative: true,
		ClassFalsePositive: true,
		ClassMissing:       true,
		ClassVersionSkew:   false,
		ClassOrdering:      false,
	} {
		if c.Counted() != want {
			t.Fatalf("%s counted = %v, want %v", c, c.Counted(), want)
		}
	}
	if len(Classes) != 5 {
		t.Fatalf("the spec names five classes, Classes has %d", len(Classes))
	}
}
