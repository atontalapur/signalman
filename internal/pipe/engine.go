package pipe

import (
	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/engine/v2"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// Engine is the evaluation slot. v1 fills it today; v2 drops in by
// implementing the same three methods.
//
// The contract is the data contract: EvaluateInto appends exactly one
// verdict per rule in RuleSet() to dst, stamped with the event's Seq and
// Partition, the engine's Name, and the rule set's versions, and returns
// dst. It must be a pure function of the event and the rule set, and safe
// to call from many goroutines at once. The pipeline checks the count on
// every event and stops the process if it is wrong, because a missing
// verdict is the one failure the audit exists to catch, and a crash is lag
// while a short verdict list is loss.
type Engine interface {
	// Name is the engine identity on every verdict and the suffix of its
	// verdict topic: "v1" writes verdicts.v1.
	Name() string
	RuleSet() *sigma.RuleSet
	EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict
}

// V1 wraps the reference evaluator as an Engine.
func V1(rs *sigma.RuleSet) Engine { return v1Engine{v1.New(rs)} }

type v1Engine struct{ *v1.Evaluator }

func (v1Engine) Name() string { return v1.Name }

// V2 wraps the compiled evaluator as an Engine. It compiles rs, which for
// 1,500 rules is well under the two seconds a reload may take.
func V2(rs *sigma.RuleSet) Engine { return v2Engine{v2.New(rs)} }

type v2Engine struct{ *v2.Evaluator }

func (v2Engine) Name() string { return v2.Name }

// VerdictTopic is where an engine's verdicts go.
func VerdictTopic(e Engine) string { return "verdicts." + e.Name() }
