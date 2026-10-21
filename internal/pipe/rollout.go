package pipe

import "hash/fnv"

// RolloutBucket is the rule's place in the rollout order: FNV-1a 32 of the
// rule id, mod 100. It depends on nothing but the id, so routing is the
// same after every restart and on every node.
func RolloutBucket(ruleID string) int {
	h := fnv.New32a()
	h.Write([]byte(ruleID))
	return int(h.Sum32() % 100)
}

// ServedByShadow reports whether the shadow engine serves ruleID's alerts
// at percent: fnv(rule_id) mod 100 < percent (spec phase 09). A rule's
// bucket never changes, so raising percent only ever adds rules, and a rule
// served by the shadow stays served by it as the rollout advances.
func ServedByShadow(ruleID string, percent int) bool {
	return RolloutBucket(ruleID) < percent
}
