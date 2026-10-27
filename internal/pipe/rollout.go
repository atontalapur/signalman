package pipe

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
)

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

// ParseRollout reads a rollout file: one integer from 0 to 100, with blank
// lines and lines starting with # ignored. signalmand -rollout reads it, and
// the cutover game day writes it.
func ParseRollout(b []byte) (int, error) {
	var vals []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			vals = append(vals, line)
		}
	}
	if len(vals) != 1 {
		return 0, fmt.Errorf("rollout file holds %d values, want one percentage", len(vals))
	}
	n, err := strconv.Atoi(vals[0])
	if err != nil {
		return 0, fmt.Errorf("rollout %q is not an integer percentage", vals[0])
	}
	if n < 0 || n > 100 {
		return 0, fmt.Errorf("rollout %d%% is outside 0 to 100", n)
	}
	return n, nil
}
