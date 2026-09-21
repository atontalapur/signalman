// Command corpusaccept loads a rule directory and reports how many rules
// were accepted and why the rest were rejected. Its output is the input to
// docs/corpus-acceptance.md, which is the Plan A gate: the supported subset
// of Sigma is documented rather than discovered.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma"
)

func main() {
	rules := flag.String("rules", "corpora/sigmahq/rules", "rule directory")
	taxonomy := flag.String("taxonomy", "config/taxonomy", "taxonomy directory")
	samples := flag.Int("samples", 3, "example rejections to print per code")
	flag.Parse()

	tax, err := sigma.LoadTaxonomy(*taxonomy)
	if err != nil {
		fmt.Fprintln(os.Stderr, "taxonomy:", err)
		os.Exit(1)
	}
	rs, errs, err := sigma.LoadRuleSet(*rules, tax)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		os.Exit(1)
	}

	byCode := map[string][]sigma.LoadError{}
	for _, e := range errs {
		byCode[e.Code] = append(byCode[e.Code], e)
	}
	codes := make([]string, 0, len(byCode))
	for c := range byCode {
		codes = append(codes, c)
	}
	sort.Strings(codes)

	total := len(rs.Rules) + len(errs)
	if total == 0 {
		fmt.Fprintf(os.Stderr, "no rule files under %s\n", *rules)
		os.Exit(1)
	}
	fmt.Printf("corpus   %s\n", *rules)
	if sha := corpusCommit(*rules); sha != "" {
		fmt.Printf("commit   %s\n", sha)
	}
	fmt.Printf("ruleset  %s\ntaxonomy %s\n", rs.Version, rs.TaxonomyV)
	fmt.Printf("accepted %d of %d (%.1f%%)\n\n", len(rs.Rules), total,
		100*float64(len(rs.Rules))/float64(total))
	for _, c := range codes {
		list := byCode[c]
		fmt.Printf("%-14s %5d  %5.1f%%\n", c, len(list), 100*float64(len(list))/float64(total))
		for i, e := range list {
			if i >= *samples {
				break
			}
			fmt.Printf("               %s\n", e.Error())
		}
	}
}

// corpusCommit records which revision of the corpus produced the numbers.
// Without it the report is a snapshot of nothing in particular.
func corpusCommit(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
