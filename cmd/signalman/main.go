// Command signalman is the rule author's tool: it runs a rule's fixtures,
// explains a verdict, and reports load errors, noise, and evaluation cost
// before a rule merges.
//
// Exit codes: 0 when every check passed, 1 when a check failed, 2 when the
// command could not run (bad arguments, unreadable input).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

type command struct {
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

var commands map[string]command

func init() {
	commands = map[string]command{
		"test": {"run each rule's fixtures from its sibling .test.yml", cmdTest},
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(stderr)
		return exitUsage
	}
	c, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "signalman: unknown command %q\n", args[0])
		usage(stderr)
		return exitUsage
	}
	return c.run(args[1:], stdout, stderr)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: signalman <command> [flags] [args]")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-8s %s\n", n, commands[n].summary)
	}
}

// newFlags returns a flag set that reports errors instead of exiting, with
// the taxonomy flag every command shares.
func newFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("signalman "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	tax := fs.String("taxonomy", "config/taxonomy", "taxonomy directory")
	return fs, tax
}

// parseInterspersed lets flags follow positional arguments, as in
// "signalman noise rules/x.yml --corpus dir". The standard flag package
// stops at the first positional argument.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func loadTaxonomy(dir string, stderr io.Writer) (*sigma.Taxonomy, bool) {
	tax, err := sigma.LoadTaxonomy(dir)
	if err != nil {
		fmt.Fprintf(stderr, "signalman: taxonomy: %v\n", err)
		return nil, false
	}
	return tax, true
}

// ruleFiles expands the arguments into rule files, or reports why it could
// not. No rule files at all is a usage error: a check over nothing passes
// vacuously, and a green result over nothing is a lie.
func ruleFiles(args []string, stderr io.Writer) ([]string, bool) {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "signalman: name at least one rule file or directory")
		return nil, false
	}
	paths, err := sigma.RuleFiles(args...)
	if err != nil {
		fmt.Fprintf(stderr, "signalman: %v\n", err)
		return nil, false
	}
	if len(paths) == 0 {
		fmt.Fprintf(stderr, "signalman: no rule files under %s\n", strings.Join(args, " "))
		return nil, false
	}
	return paths, true
}
