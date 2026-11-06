package main

import (
	"fmt"
	"io"
	"os"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/explain"
	"github.com/atontalapur/signalman/internal/sigma"
)

// cmdExplain prints one rule's condition tree evaluated against one JSON
// event. It is a report, not a check, so a non-matching event exits 0.
func cmdExplain(args []string, stdout, stderr io.Writer) int {
	fs, taxDir := newFlags("explain", stderr)
	evFlag := fs.String("event", "", "JSON event file (or pass it as the second argument)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	evPath := *evFlag
	switch {
	case len(pos) == 2 && evPath == "":
		evPath = pos[1]
	case len(pos) == 1 && evPath != "":
	default:
		fmt.Fprintln(stderr, "usage: signalman explain [--taxonomy dir] <rule.yml> <event.json>")
		return exitUsage
	}

	tax, ok := loadTaxonomy(*taxDir, stderr)
	if !ok {
		return exitUsage
	}
	src, err := os.ReadFile(evPath)
	if err != nil {
		fmt.Fprintf(stderr, "signalman: %v\n", err)
		return exitUsage
	}
	ev, err := event.DecodeJSON(src)
	if err != nil {
		fmt.Fprintf(stderr, "signalman: %s: %v\n", evPath, err)
		return exitUsage
	}
	r, lerr := sigma.LoadRule(pos[0], tax)
	if lerr != nil {
		fmt.Fprintln(stdout, lerr.Error())
		return exitFail
	}
	if err := explain.Explain(r, ev).Render(stdout); err != nil {
		fmt.Fprintf(stderr, "signalman: %v\n", err)
		return exitUsage
	}
	return exitOK
}
