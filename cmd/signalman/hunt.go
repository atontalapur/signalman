package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2" // registers the "clickhouse" database/sql driver

	"github.com/atontalapur/signalman/internal/backend/ch"
	"github.com/atontalapur/signalman/internal/sigma"
)

// hunter runs one rule over the stored events. sqlHunter is the real one;
// tests swap openHunter for a stub.
type hunter interface {
	Hunt(ctx context.Context, table string, r *sigma.Rule, w ch.Window) ([]ch.Hit, error)
	Close() error
}

type sqlHunter struct{ db *sql.DB }

func (h sqlHunter) Hunt(ctx context.Context, table string, r *sigma.Rule, w ch.Window) ([]ch.Hit, error) {
	return ch.RetroHunt(ctx, h.db, table, r, w)
}

func (h sqlHunter) Close() error { return h.db.Close() }

var openHunter = func(ctx context.Context, dsn string) (hunter, error) {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	return sqlHunter{db}, nil
}

// huntRecord is one rule's result in --json output.
type huntRecord struct {
	Path   string    `json:"path"`
	RuleID string    `json:"rule_id"`
	Title  string    `json:"title"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Hits   []huntHit `json:"hits"`
	// Error is set, and Hits empty, when the rule did not load or its
	// query failed.
	Error string `json:"error,omitempty"`
}

type huntHit struct {
	Partition int32  `json:"partition"`
	Seq       uint64 `json:"seq"`
}

// cmdHunt runs each rule as a ClickHouse query over the events table, for
// back-testing a rule against what already happened. The events table is
// filled by signalman-sink -lane events. The rows are the events the rule
// matches over [--from, --to) in event time, which is what a v1 replay of
// the same events would alert on.
func cmdHunt(args []string, stdout, stderr io.Writer) int {
	fs, taxDir := newFlags("hunt", stderr)
	dsn := fs.String("clickhouse", "", "clickhouse-go DSN (default $SIGNALMAN_CLICKHOUSE_DSN, then the compose server)")
	table := fs.String("table", ch.DefaultTable, "events table to hunt over")
	fromS := fs.String("from", "", "window start, RFC 3339, inclusive (required)")
	toS := fs.String("to", "", "window end, RFC 3339, exclusive (required)")
	asJSON := fs.Bool("json", false, "print one JSON object per rule")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up on the whole hunt after this long")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	w, err := huntWindow(*fromS, *toS)
	if err != nil {
		fmt.Fprintf(stderr, "signalman hunt: %v\n", err)
		return exitUsage
	}
	if err := ch.CheckTable(*table); err != nil {
		fmt.Fprintf(stderr, "signalman hunt: %v\n", err)
		return exitUsage
	}
	tax, ok := loadTaxonomy(*taxDir, stderr)
	if !ok {
		return exitUsage
	}
	paths, ok := ruleFiles(pos, stderr)
	if !ok {
		return exitUsage
	}
	if *dsn == "" {
		*dsn = os.Getenv("SIGNALMAN_CLICKHOUSE_DSN")
	}
	if *dsn == "" {
		*dsn = ch.ComposeDSN
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	enc := json.NewEncoder(stdout)
	// fail reports one rule that did not run: a FAIL line, or with --json a
	// record carrying the error, so stdout stays one object per line.
	fail := func(path, id string, err error) bool {
		if !*asJSON {
			fmt.Fprintf(stdout, "FAIL  %s  %s: %v\n", id, path, err)
			return true
		}
		if err := enc.Encode(huntRecord{Path: path, RuleID: id, From: w.From, To: w.To, Hits: []huntHit{}, Error: err.Error()}); err != nil {
			fmt.Fprintf(stderr, "signalman hunt: %v\n", err)
			return false
		}
		return true
	}

	// Load errors come first, before ClickHouse is dialed, so a broken rule
	// is reported even when the server is down.
	rs, loadErrs := sigma.LoadRuleFiles(paths, tax)
	failed := len(loadErrs)
	for _, e := range loadErrs {
		if !*asJSON {
			fmt.Fprintln(stdout, "FAIL  "+e.Error())
			continue
		}
		if !fail(e.Path, e.RuleID, errors.New(e.Error())) {
			return exitUsage
		}
	}
	if len(rs.Rules) == 0 {
		return exitFail
	}
	h, err := openHunter(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(stderr, "signalman hunt: %v\n", err)
		return exitUsage
	}
	defer func() { _ = h.Close() }()

	total := 0
	for i := range rs.Rules {
		r := &rs.Rules[i]
		hits, err := h.Hunt(ctx, *table, r, w)
		if err != nil {
			failed++
			if !fail(r.Path, r.ID, err) {
				return exitUsage
			}
			continue
		}
		total += len(hits)
		if *asJSON {
			rec := huntRecord{Path: r.Path, RuleID: r.ID, Title: r.Title, From: w.From, To: w.To, Hits: []huntHit{}}
			for _, hit := range hits {
				rec.Hits = append(rec.Hits, huntHit{hit.Partition, hit.Seq})
			}
			if err := enc.Encode(rec); err != nil {
				fmt.Fprintf(stderr, "signalman hunt: %v\n", err)
				return exitUsage
			}
			continue
		}
		fmt.Fprintf(stdout, "%s  %d hits  %s\n", r.ID, len(hits), r.Path)
		for _, hit := range hits {
			fmt.Fprintf(stdout, "  partition %d seq %d\n", hit.Partition, hit.Seq)
		}
	}
	if !*asJSON {
		fmt.Fprintf(stdout, "%d rules, %d hits over [%s, %s)\n", len(rs.Rules), total,
			w.From.Format(time.RFC3339Nano), w.To.Format(time.RFC3339Nano))
	}
	if failed > 0 {
		return exitFail
	}
	return exitOK
}

// huntWindow parses the window. Both ends are required: a hunt over all
// time on a 90 day table is rarely what anyone means, and an open end makes
// two runs incomparable.
func huntWindow(from, to string) (ch.Window, error) {
	if from == "" || to == "" {
		return ch.Window{}, fmt.Errorf("--from and --to are required")
	}
	f, err := time.Parse(time.RFC3339Nano, from)
	if err != nil {
		return ch.Window{}, fmt.Errorf("--from: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, to)
	if err != nil {
		return ch.Window{}, fmt.Errorf("--to: %w", err)
	}
	if !f.Before(t) {
		return ch.Window{}, fmt.Errorf("--from %s is not before --to %s", from, to)
	}
	return ch.Window{From: f.UTC(), To: t.UTC()}, nil
}
