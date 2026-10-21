package ch

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/atontalapur/signalman/internal/sigma"
)

// Window is a half-open event time range, [From, To), at millisecond
// precision, which is what the event_time column stores.
type Window struct {
	From, To time.Time
}

// Contains reports whether t falls in the window the way the query reads
// it: on the millisecond-truncated value.
func (w Window) Contains(t time.Time) bool {
	ms := t.UnixMilli()
	return ms >= w.From.UnixMilli() && ms < w.To.UnixMilli()
}

// Hit is one event a retro-hunt matched.
type Hit struct {
	Partition int32
	Seq       uint64
}

// HuntQuery is the full retro-hunt statement for r over w on table.
// DISTINCT folds the duplicates a ReplacingMergeTree holds until it merges;
// the order is fixed so two runs compare as slices.
func HuntQuery(table string, r *sigma.Rule, w Window) (string, error) {
	if err := checkTable(table); err != nil {
		return "", err
	}
	where, err := CompileRule(r)
	if err != nil {
		return "", err
	}
	q := "SELECT DISTINCT partition, seq FROM " + table +
		" WHERE toUnixTimestamp64Milli(" + colTime + ") >= " + strconv.FormatInt(w.From.UnixMilli(), 10) +
		" AND toUnixTimestamp64Milli(" + colTime + ") < " + strconv.FormatInt(w.To.UnixMilli(), 10) +
		" AND (" + where + ")" +
		" ORDER BY partition, seq"
	// max_query_size covers the whole statement, so a WHERE clause that
	// fits on its own can still be refused once wrapped.
	if len(q) > MaxQueryBytes {
		rj := reject(CodeTooLarge, "the retro-hunt query is %d bytes, over the %d byte limit", len(q), MaxQueryBytes)
		rj.RuleID = r.ID
		return "", rj
	}
	return q, nil
}

// RetroHunt runs r over the events stored in table within w. db is any
// database/sql handle on a ClickHouse server, so this package never imports
// a driver.
func RetroHunt(ctx context.Context, db *sql.DB, table string, r *sigma.Rule, w Window) ([]Hit, error) {
	q, err := HuntQuery(table, r, w)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("retro-hunt rule %s: %w", r.ID, err)
	}
	defer rows.Close()
	var out []Hit
	for rows.Next() {
		var h Hit
		if err := rows.Scan(&h.Partition, &h.Seq); err != nil {
			return nil, fmt.Errorf("retro-hunt rule %s: %w", r.ID, err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("retro-hunt rule %s: %w", r.ID, err)
	}
	return out, nil
}
