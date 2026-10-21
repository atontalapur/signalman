// Package ch compiles a loaded Sigma rule into a ClickHouse SQL WHERE
// expression over the events table, for retro-hunting: running a rule over
// events that have already happened.
//
// The compiler is pure. It reads a bound ast tree and returns a string; it
// holds no connection and imports no driver. RetroHunt runs the query over
// database/sql, so the ClickHouse driver is the caller's choice.
//
// The design rule is that the SQL never re-implements a Sigma semantic that
// ClickHouse implements differently. Where the two disagree (case folding,
// numeric parsing, address parsing, invalid UTF-8), Encode computes the
// value in Go at write time, with the same functions v1 uses, and the SQL
// only compares. docs/backend-ch.md records each disagreement found.
package ch

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/atontalapur/signalman/internal/event"
)

// Column names. The compiler emits only these identifiers; nothing from a
// rule is ever written into the query as an identifier.
const (
	colPresent = "f_present"
	colText    = "f_text"
	colFolded  = "f_folded"
	colEqFold  = "f_eqfold"
	colInts    = "f_ints"
	colIPs     = "f_ips"
	colTime    = "event_time"
)

// DefaultTable is the events table the retro-hunt reads.
const DefaultTable = "events"

// tableName is the only identifier a caller supplies. It is checked, never
// quoted: database.table or table, ASCII letters, digits, and underscores.
var tableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)

func checkTable(table string) error {
	if !tableName.MatchString(table) {
		return fmt.Errorf("ch: table name %q is not database.table or table", table)
	}
	return nil
}

// CreateTableSQL is the events table DDL. The spec fixes the alerts table,
// not an events table; this one keeps the alert table's key and 90 day
// retention, and replaces its fields Map(String, String) with one column per
// comparison family. Partitioning and TTL read ingest_time, which the
// pipeline sets, not event_time, which the source sets: an old or skewed
// event_time would be TTL-deleted on arrival, and an insert spanning more
// than 100 daily partitions is refused. event_time is used only in WHERE. Each holds a value v1 would
// compute at match time, computed once in Go by Encode. No column is
// Nullable, so SQL NULL and its three-valued logic never enter a WHERE
// clause. See docs/backend-ch.md.
func CreateTableSQL(table string) (string, error) {
	if err := checkTable(table); err != nil {
		return "", err
	}
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
  partition   Int32,
  seq         UInt64,
  event_time  DateTime64(3, 'UTC'),
  ingest_time DateTime64(3, 'UTC'),
  source      LowCardinality(String),
  f_present   Array(String),
  f_text      Map(String, Array(String)),
  f_folded    Map(String, Array(String)),
  f_eqfold    Map(String, Array(String)),
  f_ints      Map(String, Array(Int64)),
  f_ips       Map(String, Array(String)),
  raw         String CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree
ORDER BY (partition, seq)
PARTITION BY toYYYYMMDD(ingest_time)
TTL toDateTime(ingest_time) + INTERVAL 90 DAY`, nil
}

// Values returns the row's columns in CreateTableSQL order, for a
// positional batch insert.
func (r Row) Values() []any {
	return []any{
		r.Partition, r.Seq, r.EventTime, r.IngestTime, r.Source,
		r.Present, r.Text, r.Folded, r.EqFold, r.Ints, r.IPs, r.Raw,
	}
}

// Row is one event as stored. Field order matches CreateTableSQL; Values
// returns them in that order.
//
// For every field, the map entries hold one element per value the field
// carries: one for a scalar, one per element for a list. Only elements with
// a text form (string, int, bool) are stored, because those are the only
// ones any comparison can match; a null element or a nested list is never a
// match in v1 either.
type Row struct {
	Partition  int32
	Seq        uint64
	EventTime  time.Time // truncated to the millisecond, UTC
	IngestTime time.Time // truncated to the millisecond, UTC
	Source     string
	// Present lists the fields whose value is not null, sorted. A field
	// that is absent or explicitly null is missing from it, which is the
	// one thing "field: null" tests.
	Present []string
	// Text is Value.Text with each invalid UTF-8 byte replaced by U+FFFD,
	// which is the rune Go's regexp reads for it. Regex runs here.
	Text map[string][]string
	// Folded is strings.ToLower(Value.Text): the form the wildcard matcher
	// compares. Equals, contains, startswith, endswith, and keywords run here.
	Folded map[string][]string
	// EqFold maps each rune to the least rune of its unicode.SimpleFold
	// orbit, so two texts are strings.EqualFold exactly when their keys are
	// equal. fieldref runs here.
	EqFold map[string][]string
	// Ints holds every value lt, lte, gt, and gte can compare: an int as
	// is, a string that strconv.ParseInt accepts after strings.TrimSpace.
	Ints map[string][]int64
	// IPs holds every value netip.ParseAddr accepts, without a zone, as a
	// family digit and the address in fixed-width hex: "4" and 8 digits, or
	// "6" and 32. Byte order then equals numeric order within a family, and
	// the two families never compare equal. cidr runs here.
	IPs map[string][]string
	Raw string
}

// Encode turns an event into its stored row. It is a pure function of the
// event, and it is the only place a stored value is derived.
func Encode(ev *event.Event) Row {
	r := Row{
		Partition:  ev.Partition,
		Seq:        ev.Seq,
		EventTime:  ev.EventTime.UTC().Truncate(time.Millisecond),
		IngestTime: ev.IngestAt.UTC().Truncate(time.Millisecond),
		Source:     ev.Source,
		Present:    []string{},
		Text:       map[string][]string{},
		Folded:     map[string][]string{},
		EqFold:     map[string][]string{},
		Ints:       map[string][]int64{},
		IPs:        map[string][]string{},
		Raw:        string(ev.Raw),
	}
	names := make([]string, 0, len(ev.Fields))
	for n := range ev.Fields {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		v := ev.Fields[name]
		if v.Kind == event.KindNull {
			continue
		}
		r.Present = append(r.Present, name)
		items := []event.Value{v}
		if v.Kind == event.KindList {
			items = v.L
		}
		for _, item := range items {
			s, ok := item.Text()
			if !ok {
				continue
			}
			r.Text[name] = append(r.Text[name], runeSafe(s))
			r.Folded[name] = append(r.Folded[name], strings.ToLower(s))
			r.EqFold[name] = append(r.EqFold[name], FoldKey(s))
			if n, ok := intOf(item); ok {
				r.Ints[name] = append(r.Ints[name], n)
			}
			if a, ok := IPKey(s); ok {
				r.IPs[name] = append(r.IPs[name], a)
			}
		}
	}
	return r
}

// intOf is match.Compare's reading of one value.
func intOf(v event.Value) (int64, bool) {
	switch v.Kind {
	case event.KindInt:
		return v.I, true
	case event.KindString:
		n, err := strconv.ParseInt(strings.TrimSpace(v.S), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// runeSafe replaces each invalid UTF-8 byte with U+FFFD, one for one. Go's
// regexp decodes the same input to the same rune sequence, so a regex gives
// the same answer on either; RE2 in ClickHouse is undefined on invalid
// UTF-8 and gets only the valid form.
func runeSafe(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		b.WriteRune(r) // range yields RuneError for each invalid byte
	}
	return b.String()
}

// FoldKey is the strings.EqualFold canonical form: each rune, with invalid
// bytes read as U+FFFD the way EqualFold reads them, replaced by the least
// rune of its simple fold orbit.
func FoldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldMin(r))
	}
	return b.String()
}

func foldMin(r rune) rune {
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < m {
			m = f
		}
	}
	return m
}

// IPKey is the stored form of an address match.CIDR could match: what
// netip.ParseAddr accepts, minus zoned addresses, which Prefix.Contains
// never matches.
func IPKey(s string) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return addrKey(a), true
}

func addrKey(a netip.Addr) string {
	if a.Is4() {
		b := a.As4()
		return "4" + hex.EncodeToString(b[:])
	}
	b := a.As16()
	return "6" + hex.EncodeToString(b[:])
}

// prefixRange is the first and last stored key inside a masked prefix.
func prefixRange(p netip.Prefix) (lo, hi string) {
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		last := b
		setHostBits(last[:], p.Bits())
		return "4" + hex.EncodeToString(b[:]), "4" + hex.EncodeToString(last[:])
	}
	b := a.As16()
	last := b
	setHostBits(last[:], p.Bits())
	return "6" + hex.EncodeToString(b[:]), "6" + hex.EncodeToString(last[:])
}

func setHostBits(b []byte, bits int) {
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 0x80 >> j
			}
		}
	}
}
