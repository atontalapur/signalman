package chsink

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const ddlPath = "../../../deploy/clickhouse/001_alerts.sql"

// specColumns is the alert table from the spec (phase 04), in order.
var specColumns = [][2]string{
	{"partition", "Int32"},
	{"seq", "UInt64"},
	{"rule_id", "UUID"},
	{"rule_title", "LowCardinality(String)"},
	{"severity", "Enum8('informational'=1,'low'=2,'medium'=3,'high'=4,'critical'=5)"},
	{"event_time", "DateTime64(3)"},
	{"ingest_time", "DateTime64(3)"},
	{"host_id", "LowCardinality(String)"},
	{"source", "LowCardinality(String)"},
	{"fields", "Map(String, String)"},
	{"raw", "String CODEC(ZSTD(3))"},
}

func readDDL(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(ddlPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ddlColumns returns the column lines of the CREATE TABLE as name, type.
func ddlColumns(t *testing.T, ddl string) [][2]string {
	t.Helper()
	m := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS signalman\.alerts \((.*?)\n\) ENGINE`).FindStringSubmatch(ddl)
	if m == nil {
		t.Fatal("no CREATE TABLE IF NOT EXISTS signalman.alerts (...) ENGINE in the DDL")
	}
	var cols [][2]string
	for line := range strings.SplitSeq(m[1], "\n") {
		line = strings.TrimSuffix(strings.TrimSpace(line), ",")
		if line == "" {
			continue
		}
		name, typ, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("column line %q", line)
		}
		cols = append(cols, [2]string{name, strings.TrimSpace(typ)})
	}
	return cols
}

func TestDDLColumnsMatchSpec(t *testing.T) {
	cols := ddlColumns(t, readDDL(t))
	if len(cols) != len(specColumns) {
		t.Fatalf("%d columns, spec has %d: %v", len(cols), len(specColumns), cols)
	}
	for i, c := range cols {
		if c != specColumns[i] {
			t.Errorf("column %d is %v, spec says %v", i, c, specColumns[i])
		}
	}
}

// Partitioning and TTL read ingest_time, which the pipeline sets from the
// events.raw record, not event_time, which the source sets: an old event
// time would be TTL-deleted on insert, and a skewed batch would span more
// than 100 partitions. The spec says event_time; docs/pipeline.md records
// the deviation.
func TestDDLEngineOrderPartitionTTL(t *testing.T) {
	ddl := readDDL(t)
	for _, want := range []string{
		") ENGINE = ReplacingMergeTree\n",
		"\nORDER BY (partition, seq, rule_id)\n",
		"\nPARTITION BY toYYYYMMDD(ingest_time)\n",
		"\nTTL toDateTime(ingest_time) + INTERVAL 90 DAY\n",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("DDL lacks %q", want)
		}
	}
}

// The INSERT the sink sends names the table's columns in table order, so a
// column added to one and not the other fails here, not in production.
func TestInsertColumnsMatchDDL(t *testing.T) {
	cols := ddlColumns(t, readDDL(t))
	if len(cols) != len(Columns) {
		t.Fatalf("DDL has %d columns, the insert names %d", len(cols), len(Columns))
	}
	for i, c := range cols {
		if c[0] != Columns[i] {
			t.Errorf("insert column %d is %q, DDL has %q", i, Columns[i], c[0])
		}
	}
}

// Every severity the enum accepts is one the sink accepts, and no other.
func TestSeveritiesMatchEnum(t *testing.T) {
	enum := specColumns[4][1]
	for _, s := range []string{"informational", "low", "medium", "high", "critical"} {
		if !strings.Contains(enum, "'"+s+"'") || !validSeverity(s) {
			t.Errorf("severity %q", s)
		}
	}
	for _, s := range []string{"", "High", "info", "severe"} {
		if validSeverity(s) {
			t.Errorf("severity %q accepted", s)
		}
	}
}

func TestStatementsSplitsTheDDL(t *testing.T) {
	stmts := Statements(readDDL(t))
	if len(stmts) != 2 {
		t.Fatalf("%d statements: %q", len(stmts), stmts)
	}
	if !strings.HasPrefix(stmts[0], "CREATE DATABASE IF NOT EXISTS signalman") ||
		!strings.HasPrefix(stmts[1], "CREATE TABLE IF NOT EXISTS signalman.alerts") {
		t.Fatalf("statements %q", stmts)
	}
	for _, s := range stmts {
		if strings.Contains(s, "--") || strings.HasSuffix(s, ";") {
			t.Fatalf("statement keeps a comment or terminator: %q", s)
		}
	}
}
