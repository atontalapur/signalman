// Package corpus reads an event corpus: every .ndjson and .jsonl file under
// a directory, one JSON event per line. signalman noise and bench measure
// rules against one, and the cutover's G0 check replays one through both
// engines.
package corpus

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/atontalapur/signalman/internal/event"
)

// Event is one decoded corpus line and where it came from.
type Event struct {
	Event *event.Event
	File  string
	Line  int
}

// maxLine bounds one corpus line. A line longer than this is reported as an
// error rather than truncated into a different event.
const maxLine = 16 << 20

// Read reads every .ndjson and .jsonl file under dir, in sorted path
// order, one JSON object per line. Blank lines are skipped. Seq is the
// event's position in that order, so the corpus is one ordered stream and
// every run sees the same sequence. Any undecodable line fails the read: a
// noise figure over a corpus that silently lost events is wrong in the
// direction nobody checks.
func Read(dir string) ([]Event, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if ext := filepath.Ext(p); ext == ".ndjson" || ext == ".jsonl" {
				files = append(files, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var out []Event
	for _, f := range files {
		evs, err := readCorpusFile(f, uint64(len(out)))
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no events in .ndjson or .jsonl files under %s", dir)
	}
	return out, nil
}

func readCorpusFile(path string, seq uint64) ([]Event, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	var out []Event
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		ev, err := event.DecodeJSON(b)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		ev.Seq = seq
		seq++
		out = append(out, Event{Event: ev, File: path, Line: line})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s:%d: %w", path, line+1, err)
	}
	return out, nil
}
