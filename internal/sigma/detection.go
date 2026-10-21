package sigma

import (
	"fmt"
	"sort"
	"strings"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"github.com/atontalapur/signalman/internal/sigma/match"
)

// CompileDetection turns the detection block into one predicate subtree per
// selection, plus the sorted selection names. The condition key is skipped;
// the caller parses it separately and binds the names with Expand.
//
// Map keys are sorted before the tree is built. Nothing here may depend on
// Go map iteration order, because the tree shape feeds the rule set hash and
// the hash has to be identical across loads of identical files.
func CompileDetection(raw map[string]any) (map[string]ast.Node, []string, error) {
	sels := make(map[string]ast.Node, len(raw))
	names := make([]string, 0, len(raw))
	for k := range raw {
		if k == "condition" {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		n, err := compileSelection(raw[name])
		if err != nil {
			return nil, nil, fmt.Errorf("selection %q: %w", name, err)
		}
		sels[name] = n
	}
	return sels, names, nil
}

func compileSelection(raw any) (ast.Node, error) {
	switch v := raw.(type) {
	case map[string]any:
		return compileMap(v)
	case []any:
		// A list of maps is an OR across the maps. A list of scalars is a
		// keyword search: an OR over every field value on the event.
		kids := make([]ast.Node, 0, len(v))
		for i, item := range v {
			switch item := item.(type) {
			case map[string]any:
				n, err := compileMap(item)
				if err != nil {
					return nil, fmt.Errorf("item %d: %w", i, err)
				}
				kids = append(kids, n)
			default:
				n, err := keywordPred(item)
				if err != nil {
					return nil, fmt.Errorf("item %d: %w", i, err)
				}
				kids = append(kids, n)
			}
		}
		if len(kids) == 0 {
			return nil, fmt.Errorf("empty selection")
		}
		if len(kids) == 1 {
			return kids[0], nil
		}
		return &ast.Or{Children: kids}, nil
	default:
		return keywordPred(raw)
	}
}

func compileMap(m map[string]any) (ast.Node, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	kids := make([]ast.Node, 0, len(keys))
	for _, key := range keys {
		parts := strings.Split(key, "|")
		field, mods := parts[0], parts[1:]

		vals, err := valueList(m[key])
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		matcher, err := match.Build(mods, vals)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		kids = append(kids, &ast.Pred{
			Field: field, Desc: describe(key, vals), Key: predKey(mods, vals), M: matcher,
			Mods: mods, Vals: vals,
		})
	}
	if len(kids) == 0 {
		return nil, fmt.Errorf("empty map in selection")
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	return &ast.And{Children: kids}, nil
}

// keywordPred implements a bare keyword: the value must appear somewhere in
// some field value on the event. The predicate carries no field name, and
// its matcher ignores the value it is handed and walks the event instead.
//
// Contains, rather than the spec's whole-value reading, is a deliberate
// divergence recorded in docs/modifiers.md and in KNOWN_DIVERGENCES.md.
func keywordPred(raw any) (ast.Node, error) {
	v, err := toValue(raw)
	if err != nil {
		return nil, err
	}
	text, ok := v.Text()
	if !ok {
		// A null keyword would be Contains(""), which matches every event
		// with any field at all. That is never what an author meant.
		return nil, fmt.Errorf("a keyword must be a scalar, got %s", v.Kind)
	}
	return &ast.Pred{
		Field:   "",
		Desc:    fmt.Sprintf("keyword '%s'", text),
		Key:     fmt.Sprintf("(keyword %q)", text),
		M:       keywordMatcher{inner: match.Contains(text)},
		Vals:    []event.Value{v},
		Keyword: true,
	}, nil
}

type keywordMatcher struct{ inner ast.Matcher }

// Match walks every field in a fixed order. The order cannot change the
// answer, since this is an OR, but a fixed order keeps the walk itself
// independent of map iteration.
func (k keywordMatcher) Match(_ event.Value, ev *event.Event) bool {
	names := make([]string, 0, len(ev.Fields))
	for n := range ev.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if k.inner.Match(ev.Fields[n], ev) {
			return true
		}
	}
	return false
}

func valueList(raw any) ([]event.Value, error) {
	if list, ok := raw.([]any); ok {
		out := make([]event.Value, 0, len(list))
		for _, item := range list {
			v, err := toValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	v, err := toValue(raw)
	if err != nil {
		return nil, err
	}
	return []event.Value{v}, nil
}

// toValue converts a decoded YAML scalar into an event.Value. A YAML float
// that is exactly an integer becomes an int, because YAML has no way to
// write 4688 that distinguishes it from 4688.0 and rule authors write ports
// and event IDs as plain numbers.
func toValue(x any) (event.Value, error) {
	switch v := x.(type) {
	case nil:
		return event.Null(), nil
	case string:
		return event.String(v), nil
	case int:
		return event.Int(int64(v)), nil
	case int64:
		return event.Int(v), nil
	case uint64:
		return event.Int(int64(v)), nil
	case float64:
		if v == float64(int64(v)) {
			return event.Int(int64(v)), nil
		}
		return event.String(fmt.Sprintf("%v", v)), nil
	case bool:
		return event.Bool(v), nil
	default:
		return event.Value{}, fmt.Errorf("unsupported value type %T", x)
	}
}

// describe is the explain-output form of one detection entry. It does not
// quote its values, so hashing relies on predKey, not on this.
func describe(key string, vals []event.Value) string {
	texts := make([]string, 0, len(vals))
	for _, v := range vals {
		if s, ok := v.Text(); ok {
			texts = append(texts, "'"+s+"'")
		} else {
			texts = append(texts, "null")
		}
	}
	return key + " " + strings.Join(texts, ", ")
}

// predKey is the hashing form of one detection entry: the modifier chain and
// the values match.Build was given, every string quoted, so that it decides
// the matcher and no two different inputs share a key. It carries each
// value's kind even though Build only tells null from text today, so a
// matcher that starts to care cannot slip past RuleSetV.
func predKey(mods []string, vals []event.Value) string {
	var b strings.Builder
	b.WriteString("(mods")
	for _, m := range mods {
		fmt.Fprintf(&b, " %q", m)
	}
	b.WriteString(") (vals")
	for _, v := range vals {
		if s, ok := v.Text(); ok {
			fmt.Fprintf(&b, " (%s %q)", v.Kind, s)
		} else {
			fmt.Fprintf(&b, " (%s)", v.Kind)
		}
	}
	b.WriteString(")")
	return b.String()
}
