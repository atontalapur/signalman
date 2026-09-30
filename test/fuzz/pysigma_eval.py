"""Evaluate one Sigma rule against one event, as an oracle for the Go engine.

Reads newline-delimited JSON on stdin, one object per request:
    {"rule": "<yaml>", "event": {"Field": "value", ...}}
Writes {"ready": true} once the imports are done, then one object per
request:
    {"matched": true, "fields": ["Field", ...]}
    {"error": "..."}

pySigma converts rules, it does not evaluate events. So the rule is converted
to a SQLite query, the event is materialized as a single-row table, and the
query is run against it. The parser, the modifier expansion, and the
comparison engine on this path are all separate from the Go implementation,
which is the only reason the comparison is worth anything.

Fields the rule reads are reported back so the Go side can tell an honest
disagreement from a case that lands in one of the gaps recorded in
KNOWN_DIVERGENCES.md.
"""

import json
import re
import sqlite3
import sys

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

# Modifiers the oracle refuses rather than answers wrongly. Each one has a
# section in KNOWN_DIVERGENCES.md saying what the backend does instead.
UNSUPPORTED = {
    "cidr",  # converted to a string prefix LIKE, which is not CIDR
    "lt",
    "lte",
    "gt",
    "gte",  # SQL compares a TEXT column to a number by type rank
    "fieldref",  # the backend has no column-to-column form
}

TABLE = "events"


class Unanswerable(Exception):
    """The oracle cannot answer this case, and says which shape it is.

    Distinct from a rule the oracle rejects: the Go side counts these as
    unevaluated rather than as a difference in what loads.
    """


def non_ascii(node) -> bool:
    """Report whether any string in the parsed rule is not pure ASCII."""
    if isinstance(node, str):
        return not node.isascii()
    if isinstance(node, dict):
        return any(non_ascii(k) or non_ascii(v) for k, v in node.items())
    if isinstance(node, list):
        return any(non_ascii(v) for v in node)
    return False


def ident(name: str) -> str:
    """Quote a column name for SQLite, doubling any embedded quote.

    Field names come from the rule, and a name carrying a double quote would
    otherwise close the identifier and let the rest of it run as SQL against
    this connection, which can ATTACH files. The generator only produces
    names from a fixed list today, so nothing reaches this yet; the escaping
    does not depend on that staying true. Doubling rather than rejecting,
    because a Sigma field name legitimately carries dots and dashes.
    """
    return '"' + name.replace('"', '""') + '"'


def contains_nul(node) -> bool:
    """Report whether any string in the parsed rule carries a NUL.

    The check is on the parsed document, not the YAML text: a NUL reaches
    the rule as the escape sequence \\0 inside a quoted scalar, so the text
    itself is NUL-free and only the value is not.
    """
    if isinstance(node, str):
        return "\x00" in node
    if isinstance(node, dict):
        return any(contains_nul(k) or contains_nul(v) for k, v in node.items())
    if isinstance(node, list):
        return any(contains_nul(v) for v in node)
    return False


def detection_keys(rule_yaml: str):
    """Return (fields, modifiers, value_only) for the detection block.

    value_only is true when any search identifier is a bare value or a list
    of bare values rather than a field mapping. Sigma calls that a keyword
    search; the sqlite backend has no form for it and fails in more than one
    way, so the oracle declines it before conversion rather than after.

    Taken from the source rather than from pySigma's object model: the point
    of the oracle is to share as little as possible with either engine.
    """
    doc = yaml.safe_load(rule_yaml)
    if not isinstance(doc, dict):
        raise TypeError("rule is not a mapping")
    det = doc.get("detection")
    if not isinstance(det, dict):
        raise TypeError("rule has no detection block")

    fields, mods = set(), set()
    value_only = False

    def field_map(node):
        # A field mapping: keys are field names with an optional modifier
        # chain, values are scalars or lists of scalars and are not walked.
        for k in node:
            if not isinstance(k, str):
                # A non-string key is not a field name pySigma will accept;
                # let the conversion be the one to say so.
                continue
            parts = k.split("|")
            fields.add(parts[0])
            mods.update(p.lower() for p in parts[1:])

    def block(node):
        nonlocal value_only
        if isinstance(node, dict):
            field_map(node)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    field_map(item)
                else:
                    value_only = True
        else:
            value_only = True

    for name, b in det.items():
        if name == "condition":
            continue
        block(b)
    fields.discard("")
    return sorted(fields), mods, value_only


def query(rule_yaml: str) -> str:
    queries = sqliteBackend().convert(SigmaCollection.from_yaml(rule_yaml))
    if len(queries) != 1:
        raise ValueError(f"expected 1 query, got {len(queries)}")
    return queries[0].replace("<TABLE_NAME>", TABLE)


# A base64offset of a very short plaintext determines no complete base64
# character at some alignments, so pySigma emits a term with an empty
# pattern. LIKE '%' matches every row and ='' matches an empty field, which
# is a rule that alerts on everything. Signalman drops empty variants and
# rejects a chain whose variants are all empty; see docs/modifiers.md. The
# oracle reports the shape so the Go side can recognize it instead of
# reporting a divergence that is a documented decision.
DEGENERATE = ("LIKE '%' ESCAPE", "=''")

# The sqlite backend emits a negated multi-variant selection as
# "NOT a LIKE x OR a LIKE y", with no parentheses. NOT binds tighter than OR
# in SQL, so the query means "(NOT a) OR b", which is not what the rule says.
# It is a backend defect, not a Sigma question, and the oracle cannot answer
# a query it has mis-generated: it says so instead.
UNPARENTHESIZED_NOT = re.compile(r"NOT\s+(?!\()")

# The character class shorthands do not name the same sets in the two
# engines. Python's \s includes \x1c to \x1f and its \w and \d are Unicode;
# RE2's \s is [\t\n\f\r ] and its \w and \d are ASCII. A pattern using one
# is a question about which dialect Sigma means, which the oracle cannot
# settle, so it declines instead of answering from its own.
REGEX_SHORTHAND = re.compile(r"\\[sSwWdDbB]")

# RE2 accepts only a canonical repetition count and treats anything else as
# literal text: "0{00}" is the five-character string in Go and a zero-width
# repetition in Python, and "{,3}" and "{}" split the same way. The forms the
# two engines agree on are not worth the ones they do not, so the oracle
# declines a braced pattern outright.
REGEX_BRACE = re.compile(r"[{}]")


def evaluate(rule_yaml: str, event: dict, fields):
    sql = query(rule_yaml)
    degenerate = any(d in sql for d in DEGENERATE)
    if " OR " in sql and UNPARENTHESIZED_NOT.search(sql):
        raise Unanswerable("unsupported-query: NOT outside parentheses")

    # Columns the rule reads but the event does not carry exist and are NULL,
    # so a reference to an absent field is a comparison against NULL instead
    # of a "no such column" error. Sigma treats an absent field as no match,
    # which is what NULL gives for every comparison except a negated one.
    cols = sorted(set(event) | set(fields))
    conn = sqlite3.connect(":memory:")
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    if cols:
        # COLLATE NOCASE because Sigma string comparison is case insensitive
        # by default and SQLite's = is not. LIKE already ignores ASCII case,
        # so without this the same rule would be case insensitive through
        # contains and case sensitive through a plain equals. NOCASE folds
        # ASCII only; a non-ASCII case difference stays a divergence and is
        # recorded in KNOWN_DIVERGENCES.md.
        quoted = ", ".join(f"{ident(c)} COLLATE NOCASE" for c in cols)
        conn.execute(f"CREATE TABLE {TABLE} ({quoted})")
        insert_cols = ", ".join(ident(c) for c in cols)
        placeholders = ", ".join("?" for _ in cols)
        conn.execute(
            f"INSERT INTO {TABLE} ({insert_cols}) VALUES ({placeholders})",
            [event.get(c) for c in cols],
        )
    else:
        conn.execute(f"CREATE TABLE {TABLE} (_empty)")
        conn.execute(f"INSERT INTO {TABLE} (_empty) VALUES (NULL)")

    cur = conn.execute(f"SELECT count(*) FROM ({sql})")
    return cur.fetchone()[0] > 0, degenerate


def _regexp(pattern, value):
    # SQLite has no REGEXP implementation of its own. Python's engine is not
    # RE2, so pattern-syntax divergences are real; they show up as an error
    # on one side, never as a silently different verdict.
    if value is None:
        return False
    return re.search(pattern, value) is not None


def handle(req: dict) -> dict:
    rule_yaml = req["rule"]
    event = req["event"] or {}
    # SQLite refuses a query carrying a NUL, and the query is where the rule
    # values end up. Signalman compares bytes and has no such limit, so the
    # oracle says up front that it cannot answer rather than raising from
    # inside the driver.
    if contains_nul(yaml.safe_load(rule_yaml)) or contains_nul(event):
        return {"error": "unsupported-value: NUL"}

    fields, mods, value_only = detection_keys(rule_yaml)
    if "base64offset" in mods and non_ascii(yaml.safe_load(rule_yaml)):
        # pySigma indexes its offset trim table by the plaintext's character
        # count; base64 works on bytes, and Signalman indexes by byte count.
        # The two agree on ASCII and disagree on everything else.
        return {"error": "unsupported-value: non-ASCII under base64offset"}
    bad = sorted(mods & UNSUPPORTED)
    if bad:
        return {"error": f"unsupported-modifier: {bad[0]}"}
    if value_only:
        return {"error": "unsupported-feature: value-only expression"}
    if "re" in mods and REGEX_SHORTHAND.search(rule_yaml):
        return {"error": "unsupported-value: regex class shorthand"}
    if "re" in mods and REGEX_BRACE.search(rule_yaml):
        return {"error": "unsupported-value: regex repetition brace"}
    if "re" in mods and any("\n" in v for v in event.values() if v):
        # Python's $ also matches just before a trailing newline and RE2's
        # does not, so "$^" matches "\n" here and not in Go. The anchors and
        # the newline class are where the two engines genuinely differ, and
        # the oracle cannot arbitrate its own dialect.
        return {"error": "unsupported-value: newline under a regex"}
    matched, degenerate = evaluate(rule_yaml, event, fields)
    return {"matched": matched, "fields": fields, "degenerate": degenerate}


def main() -> None:
    # Announce readiness once the imports are done. pySigma takes seconds to
    # load, and the Go side's per-request deadline is meant to bound a
    # backtracking regex, not interpreter warm-up: without this line the
    # first request pays for both and times out on a loaded machine.
    sys.stdout.write(json.dumps({"ready": True}) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            out = handle(json.loads(line))
        except Unanswerable as exc:
            out = {"error": str(exc)}
        # Blind on purpose: the oracle answers every request, and the Go
        # side decides whether a refusal is a documented divergence.
        except Exception as exc:  # noqa: BLE001
            out = {"error": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
