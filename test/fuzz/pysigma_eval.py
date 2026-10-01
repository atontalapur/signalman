"""Evaluate one Sigma rule against one event, as an oracle for the Go engine.

Reads newline-delimited JSON on stdin, one object per request:
    {"rule": "<yaml>", "event": {"Field": "value", ...}}
Writes {"ready": true} once the imports are done, then one object per
request:
    {"matched": true, "fields": ["Field", ...], "degenerate": false}
    {"refusal": "<code>", "error": "..."}
    {"error": "..."}

A refusal carries a code from a closed set, and the Go side suppresses on
the code alone. Matching on message text would let a rule value that
happens to contain the text suppress an unrelated failure. An error with no
refusal code is something the oracle did not expect, and the Go side
reports it.

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
import os
import re
import sqlite3
import sys

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import (
    SigmaIdentifierError,
    SigmaModifierError,
    SigmaRegularExpressionError,
    SigmaValueError,
)

# Built once. Conversion does not carry state between rules, and the oracle
# is the slow side of every fuzz case.
BACKEND = sqliteBackend()

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

    code is one of the refusal codes the Go side knows. Distinct from a rule
    the oracle rejects for a reason nobody has documented: those carry no
    code and fail the fuzz case.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def strings(node):
    """Yield every string in a parsed YAML node, keys included."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from strings(k)
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


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
    return any("\x00" in v for v in strings(node))


def detection_keys(doc):
    """Return (fields, modifiers, value_only, keyed) for the detection block.

    value_only is true when any search identifier is a bare value or a list
    of bare values rather than a field mapping. Sigma calls that a keyword
    search; the sqlite backend has no form for it and fails in more than one
    way, so the oracle declines it before conversion rather than after.

    keyed is a list of (field, modifiers, values), one per field key, so a
    check about one modifier can look at that modifier's values and nothing
    else. A check that looks at the whole rule declines cases because of a
    value it has nothing to do with.

    Taken from the source rather than from pySigma's object model: the point
    of the oracle is to share as little as possible with either engine.
    """
    if not isinstance(doc, dict):
        raise TypeError("rule is not a mapping")
    det = doc.get("detection")
    if not isinstance(det, dict):
        raise TypeError("rule has no detection block")

    fields, mods = set(), set()
    keyed = []
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
            key_mods = {p.lower() for p in parts[1:]}
            fields.add(parts[0])
            mods.update(key_mods)
            keyed.append((parts[0], key_mods, list(strings(node[k]))))

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
    return sorted(fields), mods, value_only, keyed


def query(rule_yaml: str) -> str:
    queries = BACKEND.convert(SigmaCollection.from_yaml(rule_yaml))
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
#
# Checked only under base64offset, the one modifier that produces it, and
# only outside string literals: the SQL quotes a ' in a value as '', so a
# value like a=' would otherwise read as an empty comparison.
DEGENERATE = ("LIKE '%' ESCAPE", "=''")

# A SQL string literal, with '' as an escaped quote inside it.
LITERAL = re.compile(r"'(?:[^']|'')*'")


def strip_literals(sql: str) -> str:
    """Blank the contents of every string literal in the query.

    Every structural check on the query runs on this, because the literals
    are the rule's values and the fuzzer puts arbitrary text there. The two
    literals the degenerate check looks for are kept as they are.
    """

    def blank(m):
        lit = m.group(0)
        return lit if lit in ("'%'", "''") else "'_'"

    return LITERAL.sub(blank, sql)


def is_degenerate(sql: str, mods) -> bool:
    if "base64offset" not in mods:
        return False
    bare = strip_literals(sql)
    return any(d in bare for d in DEGENERATE)

# The sqlite backend emits a negated multi-variant selection as
# "NOT a LIKE x OR a LIKE y", with no parentheses. NOT binds tighter than OR
# in SQL, so the query means "(NOT a) OR b", which is not what the rule says.
# It is a backend defect, not a Sigma question, and the oracle cannot answer
# a query it has mis-generated: it says so instead.
UNPARENTHESIZED_NOT = re.compile(r"NOT\s+(?!\()")


def check_query(sql: str) -> None:
    """Refuse a query where a bare NOT is followed by an OR in its own group.

    "NOT a OR b" is the defect. "(a OR b) AND (NOT c)" is not: that OR is
    in another group. Literals are blanked first so a value cannot supply
    either keyword.
    """
    bare = strip_literals(sql)
    for m in UNPARENTHESIZED_NOT.finditer(bare):
        depth = 0
        for i in range(m.end(), len(bare)):
            ch = bare[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    break
            elif depth == 0 and bare.startswith(" OR ", i):
                raise Unanswerable("unparenthesized-not", "NOT outside parentheses")

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


def evaluate(rule_yaml: str, event: dict, fields, mods):
    sql = query(rule_yaml)
    degenerate = is_degenerate(sql, mods)
    check_query(sql)

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
        #
        # TEXT affinity because Sigma compares values as strings. An integer
        # event value is stored as its digits, so "443" matches 443 and
        # "0443" does not; with INTEGER affinity SQLite would coerce "0443"
        # to 443 and answer a question Sigma does not ask.
        quoted = ", ".join(f"{ident(c)} TEXT COLLATE NOCASE" for c in cols)
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
    doc = yaml.safe_load(rule_yaml)
    # SQLite refuses a query carrying a NUL, and the query is where the rule
    # values end up. Signalman compares bytes and has no such limit, so the
    # oracle says up front that it cannot answer rather than raising from
    # inside the driver.
    if contains_nul(doc) or contains_nul(event):
        raise Unanswerable("nul", "NUL in a rule or event value")

    fields, mods, value_only, keyed = detection_keys(doc)
    for _, key_mods, values in keyed:
        if "base64offset" in key_mods and any(not v.isascii() for v in values):
            # pySigma indexes its offset trim table by the plaintext's
            # character count; base64 works on bytes, and Signalman indexes
            # by byte count. The two agree on ASCII and nowhere else.
            raise Unanswerable("base64offset-non-ascii", "non-ASCII under base64offset")
    bad = sorted(mods & UNSUPPORTED)
    if bad:
        raise Unanswerable("unsupported-modifier", f"modifier {bad[0]}")
    if value_only:
        raise Unanswerable("value-only", "value-only expression")
    for field, key_mods, values in keyed:
        if "re" not in key_mods:
            continue
        if any(REGEX_SHORTHAND.search(v) for v in values):
            raise Unanswerable("regex-shorthand", "regex class shorthand")
        if any(REGEX_BRACE.search(v) for v in values):
            raise Unanswerable("regex-brace", "regex repetition brace")
        v = event.get(field)
        if isinstance(v, str) and "\n" in v:
            # Python's $ also matches just before a trailing newline and
            # RE2's does not, so "$^" matches "\n" here and not in Go. The
            # anchors and the newline class are where the two engines
            # genuinely differ, and the oracle cannot arbitrate its own
            # dialect.
            raise Unanswerable("regex-newline", "newline under a regex")
    try:
        matched, degenerate = evaluate(rule_yaml, event, fields, mods)
    except Exception as exc:
        code = refusal_code(exc)
        if code is None:
            raise
        raise Unanswerable(code, f"{type(exc).__name__}: {exc}") from exc
    return {"matched": matched, "fields": fields, "degenerate": degenerate}


# pySigma and SQLite refusals that KNOWN_DIVERGENCES.md documents, keyed on
# the exception class and the fixed start of its message. The message start
# is vendor text that comes before any interpolated rule value, so a value
# cannot forge it. test_suppression_literals_still_exist_in_vendor in the Go
# tests fails if a pySigma upgrade rewords one.
WIDE = re.compile(r"^(Wide|UTF-16\w*) modifier only allowed for (ascii|valid Unicode) strings")


def refusal_code(exc: Exception):
    msg = str(exc.args[0]) if exc.args else ""
    if isinstance(exc, SigmaIdentifierError):
        return "id-not-uuid"
    if isinstance(exc, SigmaRegularExpressionError):
        return "regex-python-rejects"
    if isinstance(exc, SigmaModifierError) and msg.startswith("Unknown modifier"):
        return "unknown-modifier"
    if isinstance(exc, SigmaValueError) and WIDE.match(msg):
        return "wide-non-ascii"
    if isinstance(exc, SigmaValueError) and msg.startswith(
        "Base64 encoding of strings with wildcards is not allowed"
    ):
        return "wildcard-in-encoding"
    if isinstance(exc, sqlite3.OperationalError) and msg.startswith(
        "Expression tree is too large"
    ):
        return "sqlite-depth"
    return None


def respond(req: dict) -> dict:
    """Answer one request. Never raises: the oracle answers every request,
    and the Go side decides whether an error is a documented divergence."""
    try:
        return handle(req)
    except Unanswerable as exc:
        return {"refusal": exc.code, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


# Runs as its own process: a thread could not run while re holds the GIL in
# a backtracking match, which is exactly when it is needed.
WATCHER = """
import os, signal, sys, time
parent, oracle = int(sys.argv[1]), int(sys.argv[2])
def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
while alive(oracle):
    if not alive(parent):
        os.kill(oracle, signal.SIGKILL)
        break
    time.sleep(1)
"""


def watch_parent() -> None:
    """Kill this process if the process that started it goes away.

    An idle oracle exits on stdin EOF when its fuzz worker dies, but one
    stuck in a backtracking regex never reads stdin again and would run
    until the regex finished. The watcher holds no copy of the oracle's
    pipes, so it cannot keep them open after the oracle exits.
    """
    import subprocess

    subprocess.Popen(
        [sys.executable, "-c", WATCHER, str(os.getppid()), str(os.getpid())],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def main() -> None:
    watch_parent()
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
        out = respond(json.loads(line))
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
