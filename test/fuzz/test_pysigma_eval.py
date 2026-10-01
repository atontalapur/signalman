"""Unit tests for the oracle's own checks.

Each check in pysigma_eval.py either declines a case or marks it for
suppression on the Go side. A check that fires too often does not fail the
fuzzer; it quietly removes cases from comparison. So every check here gets a
case where it must fire and a case where it must not, and the negative cases
put the trigger text inside a rule value, which is where the fuzzer puts
arbitrary strings.

Run with the oracle's venv: test/fuzz/.venv/bin/python -m unittest
discover -s test/fuzz -p 'test_*.py'
"""

import unittest

import pysigma_eval as pe

RULE = """title: t
id: 00000000-0000-4000-8000-000000000000
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    {key}: {value}
  condition: {condition}
"""


def rule(key, value, condition="selection"):
    return RULE.format(key=key, value=value, condition=condition)


def ask(key, value, event, condition="selection"):
    return pe.respond({"rule": rule(key, value, condition), "event": event})


class StripLiterals(unittest.TestCase):
    def test_blanks_quoted_text(self):
        self.assertEqual(
            pe.strip_literals("a LIKE '%x NOT y OR z%' ESCAPE '\\'"),
            "a LIKE '_' ESCAPE '_'",
        )

    def test_keeps_the_degenerate_literals(self):
        self.assertEqual(pe.strip_literals("a LIKE '%' ESCAPE '\\'"), "a LIKE '%' ESCAPE '_'")
        self.assertEqual(pe.strip_literals("a=''"), "a=''")

    def test_doubled_quote_stays_inside_the_literal(self):
        self.assertEqual(pe.strip_literals("a='x='''"), "a='_'")


class Degenerate(unittest.TestCase):
    def test_quote_in_value_is_not_degenerate(self):
        for value in ["\"a='\"", "\"'abc\"", "\"x=''\""]:
            with self.subTest(value=value):
                out = ask("Image|contains", value, {"Image": "zzz"})
                self.assertNotIn("error", out)
                self.assertFalse(out["degenerate"])

    def test_short_base64offset_is_degenerate(self):
        out = ask("CommandLine|base64offset|contains", "a", {"CommandLine": "zzz"})
        self.assertNotIn("error", out)
        self.assertTrue(out["degenerate"])

    def test_only_under_base64offset(self):
        self.assertFalse(pe.is_degenerate("Image=''", set()))
        self.assertTrue(pe.is_degenerate("Image=''", {"base64offset"}))


class UnparenthesizedNot(unittest.TestCase):
    def test_not_and_or_inside_a_value_are_answered(self):
        out = ask("CommandLine|contains", '"x NOT y OR z"', {"CommandLine": "x NOT y OR z"})
        self.assertNotIn("error", out)
        self.assertTrue(out["matched"])

    def test_structural_not_is_refused(self):
        with self.assertRaises(pe.Unanswerable):
            pe.check_query("NOT a LIKE 'x' OR a LIKE 'y'")

    def test_parenthesized_not_is_answered(self):
        pe.check_query("NOT (a LIKE 'x' OR a LIKE 'y')")

    def test_bare_not_beside_an_or_in_another_group_is_answered(self):
        pe.check_query("(a LIKE 'x' OR a LIKE 'y') AND (NOT b='z')")

    def test_generated_not_over_variants_is_refused(self):
        r = rule("CommandLine|base64offset|contains", "abc", "not selection")
        out = pe.respond({"rule": r, "event": {"CommandLine": "x"}})
        self.assertEqual(out.get("refusal"), "unparenthesized-not")


class RegexChecks(unittest.TestCase):
    def test_brace_outside_the_regex_value_is_answered(self):
        r = rule("Image|re", "'^a'", "selection and not filter").replace(
            "  condition:", "  filter:\n    User: '{x}'\n  condition:"
        )
        out = pe.respond({"rule": r, "event": {"Image": "abc", "User": "u"}})
        self.assertNotIn("error", out)

    def test_brace_in_the_regex_value_is_refused(self):
        out = ask("Image|re", "'a{2}'", {"Image": "aa"})
        self.assertEqual(out.get("refusal"), "regex-brace")

    def test_shorthand_in_the_regex_value_is_refused(self):
        out = ask("Image|re", "'\\d'", {"Image": "1"})
        self.assertEqual(out.get("refusal"), "regex-shorthand")

    def test_backslash_path_outside_the_regex_is_answered(self):
        r = rule("Image|re", "'^a'", "selection and not filter").replace(
            "  condition:", "  filter:\n    User: 'C:\\data'\n  condition:"
        )
        out = pe.respond({"rule": r, "event": {"Image": "abc", "User": "u"}})
        self.assertNotIn("error", out)

    def test_newline_in_an_unrelated_field_is_answered(self):
        r = rule("Image|re", "'^a'", "selection and not filter").replace(
            "  condition:", "  filter:\n    User: x\n  condition:"
        )
        out = pe.respond({"rule": r, "event": {"Image": "abc", "User": "a\nb"}})
        self.assertNotIn("error", out)

    def test_newline_in_the_regex_field_is_refused(self):
        out = ask("Image|re", "'^a'", {"Image": "a\nb"})
        self.assertEqual(out.get("refusal"), "regex-newline")


class Base64OffsetNonAscii(unittest.TestCase):
    def test_non_ascii_elsewhere_is_answered(self):
        r = rule("CommandLine|base64offset|contains", "abc", "selection and not filter").replace(
            "  condition:", "  filter:\n    User: 'é'\n  condition:"
        )
        out = pe.respond({"rule": r, "event": {"CommandLine": "x", "User": "u"}})
        self.assertNotIn("error", out)

    def test_non_ascii_in_the_encoded_value_is_refused(self):
        out = ask("CommandLine|base64offset|contains", "'é'", {"CommandLine": "x"})
        self.assertEqual(out.get("refusal"), "base64offset-non-ascii")


class RefusalCodes(unittest.TestCase):
    """pySigma's exceptions get a code from their class and the fixed start
    of their message. Each case triggers the real exception."""

    def test_codes(self):
        cases = [
            ("unknown-modifier", "Image|nosuchmodifier", "x"),
            ("wide-non-ascii", "Image|wide|base64", "'é'"),
            ("wildcard-in-encoding", "Image|base64", "'a*'"),
            ("regex-python-rejects", "Image|re", "'(?<!a+)b'"),
        ]
        for code, key, value in cases:
            with self.subTest(code=code):
                self.assertEqual(ask(key, value, {"Image": "x"}).get("refusal"), code)

    def test_id_not_uuid(self):
        r = rule("Image", "x").replace(
            "id: 00000000-0000-4000-8000-000000000000", "id: not-a-uuid"
        )
        self.assertEqual(pe.respond({"rule": r, "event": {"Image": "x"}}).get("refusal"), "id-not-uuid")

    def test_value_cannot_forge_a_code(self):
        # The vendor phrase inside a value, on a rule that fails for an
        # unrelated reason, must not pick up that phrase's code.
        out = ask("Image|nosuchmodifier", "'Base64 encoding of strings with wildcards is not allowed'", {"Image": "x"})
        self.assertEqual(out.get("refusal"), "unknown-modifier")
        self.assertIsNone(pe.refusal_code(ValueError("Unknown modifier x")))


if __name__ == "__main__":
    unittest.main()
