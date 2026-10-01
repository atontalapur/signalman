"""Tests for fuzz_stats.py.

The nightly gate is this script's exit code. If it always exited 0, the
failure it was written to catch, a run that compared nothing, would be
invisible again. So every exit path is pinned here.
"""

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

import fuzz_stats


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fuzz_stats.main(args)
    return code, out.getvalue(), err.getvalue()


class FuzzStats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def worker(self, name, **counts):
        (self.dir / f"{name}.json").write_text(json.dumps(counts))

    def test_sums_workers(self):
        self.worker("1", compared=10, suppressed=2, skipped=5)
        self.worker("2", compared=5, rejected_by_both=3, oracle_timeout=1)
        code, out, _ = run([str(self.dir)])
        self.assertEqual(code, 0)
        self.assertIn("compared: 15", out)
        self.assertIn("reached both engines: 20", out)

    def test_below_min_compared_fails(self):
        self.worker("1", compared=99)
        code, _, err = run([str(self.dir), "--min-compared", "100"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", err)

    def test_at_min_compared_passes(self):
        self.worker("1", compared=100)
        self.assertEqual(run([str(self.dir), "--min-compared", "100"])[0], 0)

    def test_suppressed_ratio_over_limit_fails(self):
        self.worker("1", compared=60, suppressed=40)
        code, _, err = run([str(self.dir), "--max-suppressed-ratio", "0.3"])
        self.assertEqual(code, 1)
        self.assertIn("suppressed", err)

    def test_suppressed_ratio_under_limit_passes(self):
        self.worker("1", compared=80, suppressed=20)
        self.assertEqual(run([str(self.dir), "--max-suppressed-ratio", "0.3"])[0], 0)

    def test_timeout_ratio_over_limit_fails(self):
        self.worker("1", compared=90, oracle_timeout=10)
        code, _, err = run([str(self.dir), "--max-timeout-ratio", "0.01"])
        self.assertEqual(code, 1)
        self.assertIn("timeout", err)

    def test_nothing_reached_fails_a_ratio_check(self):
        self.worker("1", skipped=50)
        self.assertEqual(run([str(self.dir), "--max-suppressed-ratio", "0.3"])[0], 1)

    def test_empty_dir_fails(self):
        self.assertEqual(run([str(self.dir)])[0], 1)

    def test_bad_argument_fails(self):
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            fuzz_stats.main([str(self.dir), "--min-compared", "many"])
        self.assertEqual(cm.exception.code, 2)

    def test_unreadable_file_fails(self):
        self.worker("1", compared=10)
        (self.dir / "2.json").write_text('{"compared": 1')
        code, _, err = run([str(self.dir)])
        self.assertEqual(code, 1)
        self.assertIn("2.json", err)

    def test_ignores_temp_files(self):
        self.worker("1", compared=10)
        (self.dir / "2.json.tmp").write_text('{"compared": 1')
        code, out, _ = run([str(self.dir)])
        self.assertEqual(code, 0)
        self.assertIn("compared: 10", out)


if __name__ == "__main__":
    unittest.main()
