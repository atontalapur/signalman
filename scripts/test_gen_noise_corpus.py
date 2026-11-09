import json
import pathlib
import unittest

import gen_noise_corpus as g

SHAPES = {
    ("Microsoft-Windows-Sysmon/Operational", 1): {"Image", "CommandLine", "ParentImage", "User"},
    ("Microsoft-Windows-Sysmon/Operational", 3): {"Image", "DestinationIp", "DestinationPort"},
}


class Corpus(unittest.TestCase):
    def test_same_seed_same_corpus(self):
        self.assertEqual(list(g.events(500, seed=7)), list(g.events(500, seed=7)))

    def test_other_seed_other_corpus(self):
        self.assertNotEqual(list(g.events(500, seed=7)), list(g.events(500, seed=8)))

    def test_every_event_has_a_mapped_shape(self):
        for e in g.events(2000, seed=1):
            key = (e["channel"], e["event_id"])
            self.assertIn(key, SHAPES, e)
            self.assertTrue(SHAPES[key] <= e.keys(), e)

    def test_lines_are_json(self):
        for line in g.lines(50, seed=1):
            json.loads(line)

    def test_near_misses_are_present(self):
        # Benign uses of tools that attack rules also name: a rule that keys
        # on the binary alone, not on how it is used, shows up as noise.
        cmds = " ".join(e.get("CommandLine", "") for e in g.events(g.EVENTS, seed=1))
        for want in ["certutil -hashfile", "powershell.exe -File", "rundll32.exe shell32.dll,Control_RunDLL", "net user /domain"]:
            self.assertIn(want, cmds)

    def test_both_logsources_are_well_covered(self):
        # Each logsource the shipped rules use needs enough events for a
        # rate to mean something.
        n = {1: 0, 3: 0}
        for e in g.events(g.EVENTS, seed=1):
            n[e["event_id"]] += 1
        self.assertGreater(n[1], g.EVENTS // 2)
        self.assertGreater(n[3], g.EVENTS // 5)

    def test_public_addresses_are_documentation_ranges(self):
        for e in g.events(2000, seed=1):
            ip = e.get("DestinationIp", "10.")
            self.assertTrue(ip.startswith(("10.", "192.0.2.", "198.51.100.", "203.0.113.")), ip)

    def test_committed_corpus_is_the_default_output(self):
        committed = pathlib.Path(__file__).parent.parent / "testdata" / "noise" / "benign.ndjson"
        want = "".join(line + "\n" for line in g.lines(g.EVENTS, seed=1))
        self.assertEqual(committed.read_text(encoding="utf-8"), want,
                         "regenerate with scripts/gen_noise_corpus.py testdata/noise/benign.ndjson")


if __name__ == "__main__":
    unittest.main()
