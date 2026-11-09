import json
import unittest

import gen_noise_corpus as g

SHAPES = {
    ("Microsoft-Windows-Sysmon/Operational", 1): {"Image", "CommandLine", "ParentImage", "User"},
    ("Microsoft-Windows-Sysmon/Operational", 3): {"Image", "DestinationIp", "DestinationPort"},
    ("Security", 4688): {"NewProcessName", "CommandLine", "ParentProcessName", "SubjectUserName"},
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
        cmds = " ".join(e.get("CommandLine", "") for e in g.events(20000, seed=1))
        for want in ["certutil -hashfile", "powershell.exe -File", "rundll32.exe shell32.dll,Control_RunDLL", "net user /domain"]:
            self.assertIn(want, cmds)


if __name__ == "__main__":
    unittest.main()
