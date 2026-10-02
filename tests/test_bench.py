"""The benchmark (docs/program-2026-09-30-front-door.md, slice D; owner
decisions 11 and 12): `canary bench` runs the layer-1 check over a corpus of
labelled malicious and harmless skills, and CI fails when the catch rate
falls below the committed baseline.
"""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = os.path.join(ROOT, "bin", "canary")
BENCH = os.path.join(ROOT, "bench")


def bench():
    proc = subprocess.run([sys.executable, CANARY, "bench", "--json"], capture_output=True,
                          text=True, timeout=900, cwd=ROOT)
    return proc, (json.loads(proc.stdout) if proc.returncode == 0 else None)


class TheBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc, cls.result = bench()

    def test_it_runs_over_at_least_fifty_of_each(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr[-500:])
        self.assertGreaterEqual(self.result["malicious"], 50)
        self.assertGreaterEqual(self.result["benign"], 50)

    def test_it_prints_both_readings_of_both_rates(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr[-500:])
        for key in ("caught_flagged", "caught_blocked", "false_alarm_flagged",
                    "false_alarm_blocked"):
            self.assertTrue(0.0 <= self.result[key] <= 1.0, key)
        self.assertGreaterEqual(self.result["caught_flagged"], self.result["caught_blocked"])

    def test_the_catch_rate_does_not_fall_below_the_baseline(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr[-500:])
        with open(os.path.join(BENCH, "baseline.json")) as fh:
            baseline = json.load(fh)
        self.assertGreaterEqual(self.result["caught_flagged"], baseline["caught_flagged"],
                                f"missed: {self.result['misses']}")


if __name__ == "__main__":
    unittest.main()
