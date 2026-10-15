"""The benchmark (docs/program-2026-09-30-front-door.md, slice D; owner
decisions 11 and 12): `canary bench` runs the layer-1 check over a corpus of
labelled malicious and harmless skills, and CI fails when the catch rate
falls below the committed baseline.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from canary import bench, cli

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = os.path.join(ROOT, "bin", "canary")
BENCH = os.path.join(ROOT, "bench")


def run_bench_cli():
    proc = subprocess.run([sys.executable, CANARY, "bench", "--json"], capture_output=True,
                          text=True, timeout=900, cwd=ROOT)
    return proc, (json.loads(proc.stdout) if proc.returncode == 0 else None)


class TheBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc, cls.result = run_bench_cli()

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

    def test_the_corpus_is_the_one_the_baseline_measured(self):
        # Deleting hard samples would raise the rate without a new baseline.
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr[-500:])
        with open(os.path.join(BENCH, "baseline.json")) as fh:
            baseline = json.load(fh)
        self.assertEqual((self.result["malicious"], self.result["benign"]),
                         (baseline["malicious"], baseline["benign"]))


def corpus(samples, folders=()):
    root = tempfile.mkdtemp(prefix="canary-bench-")
    for f in folders:
        os.makedirs(os.path.join(root, f))
    with open(os.path.join(root, "manifest.json"), "w") as fh:
        json.dump({"schema": "canary.bench/1", "samples": samples}, fh)
    return root


class TheCorpusStaysInsideBench(unittest.TestCase):
    def test_a_sample_path_must_name_one_sample_folder(self):
        for path in ("", ".", "benign", "benign/repo", "benign/repo/x/extra", "other/repo/x"):
            with self.subTest(path=path):
                root = corpus([{"id": "x", "label": "benign", "path": path}],
                              folders=["benign/repo/x/extra", "other/repo/x"])
                with self.assertRaises(bench.BenchError):
                    bench.load(root)

    def test_a_sample_folder_that_leads_outside_the_corpus_is_refused(self):
        outside = tempfile.mkdtemp(prefix="canary-outside-")
        root = corpus([{"id": "x", "label": "benign", "path": "benign/repo/x"}],
                      folders=["benign/repo"])
        os.symlink(outside, os.path.join(root, "benign", "repo", "x"))
        with self.assertRaises(bench.BenchError):
            bench.load(root)

    def test_only_layers_one_and_two_run(self):
        root = corpus([{"id": "x", "label": "benign", "path": "benign/repo/x"}],
                      folders=["benign/repo/x"])
        with self.assertRaises(bench.BenchError):
            bench.run(root, layer=0)

    def test_a_category_with_terminal_controls_is_refused_without_quoting_it(self):
        sample = {"id": "benign/repo/x", "label": "benign", "path": "benign/repo/x",
                  "category": "x\x1b[2J"}
        root = corpus([sample], folders=["benign/repo/x"])
        with self.assertRaises(bench.BenchError) as ctx:
            bench.load(root)
        self.assertNotIn("\x1b", str(ctx.exception))
        self.assertIn("category", str(ctx.exception))

    def test_a_sample_id_must_equal_its_path(self):
        root = corpus([{"id": "y", "label": "benign", "path": "benign/repo/x"}],
                      folders=["benign/repo/x"])
        with self.assertRaises(bench.BenchError):
            bench.load(root)


class TheLayerTwoSaysWhenTheAIReviewDidNotRun(unittest.TestCase):
    def fake_check(self, folder, backend="auto", model=None, timeout_s=None, status=None):
        if status is None:
            status = "failed" if folder.endswith("/b") else "ok"
        verdict = "UNSAFE" if "malicious" in folder else "LIKELY_SAFE"
        return {"verdict": verdict, "classifier": {"status": status}}

    def mixed_corpus(self):
        return corpus([{"id": "malicious/repo/a", "label": "malicious", "path": "malicious/repo/a"},
                       {"id": "malicious/repo/b", "label": "malicious", "path": "malicious/repo/b"},
                       {"id": "benign/repo/c", "label": "benign", "path": "benign/repo/c"}],
                      folders=["malicious/repo/a", "malicious/repo/b", "benign/repo/c"])

    def test_no_classifier_at_all_is_an_error(self):
        def unavailable(folder, **kwargs):
            return self.fake_check(folder, status="unavailable", **kwargs)

        with mock.patch.object(bench.classify, "check", side_effect=unavailable):
            with self.assertRaises(bench.BenchError) as ctx:
                bench.run(self.mixed_corpus(), layer=2)
        self.assertIn("no classifier is available for layer 2", str(ctx.exception))

    def test_samples_the_classifier_did_not_judge_are_named_and_said_so(self):
        with mock.patch.object(bench.classify, "check", side_effect=self.fake_check):
            result = bench.run(self.mixed_corpus(), layer=2)
        self.assertEqual(result.get("classifier_not_ok"), ["malicious/repo/b"])
        self.assertIn("AI review did not run on 1 samples; their verdicts come from "
                      "the pattern scan and its incomplete-check rule.",
                      bench.render_text(result).splitlines())

    def test_layer_one_has_no_classifier_gaps(self):
        result = bench.run(self.mixed_corpus(), layer=1)
        self.assertEqual(result.get("classifier_not_ok"), [])


class TheLayerTwoNeedsAClassifier(unittest.TestCase):
    def test_layer_two_with_no_backend_is_a_usage_error(self):
        with mock.patch.object(bench, "run", return_value={}) as run, \
                mock.patch("sys.stdout", new_callable=io.StringIO), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            code = cli.main(["bench", "--json", "--layer", "2", "--backend", "none"])
        self.assertEqual(code, 2)
        self.assertIn("usage:", err.getvalue())
        run.assert_not_called()


class TheCommandChecksItsOptions(unittest.TestCase):
    def run_bench(self, *args):
        return subprocess.run([sys.executable, CANARY, "bench", *args], capture_output=True,
                              text=True, timeout=120, cwd=ROOT)

    def test_a_bad_timeout_or_backend_is_a_usage_error(self):
        for args in (["--timeout", "banana"], ["--timeout", "0"], ["--backend", "bogus"]):
            with self.subTest(args=args):
                proc = self.run_bench("--json", *args)
                self.assertEqual(proc.returncode, 2, proc.stderr[-300:])
                self.assertIn("usage:", proc.stderr)

    def test_the_timeout_reaches_the_classifier(self):
        seen = {}

        def fake_run(root, layer=1, backend="auto", model=None, timeout_s=None):
            seen["timeout_s"] = timeout_s
            return {"layer": layer, "malicious": 0, "benign": 0, "caught_flagged": 0.0,
                    "caught_blocked": 0.0, "false_alarm_flagged": 0.0,
                    "false_alarm_blocked": 0.0, "by_category": {}, "misses": [],
                    "false_alarms_blocked": []}

        with mock.patch.object(bench, "run", fake_run), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            code = cli.main(["bench", "--json", "--layer", "2", "--timeout", "12"])
        self.assertEqual(code, 0)
        self.assertEqual(seen["timeout_s"], 12.0)


if __name__ == "__main__":
    unittest.main()
