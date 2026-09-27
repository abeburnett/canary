"""The canary.evidence/1 identities, checked against the shared vectors
(tests/vectors/evidence-v1.json) that the hosted consumer also tests."""

import hashlib
import json
import os
import unittest

from canary import evidence

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "evidence-v1.json")
with open(VECTORS, encoding="utf-8") as fh:
    V = json.load(fh)


class ComponentIdentity(unittest.TestCase):
    def test_vectors(self):
        for case in V["component_id"]["valid"]:
            with self.subTest(case["label"]):
                self.assertEqual(hashlib.sha256(case["canonical_json"].encode("utf-8")).hexdigest(),
                                 case["id"])
                self.assertEqual(evidence.component_id(case["path"], case["executable"],
                                                       case["content_sha256"]), case["id"])

    def test_same_bytes_at_different_paths_are_different_components(self):
        ids = {c["label"]: c["id"] for c in V["component_id"]["valid"]}
        self.assertNotEqual(ids["same bytes, root"], ids["same bytes, other path"])
        self.assertNotEqual(ids["same bytes, root"], ids["same bytes, executable"])
        self.assertNotEqual(ids["case preserved"], ids["case preserved, upper"])

    def test_invalid_inputs_are_rejected(self):
        for case in V["component_id"]["invalid_must_be_rejected"]:
            with self.subTest(case["label"]):
                with self.assertRaises(ValueError):
                    evidence.component_id(case["path"], case["executable"], case["content_sha256"])


class RulesetIdentity(unittest.TestCase):
    def test_vector(self):
        r = V["ruleset"]
        files = {k: v.encode("utf-8") for k, v in r["files_utf8"].items()}
        self.assertEqual(hashlib.sha256(r["canonical_text"].encode("utf-8")).hexdigest(),
                         r["ruleset_sha256"])
        self.assertEqual(evidence.ruleset_sha256_of(files), r["ruleset_sha256"])

    def test_any_policy_byte_changes_the_identity(self):
        base = evidence.ruleset_sha256()
        self.assertEqual(base, evidence.ruleset_sha256())
        for path in evidence.RULESET_FILES:
            with self.subTest(path):
                files = {}
                for p in evidence.RULESET_FILES:
                    with open(os.path.join(evidence.ROOT, p), "rb") as fh:
                        files[p] = fh.read()
                files[path] += b" "
                self.assertNotEqual(evidence.ruleset_sha256_of(files), base)


if __name__ == "__main__":
    unittest.main()
