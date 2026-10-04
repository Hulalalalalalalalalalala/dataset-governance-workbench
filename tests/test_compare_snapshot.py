import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from governance_workbench.catalog import Catalog


class KeyedCompareSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")
        left = self.root / "left.csv"
        right = self.root / "right.csv"
        left.write_text("id,v\n1,a\n", encoding="utf-8")
        right.write_text("id,v\n1,b\n", encoding="utf-8")
        self.catalog.import_csv("d", left)
        self.catalog.import_csv("d", right)
        self.left_blob = self.catalog.workspace / self.catalog.get("d", 1)["blob"]
        self.right_blob = self.catalog.workspace / self.catalog.get("d", 2)["blob"]

    def tearDown(self):
        self.temporary.cleanup()

    def patch_right_snapshot(self, mutate):
        real_snapshot = self.catalog._snapshot_blob

        def patched(self_cat, state, dataset, version, expected_hash=None):
            result = real_snapshot(state, dataset, version, expected_hash)
            if version == 2:
                mutate()
            return result

        return mock.patch.object(Catalog, "_snapshot_blob", patched)

    def test_rewrite_after_snapshot_does_not_leak_into_diff(self):
        # right side held value b; after its snapshot the file becomes c and
        # gains key 2 — the diff must still report only a -> b
        def rewrite():
            self.right_blob.write_text("id,v\n1,c\n2,d\n", encoding="utf-8")

        with self.patch_right_snapshot(rewrite):
            result = self.catalog.compare("d", 1, 2, keys=["id"])
        diff = result["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(
            diff["modified"],
            [{"key": ["1"], "leftRow": 1, "rightRow": 1,
              "changes": {"v": {"from": "a", "to": "b"}}}],
        )
        self.assertEqual(diff["unchangedCount"], 0)
        # the next invocation observes the new bytes and fails the hash check
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["id"])

    def test_delete_after_snapshot_still_completes(self):
        with self.patch_right_snapshot(lambda: self.right_blob.unlink()):
            diff = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual(diff["modified"][0]["changes"]["v"], {"from": "a", "to": "b"})
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["id"])

    def test_replace_with_more_rows_and_reordered(self):
        def rewrite():
            self.right_blob.write_text("id,v\n2,z\n1,c\n", encoding="utf-8")

        with self.patch_right_snapshot(rewrite):
            diff = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(
            diff["modified"][0]["changes"]["v"], {"from": "a", "to": "b"}
        )
        self.assertEqual(diff["modified"][0]["rightRow"], 1)

    def test_same_version_compare_against_mid_comparison_change(self):
        real_snapshot = self.catalog._snapshot_blob
        calls = {"n": 0}

        def patched(self_cat, state, dataset, version, expected_hash=None):
            result = real_snapshot(state, dataset, version, expected_hash)
            calls["n"] += 1
            if calls["n"] == 1:
                # tamper with the shared blob after the first (only) snapshot
                self.left_blob.write_text("id,v\n1,x\n2,y\n", encoding="utf-8")
            return result

        with mock.patch.object(Catalog, "_snapshot_blob", patched):
            diff = self.catalog.compare("d", 1, 1, keys=["id"])["rowDiff"]
        self.assertEqual(diff, {"added": [], "removed": [], "modified": [],
                               "unchangedCount": 1})
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 1, keys=["id"])

    def test_shared_blob_both_sides_see_same_content(self):
        # importing identical content makes versions 1 and 3 share one blob
        same = self.root / "same.csv"
        same.write_text("id,v\n1,a\n", encoding="utf-8")
        self.catalog.import_csv("d", same)
        r1, r3 = self.catalog.get("d", 1), self.catalog.get("d", 3)
        self.assertEqual(r1["blob"], r3["blob"])
        real_snapshot = self.catalog._snapshot_blob
        calls = {"n": 0}

        def patched(self_cat, state, dataset, version, expected_hash=None):
            result = real_snapshot(state, dataset, version, expected_hash)
            calls["n"] += 1
            if calls["n"] == 1:
                self.left_blob.write_text("id,v\n1,zzz\n9,new\n", encoding="utf-8")
            return result

        with mock.patch.object(Catalog, "_snapshot_blob", patched):
            diff = self.catalog.compare("d", 1, 3, keys=["id"])["rowDiff"]
        self.assertEqual(diff, {"added": [], "removed": [], "modified": [],
                               "unchangedCount": 1})

    def test_missing_side_before_snapshot_fails_namingly(self):
        self.right_blob.unlink()
        with self.assertRaises(ValueError) as caught:
            self.catalog.compare("d", 1, 2, keys=["id"])
        self.assertIn("d@2", str(caught.exception))

    def test_hash_mismatch_before_snapshot_fails_namingly(self):
        self.left_blob.write_text("id,v\n1,z\n", encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            self.catalog.compare("d", 1, 2, keys=["id"])
        self.assertIn("d@1", str(caught.exception))

    def test_failure_returns_no_partial_diff_and_state_untouched(self):
        self.left_blob.write_text("id,v\n1,z\n", encoding="utf-8")
        state_before = self.catalog.state_path.read_bytes()
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["id"])
        self.assertEqual(self.catalog.state_path.read_bytes(), state_before)

    def test_same_version_success_rechecks_on_next_call_after_tamper(self):
        self.assertEqual(
            self.catalog.compare("d", 1, 1, keys=["id"])["rowDiff"]["unchangedCount"], 1
        )
        self.left_blob.write_text("id,v\n1,a\n2,a\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 1, keys=["id"])

    def test_blob_is_opened_once_per_side_no_reread_race(self):
        # Deterministically reproduces the original defect: the hash pass and
        # the parse used to open the file separately. Serve the verified
        # bytes on the first open of the right blob and tampered bytes on any
        # second open; the comparison must never take that second open.
        tampered = b"id,v\n1,c\n2,d\n"
        real_open = Path.open
        opens = {"right": 0}

        def swapping_open(self_path, *args, **kwargs):
            if self_path.resolve() == self.right_blob.resolve():
                opens["right"] += 1
                if opens["right"] > 1:
                    return io.BytesIO(tampered)
            return real_open(self_path, *args, **kwargs)

        with mock.patch.object(Path, "open", swapping_open):
            diff = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual(opens["right"], 1)
        self.assertEqual(diff["added"], [])
        self.assertEqual(
            diff["modified"][0]["changes"]["v"], {"from": "a", "to": "b"}
        )

    def test_no_keys_path_unchanged_and_untouched_by_mutation(self):
        # without keys the structural compare uses catalog records only;
        # make sure it still behaves as before
        self.right_blob.unlink()
        result = self.catalog.compare("d", 1, 2)
        self.assertNotIn("rowDiff", result)
        self.assertTrue(result["contentChanged"])
        self.assertEqual(json.loads(json.dumps(result))["dataset"], "d")


if __name__ == "__main__":
    unittest.main(verbosity=2)
