import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from governance_workbench import Catalog
from governance_workbench.cli import main


class QualityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")

    def tearDown(self):
        self.temporary.cleanup()

    def csv(self, name: str, contents: str) -> Path:
        path = self.root / name
        path.write_text(contents, encoding="utf-8")
        return path

    def import_rows(self, dataset, name, header, rows):
        lines = [",".join(header), *rows]
        return self.catalog.import_csv(
            dataset, self.csv(name, "\n".join(lines) + "\n")
        )

    # --- rule configuration boundaries -----------------------------------

    def test_set_rules_returns_consecutive_revisions(self):
        rules = [{"id": "r1", "column": "id", "type": "required"}]
        self.assertEqual(self.catalog.set_rules("d", rules), 1)
        self.assertEqual(self.catalog.set_rules("d", rules), 2)
        self.assertEqual(self.catalog.set_rules("d", rules), 3)

    def test_failed_set_rules_does_not_consume_revision(self):
        with self.assertRaises(ValueError):
            self.catalog.set_rules("d", [])
        rules = [{"id": "r1", "column": "id", "type": "required"}]
        self.assertEqual(self.catalog.set_rules("d", rules), 1)

    def test_invalid_rule_configurations_rejected(self):
        cases = [
            [],
            [{"id": "r1", "column": "id", "type": "bogus"}],
            [{"column": "id", "type": "required"}],
            [{"id": "", "column": "id", "type": "required"}],
            [42],
            "not-an-array",
            [{"id": "r1", "column": "", "type": "required"}],
            [{"id": "r1", "column": 3, "type": "required"}],
            [{"id": "r1", "column": "id", "type": "required", "min": 1}],
            [{"id": "r1", "column": "id", "type": "required", "max": 1}],
            [{"id": "r1", "column": "id", "type": "unique", "min": 1}],
            [{"id": "r1", "column": "id", "type": "range"}],
            [{"id": "r1", "column": "id", "type": "range", "min": True}],
            [{"id": "r1", "column": "id", "type": "range", "min": "1"}],
            [{"id": "r1", "column": "id", "type": "range", "min": float("nan")}],
            [{"id": "r1", "column": "id", "type": "range", "min": float("inf")}],
            [{"id": "r1", "column": "id", "type": "range", "min": 5, "max": 2}],
            [{"id": "r1", "column": "id", "type": "required", "extra": 1}],
            [
                {"id": "r1", "column": "id", "type": "required"},
                {"id": "r1", "column": "name", "type": "unique"},
            ],
        ]
        for index, bad in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    self.catalog.set_rules(f"d{index}", bad)

    def test_range_bounds_accepted(self):
        variants = [
            [{"id": "r", "column": "a", "type": "range", "min": 0}],
            [{"id": "r", "column": "a", "type": "range", "max": 10}],
            [{"id": "r", "column": "a", "type": "range", "min": 0, "max": 10}],
            [{"id": "r", "column": "a", "type": "range", "min": 1.5, "max": 2.5}],
            [{"id": "r", "column": "a", "type": "range", "min": 0, "max": 0}],
        ]
        for index, rules in enumerate(variants):
            with self.subTest(case=index):
                self.assertEqual(self.catalog.set_rules(f"d{index}", rules), 1)

    # --- validation semantics --------------------------------------------

    def test_validate_required_unique_range(self):
        self.import_rows(
            "people",
            "p.csv",
            ["id", "name", "score"],
            ["1,Ada,10", "2,,x", "3,Bob,5", "4,Ada,", "5, ,0", "6,,7"],
        )
        rules = [
            {"id": "req-name", "column": "name", "type": "required"},
            {"id": "uniq-name", "column": "name", "type": "unique"},
            {"id": "rng-score", "column": "score", "type": "range", "min": 0, "max": 10},
        ]
        self.assertEqual(self.catalog.set_rules("people", rules), 1)
        report = self.catalog.validate("people", 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["dataset"], "people")
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["rule_revision"], 1)
        self.assertEqual(report["row_count"], 6)
        by_id = {item["id"]: item for item in report["rules"]}
        self.assertEqual(by_id["req-name"]["violations"], [2, 6])
        self.assertEqual(by_id["req-name"]["count"], 2)
        self.assertEqual(by_id["uniq-name"]["violations"], [1, 4])
        self.assertEqual(by_id["rng-score"]["violations"], [2])

    def test_line_numbers_are_record_based_with_quoted_newlines(self):
        self.catalog.import_csv(
            "q", self.csv("q.csv", 'id,name\n1,Ada\n2,"Bob\nJr"\n3,\n')
        )
        self.catalog.set_rules(
            "q", [{"id": "r", "column": "name", "type": "required"}]
        )
        report = self.catalog.validate("q", 1)
        self.assertEqual(report["row_count"], 3)
        self.assertEqual(report["rules"][0]["violations"], [3])

    def test_range_bounds_inclusive_and_nonfinite(self):
        self.import_rows(
            "r", "r.csv", ["v"], ["-1", "0", "10", "11", "", "x", "nan", "inf"]
        )
        self.catalog.set_rules(
            "r", [{"id": "rng", "column": "v", "type": "range", "min": 0, "max": 10}]
        )
        report = self.catalog.validate("r", 1)
        self.assertEqual(report["rules"][0]["violations"], [1, 4, 6, 7, 8])

    def test_unique_uses_raw_strings_and_skips_empty(self):
        self.import_rows("u", "u.csv", ["name"], ["a", "a", " ", " ", ""])
        self.catalog.set_rules(
            "u", [{"id": "u", "column": "name", "type": "unique"}]
        )
        report = self.catalog.validate("u", 1)
        self.assertEqual(report["rules"][0]["violations"], [1, 2, 3, 4])

    def test_rules_follow_config_order_and_no_truncation(self):
        self.import_rows("o", "o.csv", ["a", "b"], ["1,", ",2"])
        rules = [
            {"id": "second", "column": "b", "type": "required"},
            {"id": "first", "column": "a", "type": "required"},
        ]
        self.catalog.set_rules("o", rules)
        report = self.catalog.validate("o", 1)
        self.assertEqual([item["id"] for item in report["rules"]], ["second", "first"])
        self.assertEqual(report["rules"][0]["violations"], [1])
        self.assertEqual(report["rules"][1]["violations"], [2])

    def test_violations_not_truncated(self):
        self.import_rows("t", "t.csv", ["v"], [""] * 200)
        self.catalog.set_rules(
            "t", [{"id": "r", "column": "v", "type": "required"}]
        )
        report = self.catalog.validate("t", 1)
        self.assertEqual(len(report["rules"][0]["violations"]), 200)
        self.assertEqual(report["rules"][0]["count"], 200)

    def test_column_names_matched_as_is(self):
        self.import_rows("c", "c.csv", ["Name"], ["Ada"])
        self.catalog.set_rules(
            "c", [{"id": "r", "column": "Name", "type": "required"}]
        )
        self.assertTrue(self.catalog.validate("c", 1)["passed"])
        self.catalog.set_rules(
            "c", [{"id": "r", "column": "name", "type": "required"}]
        )
        with self.assertRaises(ValueError):
            self.catalog.validate("c", 1)

    def test_validate_does_not_modify_data_or_add_versions(self):
        record = self.import_rows("z", "z.csv", ["id"], ["1"])
        before = (self.catalog.workspace / record.blob).read_bytes()
        self.catalog.set_rules(
            "z", [{"id": "r", "column": "id", "type": "required"}]
        )
        self.catalog.validate("z", 1)
        self.assertEqual((self.catalog.workspace / record.blob).read_bytes(), before)
        self.assertEqual(len(self.catalog.list_datasets()["z"]), 1)

    # --- error cases ------------------------------------------------------

    def test_validate_without_rules_rejected(self):
        self.import_rows("n", "n.csv", ["id"], ["1"])
        with self.assertRaises(ValueError):
            self.catalog.validate("n", 1)

    def test_unknown_dataset_version_rejected(self):
        with self.assertRaises(ValueError):
            self.catalog.validate("nope", 1)

    def test_unknown_rule_revision_rejected(self):
        self.import_rows("ur", "ur.csv", ["id"], ["1"])
        self.catalog.set_rules(
            "ur", [{"id": "r", "column": "id", "type": "required"}]
        )
        with self.assertRaises(ValueError):
            self.catalog.validate("ur", 1, revision=5)

    def test_missing_stored_data_rejected(self):
        record = self.import_rows("md", "md.csv", ["id"], ["1"])
        self.catalog.set_rules(
            "md", [{"id": "r", "column": "id", "type": "required"}]
        )
        (self.catalog.workspace / record.blob).unlink()
        with self.assertRaises(ValueError):
            self.catalog.validate("md", 1)

    def test_hash_mismatch_rejected_and_retry_succeeds(self):
        record = self.import_rows("hm", "hm.csv", ["id"], ["1"])
        self.catalog.set_rules(
            "hm", [{"id": "r", "column": "id", "type": "required"}]
        )
        blob = self.catalog.workspace / record.blob
        original = blob.read_bytes()
        blob.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.catalog.validate("hm", 1)
        blob.write_bytes(original)
        self.assertTrue(self.catalog.validate("hm", 1)["passed"])

    def test_write_failure_leaves_state_intact_and_revision_unconsumed(self):
        self.import_rows("wf", "wf.csv", ["id"], ["1"])
        rules = [{"id": "r", "column": "id", "type": "required"}]
        with patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(ValueError):
                self.catalog.set_rules("wf", rules)
        self.assertEqual(self.catalog.set_rules("wf", rules), 1)
        json.loads((self.catalog.workspace / ".dgw" / "catalog.json").read_text())

    # --- persistence and history -----------------------------------------

    def test_report_persists_history_sorted_and_repeated_returns_same(self):
        self.import_rows("h", "h.csv", ["id"], ["1", ""])
        self.catalog.set_rules(
            "h", [{"id": "r1", "column": "id", "type": "required"}]
        )
        first = self.catalog.validate("h", 1)
        self.catalog.set_rules(
            "h", [{"id": "r2", "column": "id", "type": "unique"}]
        )
        second = self.catalog.validate("h", 1)
        self.assertEqual(first["rule_revision"], 1)
        self.assertEqual(second["rule_revision"], 2)

        restarted = Catalog(self.root / "workspace")
        history = restarted.validation_history("h", 1)
        self.assertEqual([item["rule_revision"] for item in history], [1, 2])
        self.assertEqual(history[0], first)
        self.assertEqual(history[1], second)
        self.assertEqual(restarted.validate("h", 1), second)
        self.assertEqual(restarted.validate("h", 1, revision=1), first)

    def test_history_empty_for_unknown_dataset_or_version(self):
        self.assertEqual(self.catalog.validation_history("nope", 1), [])
        self.import_rows("eh", "eh.csv", ["id"], ["1"])
        self.assertEqual(self.catalog.validation_history("eh", 99), [])

    def test_repeated_validate_verifies_hash_each_time(self):
        record = self.import_rows("rh", "rh.csv", ["id"], ["1"])
        self.catalog.set_rules(
            "rh", [{"id": "r", "column": "id", "type": "required"}]
        )
        self.catalog.validate("rh", 1)
        blob = self.catalog.workspace / record.blob
        original = blob.read_bytes()
        blob.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.catalog.validate("rh", 1)
        blob.write_bytes(original)
        self.assertTrue(self.catalog.validate("rh", 1)["passed"])

    # --- CLI --------------------------------------------------------------

    def run_cli(self, *args):
        return main(["--workspace", str(self.root / "workspace"), *args])

    def test_cli_rules_validate_validations_flow(self):
        self.import_rows("cl", "cl.csv", ["id"], ["1", ""])
        rules_path = self.root / "rules.json"
        rules_path.write_text(
            json.dumps([{"id": "req", "column": "id", "type": "required"}])
        )

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("rules", "cl", str(rules_path))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["revision"], 1)
        self.assertEqual(err.getvalue(), "")

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("validate", "cl", "1")
        self.assertEqual(code, 1)
        self.assertEqual(err.getvalue(), "")
        self.assertFalse(json.loads(out.getvalue())["passed"])

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("validations", "cl", "1")
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out.getvalue())), 1)
        self.assertEqual(err.getvalue(), "")

    def test_cli_validate_pass_exit_zero_and_revision_flag(self):
        self.import_rows("cp", "cp.csv", ["id"], ["1"])
        rules_path = self.root / "rules.json"
        rules_path.write_text(
            json.dumps([{"id": "req", "column": "id", "type": "required"}])
        )
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("rules", "cp", str(rules_path))
        self.assertEqual(code, 0)
        self.catalog.set_rules(
            "cp", [{"id": "u", "column": "id", "type": "unique"}]
        )

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("validate", "cp", "1", "--revision", "1")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out.getvalue())["passed"])
        self.assertEqual(err.getvalue(), "")

    def test_cli_error_exit_two_with_empty_stdout(self):
        self.import_rows("ce", "ce.csv", ["id"], ["1"])
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("validate", "ce", "1")
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        parsed = json.loads(err.getvalue())
        self.assertEqual(set(parsed), {"error"})
        self.assertTrue(parsed["error"])

    def test_cli_invalid_rules_file_exit_two(self):
        self.import_rows("cr", "cr.csv", ["id"], ["1"])
        bad = self.root / "bad.json"
        bad.write_text("{not json")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("rules", "cr", str(bad))
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(set(json.loads(err.getvalue())), {"error"})

    def test_cli_hash_mismatch_retry_after_restore(self):
        record = self.import_rows("ch", "ch.csv", ["id"], ["1"])
        rules_path = self.root / "rules.json"
        rules_path.write_text(
            json.dumps([{"id": "req", "column": "id", "type": "required"}])
        )
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("rules", "ch", str(rules_path))
        self.assertEqual(code, 0)
        blob = self.catalog.workspace / record.blob
        original = blob.read_bytes()
        blob.write_bytes(b"tampered")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("validate", "ch", "1")
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(set(json.loads(err.getvalue())), {"error"})
        blob.write_bytes(original)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.run_cli("validate", "ch", "1")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out.getvalue())["passed"])


if __name__ == "__main__":
    unittest.main()
