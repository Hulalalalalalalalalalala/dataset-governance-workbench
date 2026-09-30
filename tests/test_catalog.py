import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from governance_workbench import Catalog

REPO_ROOT = Path(__file__).resolve().parents[1]


class CatalogTest(unittest.TestCase):
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

    def test_import_infers_schema_and_preserves_blob(self):
        source = self.csv("input.csv", "id,active,score\n1,true,2.5\n2,false,3\n")
        record = self.catalog.import_csv("metrics", source)
        source.write_text("changed", encoding="utf-8")
        self.assertEqual(record.schema, {"id": "integer", "active": "boolean", "score": "number"})
        self.assertEqual(record.row_count, 2)
        self.assertNotEqual((self.catalog.workspace / record.blob).read_text(), "changed")

    def test_compare_reports_schema_and_row_changes(self):
        self.catalog.import_csv("people", self.csv("one.csv", "id,name\n1,Ada\n"))
        self.catalog.import_csv("people", self.csv("two.csv", "id,name,region\n1,Ada,EU\n2,Lin,APAC\n"))
        result = self.catalog.compare("people", 1, 2)
        self.assertEqual(result["addedFields"], ["region"])
        self.assertEqual(result["rowDelta"], 1)
        self.assertTrue(result["contentChanged"])

    def test_export_manifest_matches_stored_content(self):
        record = self.catalog.import_csv("events", self.csv("events.csv", "id\n1\n"))
        destination = self.root / "export"
        manifest = self.catalog.export("events", 1, destination)
        on_disk = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk, manifest)
        self.assertEqual(manifest["record"]["content_sha256"], record.content_sha256)


class RulesConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")
        source = self.root / "things.csv"
        source.write_text("id,v\n1,5\n", encoding="utf-8")
        self.catalog.import_csv("things", source)

    def tearDown(self):
        self.temporary.cleanup()

    def test_valid_rule_shapes(self):
        result = self.catalog.set_rules(
            "things",
            [
                {"id": "r1", "column": "id", "type": "required"},
                {"id": "r2", "column": "id", "type": "unique"},
                {"id": "r3", "column": "v", "type": "range", "min": 0},
                {"id": "r4", "column": "v", "type": "range", "max": 10},
                {"id": "r5", "column": "v", "type": "range", "min": -1.5, "max": 10.5},
            ],
        )
        self.assertEqual(result["revision"], 1)
        self.assertEqual([rule["id"] for rule in result["rules"]], ["r1", "r2", "r3", "r4", "r5"])

    def test_revisions_are_contiguous_and_immutable(self):
        first = self.catalog.set_rules("things", [{"id": "a", "column": "id", "type": "required"}])
        second = self.catalog.set_rules("things", [{"id": "b", "column": "v", "type": "unique"}])
        self.assertEqual((first["revision"], second["revision"]), (1, 2))
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["rules"]["things"][0]["rules"][0]["id"], "a")
        self.assertEqual(state["rules"]["things"][1]["rules"][0]["id"], "b")

    def test_unknown_dataset_rejected(self):
        with self.assertRaises(ValueError):
            self.catalog.set_rules("missing", [{"id": "a", "column": "id", "type": "required"}])

    def test_invalid_configurations(self):
        def reject(rules):
            with self.assertRaises(ValueError):
                self.catalog.set_rules("things", rules)

        reject([])
        reject("not-a-list")
        reject([None])
        reject(["not-an-object"])
        reject([{"column": "id", "type": "required"}])  # missing id
        reject([{"id": "", "column": "id", "type": "required"}])  # empty id
        reject([{"id": 5, "column": "id", "type": "required"}])  # non-string id
        reject([{"id": "a"}])  # missing column and type
        reject([{"id": "a", "column": "", "type": "required"}])  # empty column
        reject([{"id": "a", "column": 7, "type": "required"}])
        reject([{"id": "a", "column": "id", "type": "mystery"}])  # unknown type
        reject(
            [
                {"id": "a", "column": "id", "type": "required"},
                {"id": "a", "column": "v", "type": "unique"},  # duplicate id
            ]
        )
        reject([{"id": "a", "column": "id", "type": "required", "extra": 1}])
        reject([{"id": "a", "column": "v", "type": "range"}])  # no bounds
        reject([{"id": "a", "column": "v", "type": "range", "min": 10, "max": 1}])
        reject([{"id": "a", "column": "v", "type": "range", "min": True}])
        reject([{"id": "a", "column": "v", "type": "range", "max": False}])
        reject([{"id": "a", "column": "v", "type": "range", "min": "1"}])
        reject([{"id": "a", "column": "v", "type": "range", "min": float("nan")}])
        reject([{"id": "a", "column": "v", "type": "range", "max": float("inf")}])
        reject([{"id": "a", "column": "id", "type": "required", "min": 1}])
        reject([{"id": "a", "column": "id", "type": "unique", "max": 1}])

    def test_failed_write_does_not_consume_revision_and_retry_succeeds(self):
        with mock.patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.catalog.set_rules("things", [{"id": "a", "column": "id", "type": "required"}])
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state.get("rules", {}).get("things", []), [])
        result = self.catalog.set_rules("things", [{"id": "a", "column": "id", "type": "required"}])
        self.assertEqual(result["revision"], 1)

    def test_works_with_legacy_workspace_state(self):
        state_path = self.catalog.state_path
        state = json.loads(state_path.read_text(encoding="utf-8"))
        del state["rules"]
        del state["validations"]
        state_path.write_text(json.dumps(state), encoding="utf-8")
        result = self.catalog.set_rules("things", [{"id": "a", "column": "id", "type": "required"}])
        self.assertEqual(result["revision"], 1)
        self.assertEqual(self.catalog.validate("things", 1)["passed"], True)


class ValidationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")

    def tearDown(self):
        self.temporary.cleanup()

    def csv_file(self, contents: str, name: str = "data.csv") -> Path:
        path = self.root / name
        path.write_text(contents, encoding="utf-8")
        return path

    def test_required_unique_range_semantics(self):
        csv_contents = (
            "id,v,label\n"
            "1,0,a\n"          # row 1: in range, unique values so far
            "2,10,a\n"         # row 2: boundary max included; duplicate label
            "3,-1,b\n"         # row 3: below min
            "4,11, c\n"        # row 4: above max
            "5,,\n"            # row 5: missing v skipped by range, missing label
            "6,abc,d\n"        # row 6: non-numeric
            "7,true,e\n"       # row 7: boolean-looking cell is not a number
            "8,inf,f\n"        # row 8: non-finite
            "9,nan,g\n"        # row 9: non-finite
            "10, 5,h\n"        # row 10: whitespace is not stripped
            "11,5.0,i\n"       # row 11: finite numeric passes
            "12,1e1,j\n"       # row 12: 10.0 passes (max inclusive)
            " ,0,k\n"          # row 13: whitespace id is present and distinct
        )
        self.catalog.import_csv("things", self.csv_file(csv_contents))
        self.catalog.set_rules(
            "things",
            [
                {"id": "id-required", "column": "id", "type": "required"},
                {"id": "label-unique", "column": "label", "type": "unique"},
                {"id": "v-range", "column": "v", "type": "range", "min": 0, "max": 10},
            ],
        )
        report = self.catalog.validate("things", 1)
        by_id = {item["id"]: item for item in report["results"]}
        self.assertEqual([item["id"] for item in report["results"]],
                         ["id-required", "label-unique", "v-range"])
        self.assertEqual(by_id["id-required"]["violations"], [])
        self.assertEqual(by_id["label-unique"]["violations"], [1, 2])
        self.assertEqual(by_id["v-range"]["violations"], [3, 4, 6, 7, 8, 9, 10])
        self.assertEqual(by_id["v-range"]["violationCount"], 7)
        self.assertFalse(report["passed"])
        self.assertEqual(report["rowCount"], 13)
        self.assertTrue(all(
            item["violations"] == sorted(item["violations"])
            for item in report["results"]
        ))

    def test_quoted_newline_does_not_advance_row_number(self):
        csv_contents = "id,name\n1,\"line one\nline two\"\n2,\n"
        self.catalog.import_csv("notes", self.csv_file(csv_contents))
        self.catalog.set_rules(
            "notes",
            [
                {"id": "name-required", "column": "name", "type": "required"},
                {"id": "name-unique", "column": "name", "type": "unique"},
            ],
        )
        report = self.catalog.validate("notes", 1)
        by_id = {item["id"]: item for item in report["results"]}
        self.assertEqual(report["rowCount"], 2)
        self.assertEqual(by_id["name-required"]["violations"], [2])
        self.assertEqual(by_id["name-unique"]["violations"], [])

    def test_empty_string_missing_but_whitespace_present(self):
        self.catalog.import_csv("ws", self.csv_file("id,v\n1,\n2, \n3,  \n"))
        self.catalog.set_rules("ws", [{"id": "req", "column": "v", "type": "required"}])
        report = self.catalog.validate("ws", 1)
        self.assertEqual(report["results"][0]["violations"], [1])
        self.assertEqual(report["rowCount"], 3)

    def test_unique_reports_whole_duplicate_group_raw_strings(self):
        self.catalog.import_csv("u", self.csv_file("v\nx\nx\ny\nx\n z\nz\n"))
        self.catalog.set_rules("u", [{"id": "u1", "column": "v", "type": "unique"}])
        report = self.catalog.validate("u", 1)
        # rows 1,2,4 share "x"; " z" and "z" are distinct raw strings
        self.assertEqual(report["results"][0]["violations"], [1, 2, 4])

    def test_range_min_only_and_max_only_endpoints(self):
        self.catalog.import_csv("r", self.csv_file("v\n0\n5\n10\n"))
        self.catalog.set_rules(
            "r",
            [
                {"id": "lo", "column": "v", "type": "range", "min": 0},
                {"id": "hi", "column": "v", "type": "range", "max": 10},
            ],
        )
        report = self.catalog.validate("r", 1)
        self.assertTrue(report["passed"])

    def test_columns_match_verbatim(self):
        self.catalog.import_csv("c", self.csv_file(" id\n1\n"))
        self.catalog.set_rules("c", [{"id": "r", "column": "id", "type": "required"}])
        with self.assertRaises(ValueError):
            self.catalog.validate("c", 1)

    def test_missing_data_version_revision_and_rules(self):
        self.catalog.import_csv("d", self.csv_file("v\n1\n"))
        with self.assertRaises(ValueError):
            self.catalog.validate("d", 1)  # no rules
        with self.assertRaises(ValueError):
            self.catalog.validate("missing", 1)
        with self.assertRaises(ValueError):
            self.catalog.validate("d", 2)
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "required"}])
        with self.assertRaises(ValueError):
            self.catalog.validate("d", 1, revision=2)
        with self.assertRaises(ValueError):
            self.catalog.validate("d", 1, revision=0)

    def test_explicit_revision_uses_historical_rules(self):
        self.catalog.import_csv("d", self.csv_file("id,v\n1,1\n2,\n"))
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "required"}])
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "unique"}])
        report = self.catalog.validate("d", 1, revision=1)
        self.assertEqual(report["rulesRevision"], 1)
        self.assertEqual(report["results"][0]["violations"], [2])
        latest = self.catalog.validate("d", 1)
        self.assertEqual(latest["rulesRevision"], 2)
        self.assertTrue(latest["passed"])

    def test_dedup_returns_identical_report_but_rechecks_hash(self):
        self.catalog.import_csv("d", self.csv_file("v\n1\n2\n"))
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "range", "min": 0, "max": 9}])
        first = self.catalog.validate("d", 1)
        second = self.catalog.validate("d", 1)
        self.assertEqual(first, second)
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        entries = state["validations"]["d"]["1"]
        self.assertEqual(set(entries), {"1"})
        # tamper with the stored blob: repeated validation must notice
        record = self.catalog.get("d", 1)
        (self.catalog.workspace / record["blob"]).write_text("v\n999\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.catalog.validate("d", 1)

    def test_missing_blob_raises(self):
        self.catalog.import_csv("d", self.csv_file("v\n1\n"))
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "required"}])
        record = self.catalog.get("d", 1)
        (self.catalog.workspace / record["blob"]).unlink()
        with self.assertRaises(ValueError):
            self.catalog.validate("d", 1)

    def test_history_persists_across_restart_in_revision_order(self):
        self.catalog.import_csv("d", self.csv_file("v\n1\n"))
        self.assertEqual(self.catalog.validation_history("d", 1), [])
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "required"}])
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "unique"}])
        self.catalog.validate("d", 1, revision=1)
        self.catalog.validate("d", 1, revision=2)
        reloaded = Catalog(self.catalog.workspace)
        history = reloaded.validation_history("d", 1)
        self.assertEqual([item["rulesRevision"] for item in history], [1, 2])
        with self.assertRaises(ValueError):
            reloaded.validation_history("d", 99)
        with self.assertRaises(ValueError):
            reloaded.validation_history("missing", 1)

    def test_failed_report_write_leaves_no_partial_result(self):
        self.catalog.import_csv("d", self.csv_file("v\n1\n"))
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "required"}])
        with mock.patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.catalog.validate("d", 1)
        self.assertEqual(self.catalog.validation_history("d", 1), [])
        report = self.catalog.validate("d", 1)
        self.assertTrue(report["passed"])
        self.assertEqual(len(self.catalog.validation_history("d", 1)), 1)

    def test_validate_does_not_modify_data_or_add_versions(self):
        source = self.csv_file("v\n1\n")
        before = source.read_bytes()
        self.catalog.import_csv("d", source)
        self.catalog.set_rules("d", [{"id": "r", "column": "v", "type": "required"}])
        self.catalog.validate("d", 1)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(len(self.catalog.list_datasets()["d"]), 1)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "ws"
        (self.root / "good.csv").write_text("id,v\n1,5\n", encoding="utf-8")
        (self.root / "bad.csv").write_text("id,v\n1,99\n2,\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "governance_workbench", "--workspace", str(self.workspace), *arguments],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_new_commands_and_exit_codes(self):
        result = self.run_cli("import", "d", str(self.root / "good.csv"))
        self.assertEqual(result.returncode, 0, result.stderr)

        rules_path = self.root / "rules.json"
        rules_path.write_text(json.dumps([
            {"id": "req", "column": "id", "type": "required"},
            {"id": "rng", "column": "v", "type": "range", "min": 0, "max": 10},
        ]), encoding="utf-8")
        result = self.run_cli("rules", "d", str(rules_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["revision"], 1)

        result = self.run_cli("validate", "d", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["passed"])
        self.assertRegex(report["content_sha256"], r"^[0-9a-f]{64}$")

        result = self.run_cli("import", "d", str(self.root / "bad.csv"))
        self.assertEqual(result.returncode, 0)
        result = self.run_cli("validate", "d", "2")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["passed"])

        result = self.run_cli("validations", "d", "2")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(json.loads(result.stdout)), 1)
        # an existing version that was never validated yields an empty array
        self.run_cli("import", "d", str(self.root / "good.csv"))
        result = self.run_cli("validations", "d", "3")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), [])

    def test_error_envelope_on_stderr_only(self):
        self.run_cli("import", "d", str(self.root / "good.csv"))
        # validate with no rules
        result = self.run_cli("validate", "d", "1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        payload = json.loads(result.stderr)
        self.assertEqual(set(payload), {"error"})
        self.assertTrue(payload["error"])
        # unknown version
        result = self.run_cli("validate", "d", "9")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})
        # invalid rule configuration
        rules_path = self.root / "bad-rules.json"
        rules_path.write_text(json.dumps([{"id": "x"}]), encoding="utf-8")
        result = self.run_cli("rules", "d", str(rules_path))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})
        # invalid JSON document
        rules_path.write_text("{not json", encoding="utf-8")
        result = self.run_cli("rules", "d", str(rules_path))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})
        # missing rules file
        result = self.run_cli("rules", "d", str(self.root / "missing.json"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})

    def test_existing_commands_still_work(self):
        self.assertEqual(self.run_cli("list").returncode, 0)
        self.assertEqual(self.run_cli("demo").returncode, 0)
        self.run_cli("import", "c", str(self.root / "good.csv"))
        self.run_cli("import", "c", str(self.root / "bad.csv"))
        self.assertEqual(self.run_cli("compare", "c", "1", "2").returncode, 0)
        export_result = self.run_cli("export", "c", "1", str(self.root / "out"))
        self.assertEqual(export_result.returncode, 0, export_result.stderr)


class CleanLineageTest(unittest.TestCase):
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

    def import_people(self) -> None:
        self.catalog.import_csv(
            "people",
            self.csv(
                "people.csv",
                "id,name,city\n"
                "1, Ada ,EU\n"
                "2,Lin, APAC\n"
                "3, Ada ,EU\n"
                "4,Sam,US\n",
            ),
        )

    def test_clean_trim_rename_dedup_semantics(self):
        self.import_people()
        record = self.catalog.clean(
            "people",
            1,
            [
                {"type": "trim", "column": "name"},
                {"type": "trim", "column": "city"},
                {"type": "rename", "column": "name", "to": "full_name"},
                {"type": "drop_duplicates", "columns": ["full_name", "city"]},
            ],
        )
        self.assertEqual(record.version, 2)
        self.assertEqual(record.row_count, 3)
        self.assertEqual(record.schema, {"id": "integer", "full_name": "string", "city": "string"})
        blob = (self.catalog.workspace / record.blob).read_text(encoding="utf-8")
        self.assertEqual(blob, "id,full_name,city\n1,Ada,EU\n2,Lin,APAC\n4,Sam,US\n")
        lineage = record.lineage
        self.assertEqual(lineage["sourceVersion"], 1)
        self.assertEqual(lineage["sourceContentSha256"], self.catalog.get("people", 1)["content_sha256"])
        self.assertEqual(lineage["rowMapping"], [1, 2, 4])
        self.assertEqual(lineage["fieldMapping"], {"id": "id", "full_name": "name", "city": "city"})
        steps = lineage["steps"]
        self.assertEqual([step["type"] for step in steps], ["trim", "trim", "rename", "drop_duplicates"])
        self.assertEqual(steps[0]["modifiedRows"], [1, 3])
        self.assertEqual(steps[0]["inputRows"], 4)
        self.assertEqual(steps[0]["outputRows"], 4)
        self.assertEqual(steps[1]["modifiedRows"], [2])
        self.assertEqual(steps[2]["column"], "name")
        self.assertEqual(steps[2]["to"], "full_name")
        self.assertEqual(steps[3]["deletedRows"], [3])
        self.assertEqual(steps[3]["inputRows"], 4)
        self.assertEqual(steps[3]["outputRows"], 3)

    def test_rename_preserves_column_position(self):
        self.import_people()
        record = self.catalog.clean(
            "people",
            1,
            [{"type": "rename", "column": "name", "to": "full_name"}],
        )
        blob = (self.catalog.workspace / record.blob).read_text(encoding="utf-8")
        self.assertEqual(blob.splitlines()[0], "id,full_name,city")
        self.assertEqual(record.lineage["fieldMapping"], {"id": "id", "full_name": "name", "city": "city"})

    def test_dedup_keeps_first_occurrence_and_original_order(self):
        self.import_people()
        record = self.catalog.clean(
            "people",
            1,
            [{"type": "drop_duplicates", "columns": ["name"]}],
        )
        # rows 1 and 3 share " Ada " (untrimmed); row 3 is dropped
        self.assertEqual(record.lineage["steps"][0]["deletedRows"], [3])
        self.assertEqual(record.lineage["rowMapping"], [1, 2, 4])
        blob = (self.catalog.workspace / record.blob).read_text(encoding="utf-8")
        self.assertEqual(
            blob,
            "id,name,city\n1, Ada ,EU\n2,Lin, APAC\n4,Sam,US\n",
        )

    def test_empty_string_participates_and_numeric_text_not_converted(self):
        self.catalog.import_csv(
            "ee",
            self.csv("ee.csv", 'v\n""\n""\n1\n1\n01\n'),
        )
        record = self.catalog.clean("ee", 1, [{"type": "drop_duplicates", "columns": ["v"]}])
        # empty strings dedup as a group; "1" and "01" are distinct raw strings
        self.assertEqual(record.row_count, 3)
        self.assertEqual(record.lineage["steps"][0]["deletedRows"], [2, 4])
        self.assertEqual(record.lineage["rowMapping"], [1, 3, 5])
        blob = (self.catalog.workspace / record.blob).read_text(encoding="utf-8")
        self.assertEqual(blob, 'v\n""\n1\n01\n')

    def test_quoted_newline_row_numbering(self):
        self.catalog.import_csv(
            "qn",
            self.csv("qn.csv", 'id,name\n1,"line1\nline2"\n2, x \n'),
        )
        record = self.catalog.clean(
            "qn",
            1,
            [
                {"type": "trim", "column": "name"},
                {"type": "drop_duplicates", "columns": ["name"]},
            ],
        )
        self.assertEqual(record.row_count, 2)
        self.assertEqual(record.lineage["steps"][0]["modifiedRows"], [2])
        self.assertEqual(record.lineage["rowMapping"], [1, 2])

    def test_header_only_result(self):
        self.catalog.import_csv("ho", self.csv("ho.csv", "a,b\n"))
        record = self.catalog.clean("ho", 1, [{"type": "trim", "column": "a"}])
        self.assertEqual(record.row_count, 0)
        self.assertEqual(record.schema, {"a": "null", "b": "null"})
        self.assertEqual(record.lineage["rowMapping"], [])
        blob = (self.catalog.workspace / record.blob).read_text(encoding="utf-8")
        self.assertEqual(blob, "a,b\n")

    def test_deterministic_bytes_and_mappings(self):
        self.import_people()
        first = self.catalog.clean(
            "people",
            1,
            [
                {"type": "trim", "column": "name"},
                {"type": "drop_duplicates", "columns": ["name", "city"]},
            ],
        )
        second = self.catalog.clean(
            "people",
            1,
            [
                {"type": "trim", "column": "name"},
                {"type": "drop_duplicates", "columns": ["name", "city"]},
            ],
        )
        self.assertNotEqual(first.version, second.version)
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(
            (self.catalog.workspace / first.blob).read_bytes(),
            (self.catalog.workspace / second.blob).read_bytes(),
        )
        self.assertEqual(first.lineage["rowMapping"], second.lineage["rowMapping"])
        self.assertEqual(first.lineage["steps"], second.lineage["steps"])
        self.assertEqual(first.lineage["fieldMapping"], second.lineage["fieldMapping"])

    def test_appends_version_even_when_unchanged(self):
        self.import_people()
        record = self.catalog.clean("people", 1, [{"type": "trim", "column": "id"}])
        self.assertEqual(record.row_count, 4)
        self.assertEqual(record.version, 2)
        self.assertEqual(len(self.catalog.list_datasets()["people"]), 2)

    def test_rejects_bad_operations(self):
        self.import_people()

        def reject(operations):
            with self.assertRaises(ValueError):
                self.catalog.clean("people", 1, operations)

        reject([])
        reject("not-a-list")
        reject([None])
        reject(["not-an-object"])
        reject([{"type": "polish", "column": "name"}])  # unknown type
        reject([{"column": "name"}])  # missing type
        reject([{"type": "trim"}])  # missing column
        reject([{"type": "trim", "column": "name", "extra": 1}])  # extra attr
        reject([{"type": "trim", "column": ""}])  # empty column
        reject([{"type": "trim", "column": 5}])  # non-string column
        reject([{"type": "rename", "column": "name"}])  # missing to
        reject([{"type": "rename", "to": "x"}])  # missing column
        reject([{"type": "rename", "column": "name", "to": ""}])  # empty to
        reject([{"type": "rename", "column": "name", "to": 5}])  # non-string to
        reject([{"type": "drop_duplicates"}])  # missing columns
        reject([{"type": "drop_duplicates", "columns": []}])  # empty columns
        reject([{"type": "drop_duplicates", "columns": [""]}])  # empty column entry
        reject([{"type": "drop_duplicates", "columns": ["name", "name"]}])  # dup columns
        reject([{"type": "drop_duplicates", "columns": "name"}])  # non-array columns

    def test_rejects_missing_columns(self):
        self.import_people()
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "trim", "column": "nope"}])
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "rename", "column": "nope", "to": "x"}])
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "drop_duplicates", "columns": ["nope"]}])

    def test_rejects_rename_conflict(self):
        self.import_people()
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "rename", "column": "name", "to": "city"}])

    def test_rename_target_available_after_prior_rename(self):
        self.import_people()
        # renaming name->full then city->name is allowed because name is free
        record = self.catalog.clean(
            "people",
            1,
            [
                {"type": "rename", "column": "name", "to": "full"},
                {"type": "rename", "column": "city", "to": "name"},
            ],
        )
        self.assertEqual(record.lineage["fieldMapping"], {"id": "id", "full": "name", "name": "city"})

    def test_rejects_bad_csv_structure(self):
        # DictReader accepts a short row (fills None); the blob keeps the raw
        # content, and clean's strict column-count check rejects it.
        self.catalog.import_csv("bad", self.csv("bad.csv", "id,name\n1,Ada\n2\n"))
        with self.assertRaises(ValueError):
            self.catalog.clean("bad", 1, [{"type": "trim", "column": "id"}])
        # duplicate and empty headers are rejected at import time, so exercise
        # clean's defensive header check by tampering the blob and re-binding
        # the recorded hash.
        self.catalog.import_csv("dup", self.csv("dup.csv", "id\n1\n"))
        record = self.catalog.get("dup", 1)
        (self.catalog.workspace / record["blob"]).write_text("id,id\n1,2\n", encoding="utf-8")
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        state["datasets"]["dup"][0]["content_sha256"] = hashlib.sha256(
            (self.catalog.workspace / record["blob"]).read_bytes()
        ).hexdigest()
        self.catalog.state_path.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.catalog.clean("dup", 1, [{"type": "trim", "column": "id"}])

    def test_rejects_hash_mismatch(self):
        self.import_people()
        record = self.catalog.get("people", 1)
        (self.catalog.workspace / record["blob"]).write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "trim", "column": "id"}])
        self.assertEqual(len(self.catalog.list_datasets()["people"]), 1)

    def test_rejects_missing_blob(self):
        self.import_people()
        record = self.catalog.get("people", 1)
        (self.catalog.workspace / record["blob"]).unlink()
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "trim", "column": "id"}])

    def test_failed_write_consumes_no_version(self):
        self.import_people()
        with mock.patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.catalog.clean("people", 1, [{"type": "trim", "column": "id"}])
        self.assertEqual(len(self.catalog.list_datasets()["people"]), 1)
        record = self.catalog.clean("people", 1, [{"type": "trim", "column": "id"}])
        self.assertEqual(record.version, 2)

    def test_clean_does_not_modify_source(self):
        self.import_people()
        source = self.catalog.get("people", 1)
        source_bytes = (self.catalog.workspace / source["blob"]).read_bytes()
        self.catalog.clean("people", 1, [{"type": "trim", "column": "name"}])
        self.assertEqual((self.catalog.workspace / source["blob"]).read_bytes(), source_bytes)

    def test_original_rules_and_validations_unchanged(self):
        self.import_people()
        self.catalog.set_rules("people", [{"id": "r", "column": "id", "type": "required"}])
        self.catalog.validate("people", 1)
        self.catalog.clean("people", 1, [{"type": "trim", "column": "name"}])
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["rules"]["people"][0]["rules"][0]["id"], "r")
        self.assertIn("1", state["validations"]["people"])
        self.assertNotIn("2", state["validations"]["people"])

    def test_cleaned_version_supports_compare_validate_export(self):
        self.import_people()
        self.catalog.clean("people", 1, [{"type": "trim", "column": "name"}])
        comparison = self.catalog.compare("people", 1, 2)
        self.assertTrue(comparison["contentChanged"])
        self.catalog.set_rules("people", [{"id": "r", "column": "name", "type": "required"}])
        report = self.catalog.validate("people", 2)
        self.assertTrue(report["passed"])
        destination = self.root / "export"
        manifest = self.catalog.export("people", 2, destination)
        self.assertEqual(manifest["record"]["version"], 2)


class LineageTest(unittest.TestCase):
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

    def test_lineage_chain_for_cleaned_version(self):
        self.catalog.import_csv("d", self.csv("d.csv", "id,v\n1, a \n2,b\n"))
        self.catalog.clean("d", 1, [{"type": "trim", "column": "v"}])
        lineage = self.catalog.lineage("d", 2)
        self.assertEqual(lineage["dataset"], "d")
        self.assertEqual(lineage["version"], 2)
        self.assertEqual(len(lineage["chain"]), 1)
        entry = lineage["chain"][0]
        self.assertEqual(entry["version"], 2)
        self.assertEqual(entry["sourceVersion"], 1)
        self.assertEqual(entry["sourceContentSha256"], self.catalog.get("d", 1)["content_sha256"])
        self.assertEqual(entry["rowMapping"], [1, 2])
        self.assertEqual(entry["fieldMapping"], {"id": "id", "v": "v"})
        self.assertEqual([step["type"] for step in entry["steps"]], ["trim"])

    def test_lineage_chain_for_imported_version_is_empty(self):
        self.catalog.import_csv("d", self.csv("d.csv", "id\n1\n"))
        lineage = self.catalog.lineage("d", 1)
        self.assertEqual(lineage["chain"], [])
        self.assertEqual(lineage["content_sha256"], self.catalog.get("d", 1)["content_sha256"])

    def test_lineage_chained_cleaning_shows_full_chain(self):
        self.catalog.import_csv("d", self.csv("d.csv", "id,v\n1, a \n2,b\n3, a \n"))
        self.catalog.clean("d", 1, [{"type": "trim", "column": "v"}])
        self.catalog.clean("d", 2, [{"type": "rename", "column": "v", "to": "value"}])
        lineage = self.catalog.lineage("d", 3)
        self.assertEqual([entry["version"] for entry in lineage["chain"]], [3, 2])
        self.assertEqual(lineage["chain"][0]["sourceVersion"], 2)
        self.assertEqual(lineage["chain"][1]["sourceVersion"], 1)
        # direct source hash of v3 is v2's hash
        self.assertEqual(
            lineage["chain"][0]["sourceContentSha256"],
            self.catalog.get("d", 2)["content_sha256"],
        )

    def test_lineage_persists_across_restart(self):
        self.catalog.import_csv("d", self.csv("d.csv", "id,v\n1, a \n2,b\n"))
        self.catalog.clean("d", 1, [{"type": "trim", "column": "v"}])
        reloaded = Catalog(self.catalog.workspace)
        lineage = reloaded.lineage("d", 2)
        self.assertEqual(len(lineage["chain"]), 1)
        self.assertEqual(lineage["chain"][0]["rowMapping"], [1, 2])

    def test_lineage_legacy_workspace_without_lineage_key(self):
        self.catalog.import_csv("d", self.csv("d.csv", "id\n1\n"))
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        # simulate a legacy record that has no lineage key at all
        del state["datasets"]["d"][0]["lineage"]
        self.catalog.state_path.write_text(json.dumps(state), encoding="utf-8")
        lineage = self.catalog.lineage("d", 1)
        self.assertEqual(lineage["chain"], [])

    def test_lineage_unknown_dataset_and_version(self):
        with self.assertRaises(ValueError):
            self.catalog.lineage("missing", 1)
        self.catalog.import_csv("d", self.csv("d.csv", "id\n1\n"))
        with self.assertRaises(ValueError):
            self.catalog.lineage("d", 2)
        with self.assertRaises(ValueError):
            self.catalog.lineage("d", 0)


class CleanCliTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "ws"
        (self.root / "people.csv").write_text(
            "id,name,city\n1, Ada ,EU\n2,Lin, APAC\n3, Ada ,EU\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "governance_workbench", "--workspace", str(self.workspace), *arguments],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_clean_success_exit_0(self):
        result = self.run_cli("import", "people", str(self.root / "people.csv"))
        self.assertEqual(result.returncode, 0, result.stderr)
        ops = self.root / "ops.json"
        ops.write_text(json.dumps([
            {"type": "trim", "column": "name"},
            {"type": "drop_duplicates", "columns": ["name", "city"]},
        ]), encoding="utf-8")
        result = self.run_cli("clean", "people", "1", str(ops))
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record["version"], 2)
        self.assertEqual(record["row_count"], 2)
        self.assertEqual(record["lineage"]["sourceVersion"], 1)
        self.assertEqual(record["lineage"]["steps"][1]["deletedRows"], [3])

    def test_clean_error_exit_2_stderr_only(self):
        self.run_cli("import", "people", str(self.root / "people.csv"))
        ops = self.root / "bad.json"
        ops.write_text(json.dumps([{"type": "trim", "column": "nope"}]), encoding="utf-8")
        result = self.run_cli("clean", "people", "1", str(ops))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        payload = json.loads(result.stderr)
        self.assertEqual(set(payload), {"error"})
        self.assertTrue(payload["error"])
        # no version consumed
        self.assertEqual(len(json.loads(Path(self.workspace, ".dgw", "catalog.json").read_text())["datasets"]["people"]), 1)

    def test_clean_missing_ops_file_exit_2(self):
        self.run_cli("import", "people", str(self.root / "people.csv"))
        result = self.run_cli("clean", "people", "1", str(self.root / "missing.json"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})

    def test_clean_invalid_json_exit_2(self):
        self.run_cli("import", "people", str(self.root / "people.csv"))
        ops = self.root / "bad.json"
        ops.write_text("{not json", encoding="utf-8")
        result = self.run_cli("clean", "people", "1", str(ops))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})

    def test_lineage_cli_success(self):
        self.run_cli("import", "people", str(self.root / "people.csv"))
        ops = self.root / "ops.json"
        ops.write_text(json.dumps([{"type": "trim", "column": "name"}]), encoding="utf-8")
        self.run_cli("clean", "people", "1", str(ops))
        result = self.run_cli("lineage", "people", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        lineage = json.loads(result.stdout)
        self.assertEqual(lineage["version"], 2)
        self.assertEqual(len(lineage["chain"]), 1)

    def test_lineage_cli_error_exit_2(self):
        result = self.run_cli("lineage", "people", "1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})

    def test_export_cleaned_version_includes_lineage(self):
        self.run_cli("import", "people", str(self.root / "people.csv"))
        ops = self.root / "ops.json"
        ops.write_text(json.dumps([{"type": "trim", "column": "name"}]), encoding="utf-8")
        self.run_cli("clean", "people", "1", str(ops))
        destination = self.root / "export"
        result = self.run_cli("export", "people", "2", str(destination))
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("lineage", manifest)
        self.assertEqual(manifest["lineage"]["chain"][0]["sourceVersion"], 1)
        self.assertEqual(manifest["record"]["version"], 2)


if __name__ == "__main__":
    unittest.main()
