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


class CleanTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")
        self.catalog.import_csv(
            "people",
            self.csv_file(
                "id,name,city\n"
                "1, Ada ,x\n"
                "2,Bob,y\n"
                "1, Ada ,x\n"
                "3,Ada,z\n"
            ),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def csv_file(self, contents: str, name: str = "data.csv") -> Path:
        path = self.root / name
        path.write_text(contents, encoding="utf-8")
        return path

    def ops_file(self, operations, name: str = "ops.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(operations), encoding="utf-8")
        return path

    def clean_people(self):
        return self.catalog.clean(
            "people",
            1,
            [
                {"type": "trim", "column": "name"},
                {"type": "rename", "column": "city", "to": "region"},
                {"type": "drop_duplicates", "columns": ["id", "name"]},
            ],
        )

    def test_clean_appends_version_with_result_shape(self):
        result = self.clean_people()
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["row_count"], 3)
        self.assertEqual(result["schema"], {"id": "integer", "name": "string", "region": "string"})
        stored = (self.catalog.workspace / result["blob"]).read_bytes()
        self.assertEqual(stored, b"id,name,region\n1,Ada,x\n2,Bob,y\n3,Ada,z\n")
        # the source version is untouched
        self.assertEqual(len(self.catalog.list_datasets()["people"]), 2)
        original = self.catalog.get("people", 1)
        self.assertEqual(original["row_count"], 4)

    def test_cleaned_version_supports_compare_validate_export(self):
        self.clean_people()
        comparison = self.catalog.compare("people", 1, 2)
        self.assertEqual(comparison["addedFields"], ["region"])
        self.assertEqual(comparison["removedFields"], ["city"])
        self.assertEqual(comparison["rowDelta"], -1)
        self.catalog.set_rules("people", [{"id": "r", "column": "name", "type": "required"}])
        report = self.catalog.validate("people", 2)
        self.assertTrue(report["passed"])
        self.assertEqual(report["rowCount"], 3)
        manifest = self.catalog.export("people", 2, self.root / "out")
        self.assertEqual(manifest["record"]["version"], 2)
        self.assertEqual(manifest["file"], "people-v2.csv")
        self.assertEqual(len(manifest["lineage"]), 1)

    def test_lineage_records_steps_rows_and_columns(self):
        self.clean_people()
        lineage = self.catalog.lineage("people", 2)
        self.assertEqual(lineage["dataset"], "people")
        self.assertEqual(lineage["version"], 2)
        self.assertEqual(len(lineage["chain"]), 1)
        entry = lineage["chain"][0]
        self.assertEqual(entry["sourceVersion"], 1)
        self.assertEqual(entry["sourceSha256"], self.catalog.get("people", 1)["content_sha256"])
        self.assertEqual(
            entry["operations"],
            [
                {"type": "trim", "column": "name"},
                {"type": "rename", "column": "city", "to": "region"},
                {"type": "drop_duplicates", "columns": ["id", "name"]},
            ],
        )
        steps = entry["steps"]
        self.assertEqual([(s["inputRows"], s["outputRows"]) for s in steps], [(4, 4), (4, 4), (4, 3)])
        self.assertEqual(steps[0]["modifiedRows"], [1, 3])
        self.assertEqual((steps[1]["from"], steps[1]["to"]), ("city", "region"))
        self.assertEqual(steps[2]["deletedRows"], [3])
        self.assertEqual(entry["columnMapping"], {"id": "id", "name": "name", "region": "city"})
        self.assertEqual(entry["rowMapping"], [1, 2, 4])

    def test_quoted_newline_does_not_count_as_record(self):
        self.catalog.import_csv("notes", self.csv_file("id,name\n1,\"line one\nline two\"\n2, x \n", "notes.csv"))
        result = self.catalog.clean("notes", 1, [{"type": "trim", "column": "name"}])
        entry = result["lineage"]
        self.assertEqual(entry["steps"][0]["modifiedRows"], [2])
        self.assertEqual(entry["rowMapping"], [1, 2])

    def test_dedup_uses_raw_strings_and_empty_strings_participate(self):
        self.catalog.import_csv("raw", self.csv_file("a,b\n1,\n01,\n1,\n", "raw.csv"))
        result = self.catalog.clean("raw", 1, [{"type": "drop_duplicates", "columns": ["a", "b"]}])
        # "1" and "01" are distinct strings; the second ("1", "") is dropped
        self.assertEqual(result["lineage"]["steps"][0]["deletedRows"], [3])
        self.assertEqual(result["lineage"]["rowMapping"], [1, 2])

    def test_repeat_clean_is_deterministic_but_appends(self):
        first = self.clean_people()
        second = self.clean_people()
        self.assertEqual((first["version"], second["version"]), (2, 3))
        self.assertEqual(first["content_sha256"], second["content_sha256"])
        self.assertEqual(first["blob"], second["blob"])
        self.assertEqual(first["lineage"]["rowMapping"], second["lineage"]["rowMapping"])
        self.assertEqual(first["lineage"]["steps"], second["lineage"]["steps"])

    def test_noop_and_header_only_cleans_still_append(self):
        noop = self.catalog.clean("people", 1, [{"type": "trim", "column": "id"}])
        self.assertEqual(noop["row_count"], 4)
        self.assertEqual(noop["lineage"]["steps"][0]["modifiedRows"], [])
        self.catalog.import_csv("empty", self.csv_file("a,b\n", "empty.csv"))
        header_only = self.catalog.clean("empty", 1, [{"type": "trim", "column": "a"}])
        self.assertEqual(header_only["row_count"], 0)
        self.assertEqual(header_only["lineage"]["rowMapping"], [])

    def test_chain_extends_across_cleans_and_survives_restart(self):
        self.clean_people()
        self.catalog.clean("people", 2, [{"type": "rename", "column": "region", "to": "area"}])
        reloaded = Catalog(self.catalog.workspace)
        lineage = reloaded.lineage("people", 3)
        self.assertEqual([entry["version"] for entry in lineage["chain"]], [2, 3])
        self.assertEqual(lineage["chain"][0]["sourceVersion"], 1)
        self.assertEqual(lineage["chain"][1]["sourceVersion"], 2)
        self.assertEqual(lineage["chain"][1]["columnMapping"]["area"], "region")
        # an imported version is the chain start
        self.assertEqual(reloaded.lineage("people", 1)["chain"], [])

    def test_export_of_imported_version_has_no_lineage(self):
        manifest = self.catalog.export("people", 1, self.root / "plain")
        self.assertNotIn("lineage", manifest)

    def test_invalid_operations_rejected_without_version(self):
        def reject(operations):
            with self.assertRaises(ValueError):
                self.catalog.clean("people", 1, operations)

        reject([])
        reject(42)
        reject({"type": "trim", "column": "name"})  # payload must be an array
        reject([None])
        reject([{"column": "name"}])  # missing type
        reject([{"type": "sort", "column": "name"}])  # unknown operation
        reject([{"type": "trim"}])  # missing column
        reject([{"type": "trim", "column": "name", "extra": 1}])  # extra attribute
        reject([{"type": "trim", "column": ""}])
        reject([{"type": "trim", "column": 3}])
        reject([{"type": "trim", "column": "missing"}])  # unknown column
        reject([{"type": "rename", "column": "name"}])  # missing to
        reject([{"type": "rename", "column": "name", "to": ""}])
        reject([{"type": "rename", "column": "name", "to": "id"}])  # conflicts
        reject([{"type": "rename", "column": "name", "to": "name"}])  # self-conflict
        reject([{"type": "rename", "column": "missing", "to": "x"}])
        reject([{"type": "drop_duplicates", "columns": []}])
        reject([{"type": "drop_duplicates", "columns": "id"}])
        reject([{"type": "drop_duplicates", "columns": ["id", "id"]}])
        reject([{"type": "drop_duplicates", "columns": ["id", ""]}])
        reject([{"type": "drop_duplicates", "columns": ["missing"]}])
        # later operations see renamed columns
        reject([
            {"type": "rename", "column": "name", "to": "label"},
            {"type": "trim", "column": "name"},
        ])
        self.assertEqual(len(self.catalog.list_datasets()["people"]), 1)

    def test_rename_then_use_new_name(self):
        result = self.catalog.clean(
            "people",
            1,
            [
                {"type": "rename", "column": "name", "to": "label"},
                {"type": "trim", "column": "label"},
            ],
        )
        self.assertEqual(result["schema"]["label"], "string")
        self.assertEqual(result["lineage"]["steps"][1]["modifiedRows"], [1, 3])

    def test_missing_dataset_version_file_and_hash_failures(self):
        with self.assertRaises(ValueError):
            self.catalog.clean("missing", 1, [{"type": "trim", "column": "name"}])
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 9, [{"type": "trim", "column": "name"}])
        record = self.catalog.get("people", 1)
        blob = self.catalog.workspace / record["blob"]
        original = blob.read_bytes()
        blob.unlink()
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "trim", "column": "name"}])
        blob.write_bytes(b"tampered\n")
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, [{"type": "trim", "column": "name"}])
        blob.write_bytes(original)
        self.assertEqual(len(self.catalog.list_datasets()["people"]), 1)

    def test_ragged_stored_csv_rejected(self):
        self.catalog.import_csv("ragged", self.csv_file("a,b\n1,2,3\n", "ragged.csv"))
        with self.assertRaises(ValueError):
            self.catalog.clean("ragged", 1, [{"type": "trim", "column": "a"}])
        self.assertEqual(len(self.catalog.list_datasets()["ragged"]), 1)

    def test_failed_write_consumes_no_version_or_lineage(self):
        with mock.patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.clean_people()
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(state["datasets"]["people"]), 1)
        self.assertEqual(state.get("lineage", {}).get("people", {}), {})
        result = self.clean_people()
        self.assertEqual(result["version"], 2)

    def test_operations_file_path_accepted(self):
        path = self.ops_file([{"type": "trim", "column": "name"}])
        result = self.catalog.clean("people", 1, path)
        self.assertEqual(result["version"], 2)
        with self.assertRaises(OSError):
            self.catalog.clean("people", 1, self.root / "missing.json")
        bad = self.root / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.catalog.clean("people", 1, bad)
        self.assertEqual(len(self.catalog.list_datasets()["people"]), 2)


class KeyedCompareTest(unittest.TestCase):
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

    def import_versions(self, dataset: str, *contents: str) -> None:
        for index, content in enumerate(contents, start=1):
            self.catalog.import_csv(dataset, self.csv_file(content, f"{dataset}-{index}.csv"))

    def test_added_removed_modified_and_unchanged(self):
        self.import_versions(
            "people",
            "id,name,score\n1,Ada,10\n2,Lin,20\n3,Sam,30\n",
            "id,name,score\n1,Ada,10\n2,Lin,25\n4,Zo,40\n",
        )
        result = self.catalog.compare("people", 1, 2, keys=["id"])
        diff = result["rowDiff"]
        self.assertEqual(diff["unchangedCount"], 1)
        added, = diff["added"]
        self.assertEqual(added["key"], ["4"])
        self.assertEqual(added["row"], 3)
        self.assertEqual(added["values"], {"id": "4", "name": "Zo", "score": "40"})
        removed, = diff["removed"]
        self.assertEqual(removed["key"], ["3"])
        self.assertEqual(removed["row"], 3)
        self.assertEqual(removed["values"], {"id": "3", "name": "Sam", "score": "30"})
        modified, = diff["modified"]
        self.assertEqual(modified["key"], ["2"])
        self.assertEqual(modified["leftRow"], 2)
        self.assertEqual(modified["rightRow"], 2)
        self.assertEqual(modified["changes"], {"score": {"from": "20", "to": "25"}})
        # original comparison fields are still present
        self.assertIn("addedFields", result)
        self.assertIn("contentChanged", result)

    def test_unchanged_when_only_row_order_differs(self):
        self.import_versions(
            "m",
            "a,b,v\n1,x,10\n2,y,20\n",
            "a,b,v\n2,y,20\n1,x,10\n",
        )
        result = self.catalog.compare("m", 1, 2, keys=["a", "b"])
        diff = result["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["unchangedCount"], 2)

    def test_raw_strings_are_used_without_stripping_or_conversion(self):
        self.import_versions(
            "raw",
            "id,v\n1,10\n01,10\n 1 ,10\n",
            "id,v\n1,10\n01,11\n 1 ,10\n",
        )
        result = self.catalog.compare("raw", 1, 2, keys=["id"])
        diff = result["rowDiff"]
        # "1" and "01" are distinct keys; " 1 " is a third distinct key
        modified, = diff["modified"]
        self.assertEqual(modified["key"], ["01"])
        self.assertEqual(modified["changes"], {"v": {"from": "10", "to": "11"}})
        self.assertEqual(diff["unchangedCount"], 2)

    def test_whitespace_only_key_is_valid_but_empty_string_is_rejected(self):
        self.import_versions("ws", "id\n \n1\n")
        # whitespace-only key matches itself and counts as unchanged
        result = self.catalog.compare("ws", 1, 1, keys=["id"])
        self.assertEqual(result["rowDiff"]["unchangedCount"], 2)
        # a data row with an empty key cell is rejected (blank physical lines
        # are not records, so the empty cell must be an actual quoted field)
        self.import_versions("empty", 'id\n1\n""\n', 'id\n1\n""\n')
        with self.assertRaises(ValueError):
            self.catalog.compare("empty", 1, 2, keys=["id"])

    def test_duplicate_key_on_either_side_rejected(self):
        self.import_versions(
            "dup",
            "id,v\n1,a\n1,b\n",
            "id,v\n1,a\n2,c\n",
        )
        with self.assertRaises(ValueError):
            self.catalog.compare("dup", 1, 2, keys=["id"])
        self.import_versions(
            "dup2",
            "id,v\n1,a\n2,b\n",
            "id,v\n1,a\n1,c\n",
        )
        with self.assertRaises(ValueError):
            self.catalog.compare("dup2", 1, 2, keys=["id"])

    def test_multiple_keys_match_in_specified_order(self):
        self.import_versions(
            "mk",
            "a,b,v\n1,x,10\n1,y,20\n",
            "a,b,v\n1,y,21\n1,x,10\n",
        )
        result = self.catalog.compare("mk", 1, 2, keys=["a", "b"])
        diff = result["rowDiff"]
        modified, = diff["modified"]
        self.assertEqual(modified["key"], ["1", "y"])
        self.assertEqual(modified["changes"], {"v": {"from": "20", "to": "21"}})
        self.assertEqual(diff["unchangedCount"], 1)

    def test_missing_column_is_null_not_empty_string(self):
        self.import_versions(
            "cols",
            "id,a\n1,x\n",
            "id,b\n1,y\n",
        )
        result = self.catalog.compare("cols", 1, 2, keys=["id"])
        modified, = result["rowDiff"]["modified"]
        self.assertEqual(modified["changes"], {
            "a": {"from": "x", "to": None},
            "b": {"from": None, "to": "y"},
        })

    def test_rename_is_remove_old_and_add_new(self):
        self.import_versions(
            "rn",
            "id,name\n1,Ada\n",
            "id,full_name\n1,Ada\n",
        )
        result = self.catalog.compare("rn", 1, 2, keys=["id"])
        modified, = result["rowDiff"]["modified"]
        self.assertEqual(modified["changes"], {
            "name": {"from": "Ada", "to": None},
            "full_name": {"from": None, "to": "Ada"},
        })

    def test_same_version_compares_against_itself(self):
        self.import_versions("self", "id,v\n1,a\n2,b\n")
        result = self.catalog.compare("self", 1, 1, keys=["id"])
        diff = result["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["unchangedCount"], 2)
        self.assertFalse(result["contentChanged"])

    def test_header_only_on_both_sides_is_legal_empty_data(self):
        self.import_versions("empty", "a,b\n", "a,b\n")
        result = self.catalog.compare("empty", 1, 2, keys=["a"])
        diff = result["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["unchangedCount"], 0)

    def test_keyed_compare_verifies_stored_hash(self):
        self.import_versions("h", "id,v\n1,a\n")
        record = self.catalog.get("h", 1)
        blob = self.catalog.workspace / record["blob"]
        original = blob.read_bytes()
        blob.write_bytes(b"id,v\n1,tampered\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("h", 1, 1, keys=["id"])
        blob.write_bytes(original)

    def test_missing_blob_rejected(self):
        self.import_versions("miss", "id,v\n1,a\n")
        record = self.catalog.get("miss", 1)
        (self.catalog.workspace / record["blob"]).unlink()
        with self.assertRaises(ValueError):
            self.catalog.compare("miss", 1, 1, keys=["id"])

    def test_unparseable_csv_rejected(self):
        self.import_versions("bad", "id,v\n1,a\n")
        record = self.catalog.get("bad", 1)
        blob = self.catalog.workspace / record["blob"]
        blob.write_bytes(b"id,v\n1,a\n\x00bad\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("bad", 1, 1, keys=["id"])

    def test_empty_and_duplicate_headers_rejected(self):
        self.import_versions("eh", "id,v\n1,a\n")
        record = self.catalog.get("eh", 1)
        blob = self.catalog.workspace / record["blob"]
        blob.write_bytes(b",v\n1,a\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("eh", 1, 1, keys=["id"])
        blob.write_bytes(b"id,id\n1,a\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("eh", 1, 1, keys=["id"])

    def test_ragged_record_rejected(self):
        self.import_versions("rg", "id,v\n1,a\n")
        record = self.catalog.get("rg", 1)
        blob = self.catalog.workspace / record["blob"]
        blob.write_bytes(b"id,v\n1,a,b\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("rg", 1, 1, keys=["id"])

    def test_invalid_keys_parameters_rejected(self):
        self.import_versions("k", "id,v\n1,a\n")

        def reject(keys):
            with self.assertRaises(ValueError):
                self.catalog.compare("k", 1, 1, keys=keys)

        reject([])
        reject("id")
        reject([""])
        reject([1])
        reject(["id", "id"])
        reject(["missing"])

    def test_unknown_dataset_or_version_rejected(self):
        self.import_versions("u", "id,v\n1,a\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("missing", 1, 1, keys=["id"])
        with self.assertRaises(ValueError):
            self.catalog.compare("u", 1, 2, keys=["id"])

    def test_keyed_compare_does_not_persist_changes(self):
        self.import_versions("np", "id,v\n1,a\n")
        before = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.catalog.compare("np", 1, 1, keys=["id"])
        after = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(before, after)

    def test_cleaned_versions_can_be_compared_by_keys(self):
        self.import_versions(
            "cl",
            "id,name\n1,Ada\n2,Lin\n",
        )
        self.catalog.clean("cl", 1, [{"type": "rename", "column": "name", "to": "full_name"}])
        result = self.catalog.compare("cl", 1, 2, keys=["id"])
        diff = result["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        modified = {item["key"][0]: item for item in diff["modified"]}
        self.assertEqual(set(modified), {"1", "2"})
        for item in diff["modified"]:
            self.assertEqual(item["leftRow"], item["rightRow"])


class KeyedCompareCliTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "ws"
        (self.root / "one.csv").write_text("id,name\n1,Ada\n2,Lin\n", encoding="utf-8")
        (self.root / "two.csv").write_text("id,name,region\n1,Ada,EU\n3,Sam,US\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "governance_workbench", "--workspace", str(self.workspace), *arguments],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_keyed_compare_success_exits_zero(self):
        self.run_cli("import", "d", str(self.root / "one.csv"))
        self.run_cli("import", "d", str(self.root / "two.csv"))
        result = self.run_cli("compare", "d", "1", "2", "--keys", "id")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        payload = json.loads(result.stdout)
        self.assertIn("rowDiff", payload)
        diff = payload["rowDiff"]
        # key "1" gains the region column -> modified; "2" removed; "3" added
        self.assertEqual(len(diff["modified"]), 1)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["removed"]), 1)
        self.assertEqual(diff["unchangedCount"], 0)

    def test_keyed_compare_failure_emits_stderr_only_envelope(self):
        self.run_cli("import", "d", str(self.root / "one.csv"))
        self.run_cli("import", "d", str(self.root / "two.csv"))
        result = self.run_cli("compare", "d", "1", "2", "--keys", "missing")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        payload = json.loads(result.stderr)
        self.assertEqual(set(payload), {"error"})
        self.assertTrue(payload["error"])

    def test_keyed_compare_without_keys_keeps_original_output(self):
        self.run_cli("import", "d", str(self.root / "one.csv"))
        self.run_cli("import", "d", str(self.root / "two.csv"))
        result = self.run_cli("compare", "d", "1", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("rowDiff", json.loads(result.stdout))

    def test_multiple_keys_passed_to_cli(self):
        self.run_cli("import", "d", str(self.root / "one.csv"))
        result = self.run_cli("compare", "d", "1", "1", "--keys", "id", "name")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["rowDiff"]["unchangedCount"], 2)


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

    def test_clean_and_lineage_commands(self):
        result = self.run_cli("import", "d", str(self.root / "good.csv"))
        self.assertEqual(result.returncode, 0, result.stderr)

        ops_path = self.root / "ops.json"
        ops_path.write_text(json.dumps([
            {"type": "trim", "column": "v"},
            {"type": "rename", "column": "v", "to": "value"},
        ]), encoding="utf-8")
        result = self.run_cli("clean", "d", "1", str(ops_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        cleaned = json.loads(result.stdout)
        self.assertEqual(cleaned["version"], 2)
        self.assertEqual(cleaned["row_count"], 1)
        self.assertEqual(cleaned["schema"], {"id": "integer", "value": "integer"})

        result = self.run_cli("lineage", "d", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        lineage = json.loads(result.stdout)
        self.assertEqual(len(lineage["chain"]), 1)
        self.assertEqual(lineage["chain"][0]["sourceVersion"], 1)
        self.assertEqual(lineage["chain"][0]["columnMapping"], {"id": "id", "value": "v"})

        # imported version is the chain start
        result = self.run_cli("lineage", "d", "1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["chain"], [])

        # exported manifest of a cleaned version carries the full chain
        result = self.run_cli("export", "d", "2", str(self.root / "cleaned-out"))
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(result.stdout)
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertIn("record", manifest)
        self.assertIn("file", manifest)
        self.assertEqual(len(manifest["lineage"]), 1)

    def test_clean_and_lineage_error_envelope(self):
        self.run_cli("import", "d", str(self.root / "good.csv"))
        ops_path = self.root / "ops.json"
        ops_path.write_text(json.dumps([{"type": "trim", "column": "missing"}]), encoding="utf-8")
        for arguments in (
            ["clean", "d", "1", str(ops_path)],           # unknown column
            ["clean", "d", "9", str(ops_path)],           # unknown version
            ["clean", "missing", "1", str(ops_path)],     # unknown dataset
            ["clean", "d", "1", str(self.root / "no.json")],  # unreadable file
            ["lineage", "d", "9"],                        # unknown version
            ["lineage", "missing", "1"],                  # unknown dataset
        ):
            result = self.run_cli(*arguments)
            self.assertEqual(result.returncode, 2, arguments)
            self.assertEqual(result.stdout, "")
            self.assertEqual(set(json.loads(result.stderr)), {"error"})
        # failed cleans did not append versions
        self.assertEqual(len(json.loads(self.run_cli("list").stdout)["d"]), 1)
        # invalid JSON operations file
        ops_path.write_text("[{not json", encoding="utf-8")
        result = self.run_cli("clean", "d", "1", str(ops_path))
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


if __name__ == "__main__":
    unittest.main()
