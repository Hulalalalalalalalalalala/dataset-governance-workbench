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

    def import_pair(self, left: str, right: str, dataset: str = "d"):
        self.catalog.import_csv(dataset, self.csv_file(left, "left.csv"))
        self.catalog.import_csv(dataset, self.csv_file(right, "right.csv"))

    def test_without_keys_keeps_original_shape(self):
        self.import_pair("id,v\n1,a\n", "id,v\n1,b\n")
        result = self.catalog.compare("d", 1, 2)
        self.assertNotIn("rowDiff", result)
        self.assertIn("addedFields", result)

    def test_added_removed_modified_and_unchanged(self):
        self.import_pair(
            "id,name,v\n1,Ada,1\n2,Lin,2\n4,Max,4\n",
            "id,name,v\n1,Ada,1\n2,Lin,9\n3,Sam,3\n",
        )
        diff = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual([(r["key"], r["row"], r["values"]) for r in diff["removed"]],
                         [(["4"], 3, {"id": "4", "name": "Max", "v": "4"})])
        self.assertEqual([(r["key"], r["row"], r["values"]) for r in diff["added"]],
                         [(["3"], 3, {"id": "3", "name": "Sam", "v": "3"})])
        self.assertEqual(diff["modified"], [{
            "key": ["2"], "leftRow": 2, "rightRow": 2,
            "changes": {"v": {"from": "2", "to": "9"}},
        }])
        self.assertEqual(diff["unchangedCount"], 1)
        # changes only include changed fields
        self.assertEqual(set(diff["modified"][0]["changes"]), {"v"})

    def test_keys_use_raw_strings_in_given_order(self):
        self.import_pair("id,v\n1,a\n01,b\n", "id,v\n1,a\n01,c\n")
        diff = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual(diff["unchangedCount"], 1)
        self.assertEqual(diff["modified"][0]["key"], ["01"])
        self.assertEqual(diff["modified"][0]["changes"], {"v": {"from": "b", "to": "c"}})
        # whitespace and separators inside key values are literal
        self.import_pair(
            "a,b,v\nx|y,1,p\n , ,q\n",
            "a,b,v\nx|y,1,p\n , ,r\n",
            dataset="m",
        )
        diff = self.catalog.compare("m", 1, 2, keys=["a", "b"])["rowDiff"]
        self.assertEqual(diff["unchangedCount"], 1)
        self.assertEqual(diff["modified"][0]["key"], [" ", " "])

    def test_composite_key(self):
        self.import_pair(
            "g,i,v\nA,1,x\nB,2,y\n",
            "g,i,v\nA,1,x\nB,2,z\n",
        )
        diff = self.catalog.compare("d", 1, 2, keys=["g", "i"])["rowDiff"]
        self.assertEqual(diff["modified"][0]["key"], ["B", "2"])
        self.assertEqual(diff["unchangedCount"], 1)

    def test_row_reorder_is_not_modification(self):
        self.import_pair("id,v\n1,a\n2,b\n", "id,v\n2,b\n1,a\n")
        diff = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["unchangedCount"], 2)

    def test_added_modified_sorted_right_rows_removed_left_rows(self):
        self.import_pair(
            "id,v\n1,a\n8,x\n7,u\n",
            "id,v\n2,b\n1,c\n7,u\n3,d\n",
        )
        diff = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual([r["row"] for r in diff["added"]], [1, 4])
        self.assertEqual([r["rightRow"] for r in diff["modified"]], [2])
        self.assertEqual([r["row"] for r in diff["removed"]], [2])
        self.assertEqual(diff["unchangedCount"], 1)

    def test_same_version_compare(self):
        self.import_pair("id,v\n1,a\n", "id,v\n1,a\n")
        diff = self.catalog.compare("d", 1, 1, keys=["id"])["rowDiff"]
        self.assertEqual(diff["unchangedCount"], 1)
        self.assertFalse(self.catalog.compare("d", 1, 1, keys=["id"])["contentChanged"])

    def test_header_only_sides_are_empty_data(self):
        self.import_pair("a,b\n", "a,b\n")
        diff = self.catalog.compare("d", 1, 2, keys=["a"])["rowDiff"]
        self.assertEqual(diff, {"added": [], "removed": [], "modified": [], "unchangedCount": 0})

    def test_missing_column_on_one_side_is_null_and_distinct_from_empty(self):
        self.import_pair("id,v\n1,\n", "id,w\n1,x\n")
        changes = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]["modified"][0]["changes"]
        self.assertEqual(changes, {
            "v": {"from": "", "to": None},
            "w": {"from": None, "to": "x"},
        })

    def test_added_and_removed_fields_in_values(self):
        self.import_pair("id,v\n1,a\n", "id,v,w\n1,a,z\n")
        added = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]["added"]
        self.assertEqual(added, [])
        # values objects span the union of fields with stable key order
        self.catalog.import_csv("d", self.csv_file("id,v,w\n9,a,z\n", "third.csv"))
        entry = self.catalog.compare("d", 1, 3, keys=["id"])["rowDiff"]["added"][0]
        self.assertEqual(list(entry["values"]), ["id", "v", "w"])
        self.assertEqual(entry["values"], {"id": "9", "v": "a", "w": "z"})

    def test_quoted_newline_does_not_advance_row_numbers(self):
        self.import_pair(
            'id,name\n1,"line one\nline two"\n2,x\n',
            'id,name\n1,"line one\nline two"\n2,y\n',
        )
        modified = self.catalog.compare("d", 1, 2, keys=["id"])["rowDiff"]["modified"]
        self.assertEqual([(m["leftRow"], m["rightRow"]) for m in modified], [(2, 2)])

    def test_cleaned_versions_compare_by_keys(self):
        self.catalog.import_csv("p", self.csv_file("id,name,city\n1, Ada ,x\n2,Bob,y\n"))
        self.catalog.clean("p", 1, [
            {"type": "trim", "column": "name"},
            {"type": "rename", "column": "city", "to": "region"},
        ])
        diff = self.catalog.compare("p", 1, 2, keys=["id"])["rowDiff"]
        self.assertEqual(diff["unchangedCount"], 0)
        by_row = {m["leftRow"]: m["changes"] for m in diff["modified"]}
        self.assertEqual(set(by_row[1]), {"city", "region", "name"})
        self.assertEqual(by_row[1]["name"], {"from": " Ada ", "to": "Ada"})
        self.assertEqual(set(by_row[2]), {"city", "region"})

    def test_invalid_keys_arguments(self):
        self.import_pair("id,v\n1,a\n", "id,v\n1,a\n")
        for bad in ([], "id", [""], ["a", ""], [1], [None], ["id", "id"], [["id"]]):
            with self.assertRaises(ValueError):
                self.catalog.compare("d", 1, 2, keys=bad)

    def test_key_column_missing_on_either_side(self):
        self.import_pair("id,v\n1,a\n", "id,w\n1,a\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["v"])  # missing on right
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["w"])  # missing on left
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["nope"])

    def test_empty_key_cell_rejects_whole_compare(self):
        self.import_pair("id,v\n,a\n1,b\n", "id,v\n,c\n1,b\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["id"])
        # whitespace-only key cells are allowed
        self.import_pair("id,v\n ,a\n", "id,v\n ,a\n", dataset="ws")
        self.assertEqual(
            self.catalog.compare("ws", 1, 2, keys=["id"])["rowDiff"]["unchangedCount"], 1
        )

    def test_duplicate_full_key_rejects_whole_compare(self):
        self.import_pair("id,v\n1,a\n1,b\n", "id,v\n1,a\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["id"])
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 2, 1, keys=["id"])
        # duplicates only over the *full* composite key are rejected
        self.import_pair("g,i,v\nA,1,x\nA,2,y\n", "g,i,v\nA,1,x\nA,2,y\n", dataset="c")
        self.assertEqual(
            self.catalog.compare("c", 1, 2, keys=["g", "i"])["rowDiff"]["unchangedCount"], 2
        )

    def test_unknown_dataset_and_version(self):
        self.import_pair("id,v\n1,a\n", "id,v\n1,b\n")
        with self.assertRaises(ValueError):
            self.catalog.compare("missing", 1, 2, keys=["id"])
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 9, 2, keys=["id"])

    def test_stored_hashes_verified_every_time(self):
        self.import_pair("id,v\n1,a\n", "id,v\n1,b\n")
        record = self.catalog.get("d", 1)
        blob = self.catalog.workspace / record["blob"]
        # tamper: even same-version keyed comparison must detect it
        blob.write_text("id,v\n1,z\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 1, keys=["id"])
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["id"])
        # missing blob
        blob.unlink()
        with self.assertRaises(ValueError):
            self.catalog.compare("d", 1, 2, keys=["id"])

    def test_ragged_stored_csv_rejected(self):
        self.catalog.import_csv("r", self.csv_file("a,b\n1,2,3\n"))
        with self.assertRaises(ValueError):
            self.catalog.compare("r", 1, 1, keys=["a"])

    def test_compare_does_not_modify_state(self):
        self.import_pair("id,v\n1,a\n", "id,v\n1,b\n")
        before = self.catalog.state_path.read_bytes()
        self.catalog.compare("d", 1, 2, keys=["id"])
        self.assertEqual(self.catalog.state_path.read_bytes(), before)


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

    def test_compare_keys_option(self):
        left = self.root / "left.csv"
        right = self.root / "right.csv"
        left.write_text("id,v\n1,a\n2,b\n", encoding="utf-8")
        right.write_text("id,v\n1,a\n2,c\n3,d\n", encoding="utf-8")
        self.assertEqual(self.run_cli("import", "k", str(left)).returncode, 0)
        self.assertEqual(self.run_cli("import", "k", str(right)).returncode, 0)

        # without --keys the response has no rowDiff
        result = self.run_cli("compare", "k", "1", "2")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("rowDiff", json.loads(result.stdout))

        # single and multiple keys
        result = self.run_cli("compare", "k", "1", "2", "--keys", "id")
        self.assertEqual(result.returncode, 0, result.stderr)
        diff = json.loads(result.stdout)["rowDiff"]
        self.assertEqual(diff["added"], [{"key": ["3"], "row": 3, "values": {"id": "3", "v": "d"}}])
        self.assertEqual(diff["modified"][0]["key"], ["2"])
        self.assertEqual(diff["unchangedCount"], 1)
        result = self.run_cli("compare", "k", "1", "2", "--keys", "id", "v")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["rowDiff"]["unchangedCount"], 1)

        # invalid key and tampered blob fail with the stderr envelope, exit 2
        result = self.run_cli("compare", "k", "1", "2", "--keys", "missing")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})

        # hash verification on a same-version keyed comparison
        result = self.run_cli("compare", "k", "1", "1", "--keys", "id")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(self.run_cli("list").stdout)["k"][0]
        (self.workspace / record["blob"]).write_text("id,v\n9,z\n", encoding="utf-8")
        result = self.run_cli("compare", "k", "1", "1", "--keys", "id")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})


if __name__ == "__main__":
    unittest.main()
