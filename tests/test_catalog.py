import csv as csv_module
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from governance_workbench import Catalog
from governance_workbench.catalog import _read_csv_records

REPO_ROOT = Path(__file__).resolve().parents[1]


def legacy_import(catalog: Catalog, dataset: str, contents: str) -> str:
    """Simulate a version stored by a pre-strictness build.

    Writes the bytes directly to the content-addressed blob directory and
    appends a catalog record using the old, permissive inference rules, so
    tests can exercise how downstream stages handle legacy ragged data
    without going through the now-strict importer.
    """
    import csv as csv_module
    import hashlib

    from governance_workbench.catalog import _kind, _merge_kinds

    data = contents.encode("utf-8")
    content_hash = hashlib.sha256(data).hexdigest()
    catalog.blobs.mkdir(parents=True, exist_ok=True)
    blob = catalog.blobs / f"{content_hash}.csv"
    blob.write_bytes(data)

    reader = csv_module.DictReader(io.StringIO(contents, newline=""))
    fieldnames = reader.fieldnames or []
    observed = {name: set() for name in fieldnames}
    row_count = 0
    for row in reader:
        row_count += 1
        for name in fieldnames:
            observed[name].add(_kind(row[name] or ""))

    state = catalog._load()
    versions = state["datasets"].setdefault(dataset, [])
    versions.append(
        {
            "dataset": dataset,
            "version": len(versions) + 1,
            "source_name": "legacy.csv",
            "content_sha256": content_hash,
            "row_count": row_count,
            "schema": {name: _merge_kinds(kinds) for name, kinds in observed.items()},
            "imported_at": "2000-01-01T00:00:00+00:00",
            "blob": str(blob.relative_to(catalog.workspace)),
        }
    )
    catalog._save(state)
    return content_hash


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


class StrictImportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, contents, name: str = "data.csv") -> Path:
        path = self.root / name
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        return path

    def reject(self, contents):
        path = self.write(contents)
        with self.assertRaises(ValueError) as context:
            self.catalog.import_csv("d", path)
        return str(context.exception)

    # ---- validity rules with distinct reasons ----------------------------

    def test_invalid_files_rejected_with_distinct_reasons(self):
        cases = {
            "no header (empty file)": "",
            "empty header field": "a,\n1,2\n",
            "duplicate header field": "a,a\n1,2\n",
            "record too short": "a,b\n1\n",
            "record too long": "a,b\n1,2,3\n",
            "unclosed quote": 'a,b\n1,"unclosed\n',
        }
        messages = set()
        for label, contents in cases.items():
            message = self.reject(contents)
            self.assertTrue(message, label)
            self.assertNotIn(str(self.root), message)
            messages.add(message)
        self.assertEqual(len(messages), len(cases))

        # invalid UTF-8
        path = self.write(b"a,b\n1,\xff\n")
        with self.assertRaises(ValueError) as context:
            self.catalog.import_csv("d", path)
        self.assertIn("UTF-8", str(context.exception))
        messages.add(str(context.exception))

        # parse error: a field over the reader's size limit is a csv.Error
        path = self.write("a\n" + ("x" * 100) + "\n")
        previous_limit = csv_module.field_size_limit()
        try:
            csv_module.field_size_limit(10)
            with self.assertRaises(ValueError) as context:
                self.catalog.import_csv("d", path)
        finally:
            csv_module.field_size_limit(previous_limit)
        self.assertIn("could not be parsed", str(context.exception))

    def test_field_count_error_names_record_number_actual_and_expected(self):
        # blank physical lines are skipped; the quoted newline stays in record 1,
        # so the ragged line is data record 2
        path = self.write('a,b\n\n1,"line one\nline two"\n2,3,4\n')
        with self.assertRaises(ValueError) as context:
            self.catalog.import_csv("d", path)
        message = str(context.exception)
        self.assertIn("data record 2", message)
        self.assertIn("3 field(s)", message)
        self.assertIn("expected 2", message)

        # a short record reports its own number and actual count
        path = self.write("a,b,c\n1,2,3\n4\n")
        with self.assertRaises(ValueError) as context:
            self.catalog.import_csv("d", path)
        message = str(context.exception)
        self.assertIn("data record 2", message)
        self.assertIn("1 field(s)", message)
        self.assertIn("expected 3", message)

    # ---- accepted shapes --------------------------------------------------

    def test_header_only_file_imports_with_zero_rows_and_null_types(self):
        record = self.catalog.import_csv("d", self.write("a,b\n"))
        self.assertEqual(record.row_count, 0)
        self.assertEqual(record.schema, {"a": "null", "b": "null"})
        rows = self.catalog.list_datasets()["d"]
        self.assertEqual(len(rows), 1)

    def test_blank_lines_and_quoted_newlines_match_record_semantics(self):
        contents = 'id,name\n\n1,"line one\nline two"\n\n2,Bob\n'
        record = self.catalog.import_csv("d", self.write(contents))
        self.assertEqual(record.row_count, 2)

    def test_empty_vs_whitespace_inference_and_quote_then_text_kept(self):
        record = self.catalog.import_csv(
            "d", self.write("id,v,w\n1,,s\n2, ,\"x\"y\n")
        )
        # "" is missing/null, " " is a whitespace string; "x"y parses as xy
        self.assertEqual(record.schema, {"id": "integer", "v": "string", "w": "string"})
        _, rows = _read_csv_records((self.catalog.workspace / record.blob).read_bytes())
        self.assertEqual(rows[0][1], "")
        self.assertEqual(rows[1][1], " ")
        self.assertEqual(rows[1][2], "xy")

    def test_stored_bytes_match_source_exactly(self):
        contents = 'id,name\r\n1, "Ada" \r\n2,"line one\nline two"\r\n'
        source = self.write(contents)
        record = self.catalog.import_csv("d", source)
        stored = (self.catalog.workspace / record.blob).read_bytes()
        # newlines, spacing and quoting are preserved byte-for-byte
        self.assertEqual(stored, contents.encode("utf-8"))
        self.assertEqual(record.content_sha256, hashlib.sha256(stored).hexdigest())

    def test_later_source_change_does_not_affect_version(self):
        source = self.write("id,v\n1,5\n")
        record = self.catalog.import_csv("d", source)
        source.write_text("id,v\n9,999\n", encoding="utf-8")
        reloaded = Catalog(self.catalog.workspace)
        stored = (reloaded.workspace / record.blob).read_bytes()
        self.assertEqual(stored, b"id,v\n1,5\n")
        self.assertEqual(reloaded.get("d", 1)["content_sha256"], record.content_sha256)

    def test_source_replaced_during_import_cannot_desynchronize_version(self):
        # The file on disk (B, ragged) differs from the bytes the importer
        # snapshots at read time (A). The stored blob and record must both
        # describe A; the old code re-read the path while copying and ended
        # up storing B under A's description.
        valid = b"id,v\n1,5\n"
        source = self.write(b"id,v\n1,5,extra\n")
        real_open = Path.open

        def snapshot_open(path, *args, **kwargs):
            if Path(path) == source:
                return io.BytesIO(valid)
            return real_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", snapshot_open):
            record = self.catalog.import_csv("d", source)
        stored = (self.catalog.workspace / record.blob).read_bytes()
        self.assertEqual(stored, valid)
        self.assertEqual(record.content_sha256, hashlib.sha256(valid).hexdigest())
        export_dir = self.root / "out"
        self.catalog.export("d", 1, export_dir)
        self.assertTrue(Catalog(self.root / "offline").verify_export(export_dir)["passed"])

    # ---- content-addressed storage ---------------------------------------

    def test_repeated_imports_append_versions_but_share_blob(self):
        source = self.write("id,v\n1,5\n")
        first = self.catalog.import_csv("d", source)
        second = self.catalog.import_csv("d", source)
        third = self.catalog.import_csv("d", source)
        self.assertEqual([r["version"] for r in self.catalog.list_datasets()["d"]], [1, 2, 3])
        self.assertEqual({first.blob, second.blob, third.blob}, {first.blob})
        self.assertEqual(
            first.content_sha256,
            self.catalog.get("d", 3)["content_sha256"],
        )

    def test_existing_matching_blob_is_reused(self):
        data = b"id,v\n1,5\n"
        content_hash = hashlib.sha256(data).hexdigest()
        self.catalog.blobs.mkdir(parents=True, exist_ok=True)
        existing = self.catalog.blobs / f"{content_hash}.csv"
        existing.write_bytes(data)
        record = self.catalog.import_csv("d", self.write(data.decode("utf-8")))
        self.assertEqual(record.blob, str(existing.relative_to(self.catalog.workspace)))
        self.assertEqual(existing.read_bytes(), data)

    def test_corrupt_existing_blob_errors_and_is_not_overwritten(self):
        data = b"id,v\n1,5\n"
        content_hash = hashlib.sha256(data).hexdigest()
        self.catalog.blobs.mkdir(parents=True, exist_ok=True)
        damaged = self.catalog.blobs / f"{content_hash}.csv"
        damaged.write_bytes(b"id,v\n9,9\n")
        with self.assertRaises(OSError):
            self.catalog.import_csv("d", self.write(data.decode("utf-8")))
        # the corrupt file is untouched and no version appeared
        self.assertEqual(damaged.read_bytes(), b"id,v\n9,9\n")
        self.assertEqual(self.catalog.list_datasets(), {})
        # once storage is repaired, reuse succeeds
        damaged.write_bytes(data)
        record = self.catalog.import_csv("d", self.write(data.decode("utf-8")))
        self.assertEqual(record.version, 1)
        self.assertEqual(record.content_sha256, content_hash)

    # ---- failure atomicity ------------------------------------------------

    def test_invalid_data_creates_nothing_and_consumes_no_version(self):
        self.reject("a,b\n1,2,3\n")
        self.assertFalse(self.catalog.state_path.exists())
        self.assertEqual(self.catalog.list_datasets(), {})
        # no stray temporary files in the blob directory
        leftovers = list(self.catalog.blobs.glob("*.tmp")) if self.catalog.blobs.exists() else []
        self.assertEqual(leftovers, [])
        # retry uses the original next version number
        record = self.catalog.import_csv("d", self.write("a,b\n1,2\n", "good.csv"))
        self.assertEqual(record.version, 1)

    def test_failed_import_after_good_version_consumes_no_version(self):
        self.catalog.import_csv("d", self.write("a,b\n1,2\n", "v1.csv"))
        self.reject("a,b\n1,2,3\n")
        record = self.catalog.import_csv("d", self.write("a,b\n3,4\n", "v2.csv"))
        self.assertEqual(record.version, 2)
        self.assertEqual(len(self.catalog.list_datasets()["d"]), 2)

    def test_blob_write_failure_leaves_no_blob_and_no_version(self):
        with mock.patch.object(tempfile, "mkstemp", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.catalog.import_csv("d", self.write("a,b\n1,2\n"))
        self.assertFalse(self.catalog.state_path.exists())
        self.assertEqual(list(self.catalog.blobs.iterdir()), [])
        record = self.catalog.import_csv("d", self.write("a,b\n1,2\n"))
        self.assertEqual(record.version, 1)

    def test_state_write_failure_leaves_no_version_but_blob_remains(self):
        with mock.patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.catalog.import_csv("d", self.write("a,b\n1,2\n"))
        self.assertEqual(self.catalog.list_datasets(), {})
        # the orphaned blob is content-addressed and verified on reuse
        record = self.catalog.import_csv("d", self.write("a,b\n1,2\n"))
        self.assertEqual(record.version, 1)

    def test_missing_and_unreadable_source_raise_oserror(self):
        with self.assertRaises(OSError):
            self.catalog.import_csv("d", self.root / "missing.csv")
        source = self.write("a,b\n1,2\n")
        real_open = Path.open

        def deny_open(path, *args, **kwargs):
            if Path(path) == source:
                raise PermissionError("denied")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", deny_open):
            with self.assertRaises(OSError):
                self.catalog.import_csv("d", source)
        self.assertEqual(self.catalog.list_datasets(), {})

    def test_failed_import_invisible_after_restart(self):
        self.reject("a,b\n1,2,3\n")
        reloaded = Catalog(self.catalog.workspace)
        self.assertEqual(reloaded.list_datasets(), {})

    # ---- round trip --------------------------------------------------------

    def test_imported_version_exports_and_verifies(self):
        contents = 'id,name\n1,"Ada"\n2,"Bo\nby"\n'
        self.catalog.import_csv("d", self.write(contents))
        export_dir = self.root / "out"
        self.catalog.export("d", 1, export_dir)
        report = Catalog(self.root / "offline").verify_export(export_dir)
        self.assertTrue(report["passed"], report["issues"])


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
        legacy_import(self.catalog, "ragged", "a,b\n1,2,3\n")
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
        legacy_import(self.catalog, "r", "a,b\n1,2,3\n")
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

    def test_import_strictness_envelope_and_exit_codes(self):
        # success still prints the full record on stdout
        result = self.run_cli("import", "d", str(self.root / "good.csv"))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        record = json.loads(result.stdout)
        self.assertEqual(record["version"], 1)
        self.assertEqual(record["row_count"], 1)
        self.assertEqual(record["schema"], {"id": "integer", "v": "integer"})

        ragged = self.root / "ragged.csv"
        ragged.write_text("id,v\n1,2,3\n", encoding="utf-8")
        for path, label in (
            (ragged, "ragged rows"),
            (self.root / "missing.csv", "missing source"),
        ):
            result = self.run_cli("import", "d", str(path))
            self.assertEqual(result.returncode, 2, label)
            self.assertEqual(result.stdout, "", label)
            self.assertEqual(result.stderr.count("\n"), 1, label)
            payload = json.loads(result.stderr)
            self.assertEqual(set(payload), {"error"}, label)
            self.assertTrue(payload["error"], label)

        # header problems fail the same way
        no_header = self.root / "empty.csv"
        no_header.write_text("", encoding="utf-8")
        result = self.run_cli("import", "d", str(no_header))
        self.assertEqual(result.returncode, 2)
        self.assertIn("header", json.loads(result.stderr)["error"])

        # failures consumed no version number and left no success output;
        # the next successful import is version 2
        result = self.run_cli("import", "d", str(self.root / "good.csv"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["version"], 2)
        datasets = json.loads(self.run_cli("list").stdout)
        self.assertEqual(len(datasets["d"]), 2)

    def test_imported_export_passes_verify_export_unchanged(self):
        result = self.run_cli("import", "d", str(self.root / "good.csv"))
        self.assertEqual(result.returncode, 0)
        export_dir = self.root / "out"
        self.assertEqual(self.run_cli("export", "d", "1", str(export_dir)).returncode, 0)
        result = self.run_cli("verify-export", str(export_dir))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["passed"])

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


class VerifyExportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")
        # A catalog rooted at a workspace that never exists; verification must
        # never consult workspace state.
        self.offline = Catalog(self.root / "never-created-workspace")

    def tearDown(self):
        self.temporary.cleanup()

    def write_csv(self, name: str, contents) -> Path:
        path = self.root / name
        if isinstance(contents, str):
            path.write_text(contents, encoding="utf-8")
        else:
            path.write_bytes(contents)
        return path

    def export_dir(self, dataset="events", version=1, destination="export"):
        return self.root / destination

    def load_manifest(self, directory: Path):
        return json.loads((directory / "manifest.json").read_text(encoding="utf-8"))

    def save_manifest(self, directory: Path, manifest):
        (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def export_simple(self, csv_contents="id,active,score\n1,true,2.5\n2,false,3\n"):
        self.catalog.import_csv("events", self.write_csv("events.csv", csv_contents))
        directory = self.root / "export"
        self.catalog.export("events", 1, directory)
        return directory

    def rewrite_data(self, directory: Path, contents, fix_hash=False, file_name=None):
        manifest = self.load_manifest(directory)
        data_name = file_name or manifest["file"]
        path = directory / data_name
        if isinstance(contents, str):
            path.write_text(contents, encoding="utf-8")
        else:
            path.write_bytes(contents)
        if fix_hash:
            import hashlib

            manifest["record"]["content_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            self.save_manifest(directory, manifest)
        return manifest

    # ---- passing reports -------------------------------------------------

    def test_plain_export_verifies_offline(self):
        directory = self.export_simple()
        report = self.offline.verify_export(directory)
        self.assertEqual(
            report, {"dataset": "events", "version": 1, "passed": True, "issues": []}
        )

    def test_header_only_is_zero_records(self):
        self.catalog.import_csv("events", self.write_csv("h.csv", "id,name\n"))
        directory = self.root / "export"
        self.catalog.export("events", 1, directory)
        report = self.offline.verify_export(directory)
        self.assertTrue(report["passed"], report["issues"])

    def test_blank_physical_lines_and_quoted_newlines_do_not_add_records(self):
        contents = 'id,name\n\n1,"line one\nline two"\n\n2,Bob\n'
        directory = self.export_simple(contents)
        manifest = self.load_manifest(directory)
        self.assertEqual(manifest["record"]["row_count"], 2)
        report = self.offline.verify_export(directory)
        self.assertTrue(report["passed"], report["issues"])

    def test_cleaned_export_with_lineage_verifies(self):
        self.catalog.import_csv("p", self.write_csv("p.csv", "id,name\n1, Ada \n"))
        self.catalog.clean("p", 1, [{"type": "trim", "column": "name"}])
        directory = self.root / "cleaned"
        self.catalog.export("p", 2, directory)
        report = self.offline.verify_export(directory)
        self.assertTrue(report["passed"], report["issues"])

    def test_unknown_extra_manifest_fields_ignored(self):
        directory = self.export_simple()
        manifest = self.load_manifest(directory)
        manifest["extra"] = {"nested": [1, 2]}
        manifest["record"]["unexpected"] = 42
        self.save_manifest(directory, manifest)
        report = self.offline.verify_export(directory)
        self.assertTrue(report["passed"], report["issues"])

    # ---- issue categories -------------------------------------------------

    def test_missing_data_file(self):
        directory = self.export_simple()
        (directory / "events-v1.csv").unlink()
        report = self.offline.verify_export(directory)
        self.assertFalse(report["passed"])
        self.assertEqual([i["code"] for i in report["issues"]], ["missing"])
        self.assertEqual(set(report["issues"][0]), {"code", "message"})

    def test_hash_mismatch(self):
        directory = self.export_simple()
        self.rewrite_data(directory, "id,active,score\n1,true,2.5\n2,false,9\n")
        report = self.offline.verify_export(directory)
        self.assertEqual([i["code"] for i in report["issues"]], ["hash"])

    def test_structure_problems(self):
        def expect(contents, fix_hash=True, raw=False):
            directory = self.export_simple()
            self.rewrite_data(directory, contents, fix_hash=fix_hash)
            codes = [i["code"] for i in self.offline.verify_export(directory)["issues"]]
            self.assertIn("csv", codes, contents)

        expect("id,id\n1,2\n")  # duplicate headers
        expect("id,\n1,2\n")  # empty header field
        expect("id,a\n1,2,3\n")  # ragged record
        expect('id,a\n1,"unclosed\n')  # unclosed quote
        expect(b"id,a\n1,\xff\n", raw=True)  # invalid UTF-8

    def test_no_header_row_is_structure_error(self):
        directory = self.export_simple()
        self.rewrite_data(directory, "", fix_hash=True)
        report = self.offline.verify_export(directory)
        self.assertEqual([i["code"] for i in report["issues"]], ["csv"])

    def test_row_count_mismatch(self):
        directory = self.export_simple()
        manifest = self.rewrite_data(
            directory, "id,active,score\n1,true,2.5\n", fix_hash=True
        )
        # manifest still says 2 rows, file now has 1
        self.assertEqual(manifest["record"]["row_count"], 2)
        report = self.offline.verify_export(directory)
        self.assertEqual([i["code"] for i in report["issues"]], ["rows"])

    def test_schema_field_and_type_mismatch(self):
        directory = self.export_simple()
        # renamed field
        self.rewrite_data(directory, "id,active,rating\n1,true,2.5\n2,false,3\n", fix_hash=True)
        report = self.offline.verify_export(directory)
        self.assertEqual([i["code"] for i in report["issues"]], ["schema"])
        self.assertIn("rating", report["issues"][0]["message"])

        # type change: score widens from number to text, same hash recorded
        directory2 = self.root / "typed2"
        self.catalog.import_csv("s", self.write_csv("s.csv", "id,score\n1,2.5\n2,3\n"))
        self.catalog.export("s", 1, directory2)
        self.rewrite_data(directory2, "id,score\n1,2.5\n2,abc\n", fix_hash=True)
        report = self.offline.verify_export(directory2)
        self.assertEqual([i["code"] for i in report["issues"]], ["schema"])
        self.assertIn("'number'", report["issues"][0]["message"])

    def test_type_inference_matches_import_semantics(self):
        # integer column widening to text yields string mismatch
        directory = self.root / "typed"
        self.catalog.import_csv("t", self.write_csv("t.csv", "v\n1\n2\n"))
        self.catalog.export("t", 1, directory)
        self.rewrite_data(directory, "v\n1\nabc\n", fix_hash=True)
        report = self.offline.verify_export(directory)
        self.assertEqual([i["code"] for i in report["issues"]], ["schema"])
        self.assertIn("infers as 'string'", report["issues"][0]["message"])

    def test_importer_tolerated_quoting_is_not_a_structure_error(self):
        # Non-strict reader accepts text immediately after a closing quote,
        # exactly as import does; verification must not reject it.
        directory = self.root / "quoted"
        self.catalog.import_csv("q", self.write_csv("q.csv", "id,n\n1,\"x\"y\n"))
        self.catalog.export("q", 1, directory)
        report = self.offline.verify_export(directory)
        self.assertTrue(report["passed"], report["issues"])

    # ---- lineage ----------------------------------------------------------

    def test_missing_or_empty_lineage_is_accepted(self):
        directory = self.export_simple()
        for lineage in (None, []):
            manifest = self.load_manifest(directory)
            if lineage is None:
                manifest.pop("lineage", None)
            else:
                manifest["lineage"] = lineage
            self.save_manifest(directory, manifest)
            self.assertTrue(self.offline.verify_export(directory)["passed"])

    def test_lineage_chain_mismatches_reported(self):
        directory = self.export_simple()
        manifest = self.load_manifest(directory)
        record_hash = manifest["record"]["content_sha256"]
        # A valid-shaped single entry whose links contradict the v1 record.
        manifest["lineage"] = [
            {
                "dataset": "events",
                "version": 2,
                "sourceVersion": 1,
                "sourceSha256": "a" * 64,
                "contentSha256": record_hash,
                "rowCount": 99,
            }
        ]
        self.save_manifest(directory, manifest)
        report = self.offline.verify_export(directory)
        codes = [i["code"] for i in report["issues"]]
        self.assertTrue(codes and all(code == "lineage" for code in codes))

    def test_lineage_same_dataset_and_descending_versions_required(self):
        directory = self.export_simple()
        manifest = self.load_manifest(directory)
        manifest["lineage"] = [
            {
                "dataset": "other",
                "version": 1,
                "sourceVersion": 1,  # not below version
                "sourceSha256": "a" * 64,
                "contentSha256": "b" * 64,
                "rowCount": 2,
            }
        ]
        self.save_manifest(directory, manifest)
        issues = self.offline.verify_export(directory)["issues"]
        self.assertTrue(all(i["code"] == "lineage" for i in issues))
        self.assertGreaterEqual(len(issues), 2)

    def test_lineage_adjacent_entries_must_link(self):
        directory = self.export_simple()
        manifest = self.load_manifest(directory)
        record_hash = manifest["record"]["content_sha256"]
        manifest["lineage"] = [
            {
                "dataset": "events",
                "version": 2,
                "sourceVersion": 1,
                "sourceSha256": "a" * 64,
                "contentSha256": "c" * 64,
                "rowCount": 2,
            },
            {
                "dataset": "events",
                "version": 3,
                "sourceVersion": 2,
                "sourceSha256": "d" * 64,  # does not equal prior contentSha256
                "contentSha256": record_hash,
                "rowCount": 2,
            },
        ]
        self.save_manifest(directory, manifest)
        report = self.offline.verify_export(directory)
        self.assertTrue(any("hash" in i["message"] for i in report["issues"]))
        self.assertTrue(all(i["code"] == "lineage" for i in report["issues"]))

    def test_malformed_lineage_entry_reported(self):
        directory = self.export_simple()
        manifest = self.load_manifest(directory)
        manifest["lineage"] = [{"dataset": "events"}, "not-an-object"]
        self.save_manifest(directory, manifest)
        report = self.offline.verify_export(directory)
        self.assertTrue(all(i["code"] == "lineage" for i in report["issues"]))
        self.assertEqual(len(report["issues"]), 2)

    # ---- ordering ----------------------------------------------------------

    def test_issues_ordered_missing_hash_csv_rows_schema_lineage(self):
        directory = self.export_simple()
        (directory / "events-v1.csv").unlink()  # missing
        manifest = self.load_manifest(directory)
        manifest["lineage"] = [{"dataset": "events"}]  # lineage problem
        self.save_manifest(directory, manifest)
        codes = [i["code"] for i in self.offline.verify_export(directory)["issues"]]
        self.assertEqual(codes, ["missing", "lineage"])

        directory2 = self.root / "multi"
        self.catalog.import_csv("m", self.write_csv("m.csv", "a,b\n1,2\n3,4\n"))
        self.catalog.export("m", 1, directory2)
        # tamper bytes (hash), make ragged (csv), claim wrong row count (rows),
        # and the field/type checks follow
        (directory2 / "m-v1.csv").write_text("a,b,c\n1,2\nbad\n", encoding="utf-8")
        manifest2 = self.load_manifest(directory2)
        manifest2["record"]["row_count"] = 99
        self.save_manifest(directory2, manifest2)
        codes = [i["code"] for i in self.offline.verify_export(directory2)["issues"]]
        self.assertEqual(codes[0], "hash")
        self.assertEqual(codes, ["hash", "csv", "rows", "schema"])

    # ---- manifest and parameter errors ------------------------------------

    def test_manifest_errors_raise_value_error(self):
        directory = self.export_simple()

        def reject(rewrite):
            rewrite(directory)
            with self.assertRaises(ValueError):
                self.offline.verify_export(directory)
            # restore a valid manifest between cases
            self.catalog.export("events", 1, directory)

        reject(lambda d: (d / "manifest.json").write_text("{not json", encoding="utf-8"))
        reject(lambda d: (d / "manifest.json").write_text("[]", encoding="utf-8"))
        reject(
            lambda d: self.save_manifest(
                d, {"schemaVersion": 2, "record": {}, "file": "x"}
            )
        )
        reject(
            lambda d: self.save_manifest(
                d, {"schemaVersion": 1.0, "record": {}, "file": "x"}
            )
        )
        reject(
            lambda d: self.save_manifest(
                d, {"schemaVersion": True, "record": {}, "file": "x"}
            )
        )
        reject(lambda d: self.save_manifest(d, {"schemaVersion": 1, "file": "x"}))
        reject(lambda d: self.save_manifest(d, {"schemaVersion": 1, "record": {}}))

        def record_mutation(mutate):
            def do(d):
                manifest = self.load_manifest(d)
                mutate(manifest["record"])
                self.save_manifest(d, manifest)
            return do

        reject(record_mutation(lambda r: r.update(version=0)))
        reject(record_mutation(lambda r: r.update(version=True)))
        reject(record_mutation(lambda r: r.update(version=1.5)))
        reject(record_mutation(lambda r: r.update(row_count=-1)))
        reject(record_mutation(lambda r: r.update(row_count=True)))
        reject(record_mutation(lambda r: r.update(content_sha256="A" * 64)))
        reject(record_mutation(lambda r: r.update(content_sha256="abc")))
        reject(record_mutation(lambda r: r.update(dataset="")))
        reject(record_mutation(lambda r: r.update(schema={})))
        reject(record_mutation(lambda r: r.__setitem__("schema", {"id": "datetime"})))

        def file_name(value):
            def do(d):
                manifest = self.load_manifest(d)
                manifest["file"] = value
                self.save_manifest(d, manifest)
            return do

        reject(file_name(""))
        reject(file_name("."))
        reject(file_name(".."))
        reject(file_name("a/b.csv"))
        reject(file_name("a\\b.csv"))
        reject(file_name(3))

        # invalid UTF-8 manifest
        def bad_utf8(d):
            (d / "manifest.json").write_bytes(b'{"schemaVersion": 1, "x": \xff}')
        reject(bad_utf8)
        # the restored manifest is still usable
        self.assertTrue(self.offline.verify_export(directory)["passed"])

    def test_missing_manifest_raises_os_error(self):
        directory = self.export_simple()
        (directory / "manifest.json").unlink()
        with self.assertRaises(OSError):
            self.offline.verify_export(directory)

    def test_missing_export_directory_raises_os_error(self):
        with self.assertRaises(OSError):
            self.offline.verify_export(self.root / "no-such-directory")

    def test_path_traversal_rejected_before_reading_target(self):
        directory = self.export_simple()
        outside = self.root / "outside.csv"
        outside.write_bytes((directory / "events-v1.csv").read_bytes())
        for name in ("../outside.csv", "sub/../x", "..\\outside.csv"):
            manifest = self.load_manifest(directory)
            manifest["file"] = name
            self.save_manifest(directory, manifest)
            with self.assertRaises(ValueError):
                self.offline.verify_export(directory)

    def test_symlink_outside_directory_rejected(self):
        directory = self.export_simple()
        outside = self.root / "outside.csv"
        outside.write_bytes(b"id,active,score\n1,true,2.5\n2,false,3\n")
        data = directory / "events-v1.csv"
        data.unlink()
        data.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.offline.verify_export(directory)

    def test_verification_writes_nothing_and_is_repeatable(self):
        directory = self.export_simple()
        snapshot = {
            path.name: path.read_bytes() for path in directory.iterdir()
        }
        first = self.offline.verify_export(directory)
        second = self.offline.verify_export(directory)
        self.assertEqual(first, second)
        self.assertEqual(
            snapshot, {path.name: path.read_bytes() for path in directory.iterdir()}
        )

    def test_report_has_no_machine_paths(self):
        directory = self.export_simple()
        (directory / "events-v1.csv").unlink()
        report = self.offline.verify_export(directory)
        rendered = json.dumps(report)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn(str(directory), rendered)


class CliVerifyExportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "ws"
        self.catalog = Catalog(self.workspace)
        source = self.root / "events.csv"
        source.write_text("id,active,score\n1,true,2.5\n2,false,3\n", encoding="utf-8")
        self.catalog.import_csv("events", source)
        self.directory = self.root / "export"
        self.catalog.export("events", 1, self.directory)

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "governance_workbench",
                "--workspace",
                str(self.workspace),
                *arguments,
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_passing_verify_exit_0(self):
        result = self.run_cli("verify-export", str(self.directory))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["passed"])
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["dataset"], "events")
        self.assertEqual(report["version"], 1)

    def test_failing_verify_exit_1_with_report_on_stdout(self):
        (self.directory / "events-v1.csv").unlink()
        result = self.run_cli("verify-export", str(self.directory))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertFalse(report["passed"])
        self.assertEqual([i["code"] for i in report["issues"]], ["missing"])

    def test_manifest_error_exit_2_stderr_envelope(self):
        (self.directory / "manifest.json").write_text("{bad json", encoding="utf-8")
        result = self.run_cli("verify-export", str(self.directory))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})

    def test_missing_export_dir_exit_2(self):
        result = self.run_cli("verify-export", str(self.root / "gone"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})


class ReferenceRuleTest(unittest.TestCase):
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

    def import_customers(self, contents="编号,地区\n1,EU\n2,APAC\n"):
        return self.catalog.import_csv("客户", self.csv_file(contents, "customers.csv"))

    def import_orders(
        self,
        contents="客户号,地区,金额\n1,EU,10\n2,APAC,20\n3,US,30\n,EU,40\n1,US,50\n3,US,60\n",
    ):
        return self.catalog.import_csv("订单", self.csv_file(contents, "orders.csv"))

    def reference_rule(
        self,
        identifier="客户引用",
        columns=("客户号", "地区"),
        dataset="客户",
        version=1,
        ref_columns=("编号", "地区"),
    ):
        return {
            "id": identifier,
            "type": "reference",
            "columns": list(columns),
            "reference": {
                "dataset": dataset,
                "version": version,
                "columns": list(ref_columns),
            },
        }

    def test_reference_validation_reports_missing_and_empty_combinations(self):
        customers = self.import_customers()
        self.import_orders()
        self.catalog.set_rules("订单", [self.reference_rule()])
        report = self.catalog.validate("订单", 1)
        self.assertFalse(report["passed"])
        result = report["results"][0]
        self.assertEqual(result["id"], "客户引用")
        self.assertEqual(result["type"], "reference")
        self.assertEqual(result["columns"], ["客户号", "地区"])
        self.assertEqual(
            result["reference"],
            {
                "dataset": "客户",
                "version": 1,
                "columns": ["编号", "地区"],
                "content_sha256": customers.content_sha256,
            },
        )
        # rows 3 (3,US), 4 (empty 客户号), 5 (1,US), 6 (3,US, repeated)
        self.assertEqual(result["violations"], [3, 4, 5, 6])
        self.assertEqual(result["violationCount"], 4)
        self.assertNotIn("column", result)
        self.assertRegex(result["reference"]["content_sha256"], r"^[0-9a-f]{64}$")

    def test_raw_string_matching_positional_composite_columns(self):
        # no trimming, no numeric conversion, separators inside values literal
        self.import_customers('编号,地区\n1,EU\n"01",APAC\n" 1",EU\n1,"EU,APAC"\n')
        self.import_orders(
            '客户号,地区,金额\n'
            '1,EU,10\n'          # row 1: exact match
            '01,APAC,20\n'       # row 2: "01" != "01"? here it matches the quoted ref
            '1,APAC,30\n'        # row 3: "1" != " 1" and region differs
            '1,"EU,APAC",40\n'   # row 4: separator inside value is literal
        )
        self.catalog.set_rules("订单", [self.reference_rule()])
        report = self.catalog.validate("订单", 1)
        self.assertEqual(report["results"][0]["violations"], [3])

    def test_header_only_reference_makes_every_validated_row_violate(self):
        self.import_customers("编号,地区\n")
        self.import_orders()
        self.catalog.set_rules("订单", [self.reference_rule()])
        report = self.catalog.validate("订单", 1)
        self.assertEqual(report["results"][0]["violations"], [1, 2, 3, 4, 5, 6])
        self.assertFalse(report["passed"])

    def test_two_record_less_sides_pass(self):
        self.import_customers("编号,地区\n")
        self.import_orders("客户号,地区,金额\n")
        self.catalog.set_rules("订单", [self.reference_rule()])
        report = self.catalog.validate("订单", 1)
        self.assertTrue(report["passed"])
        self.assertEqual(report["results"][0]["violations"], [])
        self.assertEqual(report["rowCount"], 0)

    def test_empty_reference_value_fails_whole_validation_even_without_rows(self):
        self.import_customers("编号,地区\n1,EU\n,APAC\n")
        self.import_orders("客户号,地区,金额\n")  # header-only validated side
        self.catalog.set_rules("订单", [self.reference_rule()])
        with self.assertRaises(ValueError):
            self.catalog.validate("订单", 1)

    def test_duplicate_reference_combination_fails_whole_validation(self):
        self.import_customers("编号,地区\n1,EU\n1,EU\n")
        self.import_orders("客户号,地区,金额\n")
        self.catalog.set_rules("订单", [self.reference_rule()])
        with self.assertRaises(ValueError):
            self.catalog.validate("订单", 1)

    def test_configuration_checks_reference_dataset_version_and_columns(self):
        self.import_customers()
        # missing dataset
        with self.assertRaises(ValueError):
            self.catalog.set_rules("订单", [self.reference_rule(dataset="不存在")])
        # missing version
        with self.assertRaises(ValueError):
            self.catalog.set_rules("订单", [self.reference_rule(version=9)])
        # missing reference column
        with self.assertRaises(ValueError):
            self.catalog.set_rules(
                "订单", [self.reference_rule(ref_columns=("编号", "不存在"))]
            )
        # no revision was consumed
        self.assertEqual(self.catalog.list_datasets().get("订单"), None)

    def test_configuration_accepts_cleaned_version_and_self_reference(self):
        self.import_customers()
        # a cleaned version of the reference dataset is a valid reference side
        self.catalog.clean("客户", 1, [{"type": "rename", "column": "编号", "to": "客户编号"}])
        self.import_orders()
        rule = self.reference_rule(version=2, ref_columns=("客户编号", "地区"))
        result = self.catalog.set_rules("订单", [rule])
        self.assertEqual(result["revision"], 1)
        # a dataset may reference one of its own versions
        self.catalog.set_rules(
            "客户",
            [self.reference_rule(columns=("编号",), ref_columns=("编号",))],
        )
        report = self.catalog.validate("客户", 1)
        self.assertTrue(report["passed"])

    def test_configuration_shape_rejected(self):
        self.import_customers()

        def reject(rule):
            with self.assertRaises(ValueError):
                self.catalog.set_rules("订单", [rule])

        base = self.reference_rule()
        reject({k: v for k, v in base.items() if k != "columns"})  # missing columns
        reject({k: v for k, v in base.items() if k != "reference"})  # missing reference
        reject({**base, "extra": 1})  # extra attribute
        reject({**base, "columns": []})  # empty columns
        reject({**base, "columns": [""]})  # empty column name
        reject({**base, "columns": [1]})  # non-string column
        reject({**base, "columns": ["客户号", "客户号"]})  # duplicate columns
        reject({**base, "reference": "客户"})  # reference not an object
        ref = dict(base["reference"])
        del ref["dataset"]
        reject({**base, "reference": ref})  # missing dataset
        ref = dict(base["reference"])
        ref["extra"] = 1
        reject({**base, "reference": ref})  # extra reference attribute
        ref = dict(base["reference"])
        ref["dataset"] = ""
        reject({**base, "reference": ref})  # empty dataset name
        ref = dict(base["reference"])
        ref["version"] = 0
        reject({**base, "reference": ref})  # non-positive version
        ref = dict(base["reference"])
        ref["version"] = True
        reject({**base, "reference": ref})  # boolean version
        ref = dict(base["reference"])
        ref["version"] = 1.5
        reject({**base, "reference": ref})  # non-integer version
        ref = dict(base["reference"])
        ref["columns"] = []
        reject({**base, "reference": ref})  # empty reference columns
        ref = dict(base["reference"])
        ref["columns"] = ["编号", "编号"]
        reject({**base, "reference": ref})  # duplicate reference columns
        ref = dict(base["reference"])
        ref["columns"] = ["编号"]
        reject({**base, "reference": ref})  # length mismatch
        # no revision consumed by any failed configuration
        self.assertEqual(self.catalog.list_datasets().get("订单"), None)

    def test_left_side_columns_checked_at_validation(self):
        self.import_customers()
        self.import_orders("客户号,金额\n1,10\n")  # no 地区 column
        # configuration succeeds (reference side exists)
        result = self.catalog.set_rules("订单", [self.reference_rule()])
        self.assertEqual(result["revision"], 1)
        # validation fails because the validated side lacks a column
        with self.assertRaises(ValueError):
            self.catalog.validate("订单", 1)

    def test_report_persists_identically_and_survives_restart(self):
        customers = self.import_customers()
        self.import_orders()
        self.catalog.set_rules("订单", [self.reference_rule()])
        first = self.catalog.validate("订单", 1)
        second = self.catalog.validate("订单", 1)
        self.assertEqual(first, second)
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(set(state["validations"]["订单"]["1"]), {"1"})
        reloaded = Catalog(self.catalog.workspace)
        self.assertEqual(reloaded.validation_history("订单", 1), [first])
        self.assertEqual(reloaded.validate("订单", 1), first)
        self.assertEqual(
            first["results"][0]["reference"]["content_sha256"],
            customers.content_sha256,
        )

    def test_revalidation_reverifies_every_side_and_keeps_report_on_failure(self):
        self.import_customers()
        self.import_orders()
        self.catalog.set_rules("订单", [self.reference_rule()])
        first = self.catalog.validate("订单", 1)
        record = self.catalog.get("订单", 1)
        ref_record = self.catalog.get("客户", 1)
        blob = self.catalog.workspace / record["blob"]
        ref_blob = self.catalog.workspace / ref_record["blob"]
        original = blob.read_bytes()
        ref_original = ref_blob.read_bytes()

        for tampered, target in (
            ("客户号,地区,金额\n9,EU,10\n".encode("utf-8"), blob),
            ("编号,地区\n9,EU\n".encode("utf-8"), ref_blob),
        ):
            target.write_bytes(tampered)
            with self.assertRaises(ValueError):
                self.catalog.validate("订单", 1)
            # the stored report was not overwritten
            self.assertEqual(self.catalog.validation_history("订单", 1), [first])
            target.write_bytes(original if target is blob else ref_original)

        # missing files on either side also fail without touching the report
        for target in (blob, ref_blob):
            target.unlink()
            with self.assertRaises(ValueError):
                self.catalog.validate("订单", 1)
            self.assertEqual(self.catalog.validation_history("订单", 1), [first])
            target.write_bytes(original if target is blob else ref_original)

        # once repaired, validation returns the identical stored report
        self.assertEqual(self.catalog.validate("订单", 1), first)

    def test_reference_version_is_pinned_across_revisions(self):
        self.import_customers("编号,地区\n1,EU\n")
        self.import_orders("客户号,地区,金额\n1,EU,10\n")
        self.catalog.set_rules("订单", [self.reference_rule()])
        first = self.catalog.validate("订单", 1)
        self.assertTrue(first["passed"])
        # a new reference version with a different combination does not change
        # the meaning of the existing rule revision
        self.import_customers("编号,地区\n9,US\n")
        reloaded = Catalog(self.catalog.workspace)
        second = reloaded.validate("订单", 1)
        self.assertEqual(second, first)
        self.assertEqual(second["results"][0]["reference"]["version"], 1)

    def test_mixed_rules_keep_configuration_order_and_shapes(self):
        self.import_customers()
        self.import_orders("客户号,地区,金额\n1,EU,10\n1,APAC,20\n3,US,30\n,EU,40\n")
        rules = [
            {"id": "金额必填", "column": "金额", "type": "required"},
            self.reference_rule("客户引用"),
            {"id": "客户号唯一", "column": "客户号", "type": "unique"},
            self.reference_rule("地区引用", columns=("地区",), ref_columns=("地区",)),
        ]
        self.catalog.set_rules("订单", rules)
        report = self.catalog.validate("订单", 1)
        self.assertEqual(
            [item["id"] for item in report["results"]],
            ["金额必填", "客户引用", "客户号唯一", "地区引用"],
        )
        by_id = {item["id"]: item for item in report["results"]}
        self.assertEqual(by_id["金额必填"]["column"], "金额")
        self.assertEqual(by_id["金额必填"]["violations"], [])
        self.assertEqual(by_id["客户号唯一"]["violations"], [1, 2])
        self.assertEqual(by_id["客户引用"]["violations"], [2, 3, 4])
        self.assertEqual(by_id["地区引用"]["violations"], [3])
        for item in report["results"]:
            if item["type"] == "reference":
                self.assertEqual(item["columns"], ["客户号", "地区"] if item["id"] == "客户引用" else ["地区"])
                self.assertIn("content_sha256", item["reference"])
            else:
                self.assertIn("column", item)

    def test_cleaned_versions_work_as_both_sides(self):
        self.import_customers()
        self.import_orders("客户号,地区,金额\n1,EU,10\n3,US,30\n")
        # clean the reference side (rename 编号 -> 客户编号) and the validated side
        self.catalog.clean("客户", 1, [{"type": "rename", "column": "编号", "to": "客户编号"}])
        self.catalog.clean("订单", 1, [{"type": "trim", "column": "地区"}])
        rule = self.reference_rule(
            columns=("客户号", "地区"),
            version=2,
            ref_columns=("客户编号", "地区"),
        )
        self.catalog.set_rules("订单", [rule])
        report = self.catalog.validate("订单", 2)
        self.assertEqual(report["results"][0]["violations"], [2])
        self.assertEqual(report["results"][0]["reference"]["version"], 2)

    def test_failed_report_write_leaves_no_partial_result(self):
        self.import_customers()
        self.import_orders()
        self.catalog.set_rules("订单", [self.reference_rule()])
        with mock.patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.catalog.validate("订单", 1)
        self.assertEqual(self.catalog.validation_history("订单", 1), [])
        report = self.catalog.validate("订单", 1)
        self.assertEqual(len(self.catalog.validation_history("订单", 1)), 1)
        self.assertFalse(report["passed"])

    def test_reference_rule_does_not_modify_data_or_consume_versions(self):
        self.import_customers()
        source = self.csv_file("客户号,地区,金额\n1,EU,10\n", "orders.csv")
        before = source.read_bytes()
        self.catalog.import_csv("订单", source)
        self.catalog.set_rules("订单", [self.reference_rule()])
        self.catalog.validate("订单", 1)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(len(self.catalog.list_datasets()["订单"]), 1)
        self.assertEqual(len(self.catalog.list_datasets()["客户"]), 1)


class ReferenceRuleCliTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "ws"

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "governance_workbench",
                "--workspace",
                str(self.workspace),
                *arguments,
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_rules_validate_validations_with_reference_rule(self):
        customers = self.root / "customers.csv"
        customers.write_text("编号,地区\n1,EU\n2,APAC\n", encoding="utf-8")
        orders = self.root / "orders.csv"
        orders.write_text("客户号,地区,金额\n1,EU,10\n3,US,30\n,EU,40\n", encoding="utf-8")
        self.assertEqual(self.run_cli("import", "客户", str(customers)).returncode, 0)
        self.assertEqual(self.run_cli("import", "订单", str(orders)).returncode, 0)

        rules_path = self.root / "rules.json"
        rules_path.write_text(
            json.dumps([
                {"id": "金额必填", "column": "金额", "type": "required"},
                {
                    "id": "客户引用",
                    "type": "reference",
                    "columns": ["客户号", "地区"],
                    "reference": {"dataset": "客户", "version": 1, "columns": ["编号", "地区"]},
                },
            ]),
            encoding="utf-8",
        )
        result = self.run_cli("rules", "订单", str(rules_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["revision"], 1)

        result = self.run_cli("validate", "订单", "1")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["passed"])
        by_id = {item["id"]: item for item in report["results"]}
        self.assertEqual(by_id["客户引用"]["violations"], [2, 3])
        self.assertEqual(by_id["客户引用"]["reference"]["dataset"], "客户")
        self.assertEqual(by_id["客户引用"]["reference"]["version"], 1)
        self.assertRegex(by_id["客户引用"]["reference"]["content_sha256"], r"^[0-9a-f]{64}$")

        result = self.run_cli("validations", "订单", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        history = json.loads(result.stdout)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["results"][1]["reference"]["dataset"], "客户")

    def test_reference_configuration_failure_envelope_and_exit_2(self):
        customers = self.root / "customers.csv"
        customers.write_text("编号,地区\n1,EU\n", encoding="utf-8")
        self.run_cli("import", "客户", str(customers))
        orders = self.root / "orders.csv"
        orders.write_text("客户号,地区\n1,EU\n", encoding="utf-8")
        self.run_cli("import", "订单", str(orders))

        rules_path = self.root / "rules.json"
        rules_path.write_text(
            json.dumps([{
                "id": "客户引用",
                "type": "reference",
                "columns": ["客户号", "地区"],
                "reference": {"dataset": "客户", "version": 9, "columns": ["编号", "地区"]},
            }]),
            encoding="utf-8",
        )
        result = self.run_cli("rules", "订单", str(rules_path))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})
        # no revision was consumed: a valid configuration starts at revision 1
        rules_path.write_text(
            json.dumps([{
                "id": "客户引用",
                "type": "reference",
                "columns": ["客户号", "地区"],
                "reference": {"dataset": "客户", "version": 1, "columns": ["编号", "地区"]},
            }]),
            encoding="utf-8",
        )
        result = self.run_cli("rules", "订单", str(rules_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["revision"], 1)

    def test_reference_validation_failure_envelope_and_exit_2(self):
        customers = self.root / "customers.csv"
        customers.write_text("编号,地区\n1,EU\n", encoding="utf-8")
        self.run_cli("import", "客户", str(customers))
        orders = self.root / "orders.csv"
        orders.write_text("客户号,地区\n1,EU\n", encoding="utf-8")
        self.run_cli("import", "订单", str(orders))
        rules_path = self.root / "rules.json"
        rules_path.write_text(
            json.dumps([{
                "id": "客户引用",
                "type": "reference",
                "columns": ["客户号", "地区"],
                "reference": {"dataset": "客户", "version": 1, "columns": ["编号", "地区"]},
            }]),
            encoding="utf-8",
        )
        self.run_cli("rules", "订单", str(rules_path))
        # tamper with the reference blob after configuration
        ref_record = json.loads(self.run_cli("list").stdout)["客户"][0]
        (self.workspace / ref_record["blob"]).write_text("编号,地区\n9,US\n", encoding="utf-8")
        result = self.run_cli("validate", "订单", "1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})


if __name__ == "__main__":
    unittest.main()
