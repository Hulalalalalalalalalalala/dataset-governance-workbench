import csv as csv_module
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from governance_workbench import Catalog
from governance_workbench import catalog as catalog_module
from governance_workbench.catalog import _read_csv_records

REPO_ROOT = Path(__file__).resolve().parents[1]


def _directory_snapshot(directory) -> dict:
    """Map every regular file under *directory* to its current bytes."""
    base = Path(directory)
    return {
        path.relative_to(base): path.read_bytes()
        for path in base.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


class _FailingOutputFile:
    """File-like object whose ``write`` always raises OSError.

    Wraps a real ``os.fdopen`` result so the descriptor lifecycle and the
    temporary file on disk behave normally, while the payload write fails -
    a stand-in for a disk-full or I/O error in the middle of delivery.
    """

    def __init__(self, real_fdopen, fd, args, kwargs):
        self._handle = real_fdopen(fd, *args, **kwargs)

    def write(self, payload):
        raise OSError("simulated write failure")

    def flush(self):
        self._handle.flush()

    def fileno(self):
        return self._handle.fileno()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return self._handle.__exit__(*exc)


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


class ExportDeliveryTest(unittest.TestCase):
    """Regression coverage for joint CSV + manifest delivery.

    Both files must land together or not at all: a failure partway through
    restores the destination directory to exactly its prior bytes, and the
    workspace (catalog state and stored blobs) is never modified.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = Catalog(self.root / "workspace")
        # CRLF line endings, quoted fields with embedded commas and spaces:
        # the delivered bytes must survive verbatim, not be re-normalized.
        self.v1 = b'id,name\r\n1,"Ada, Q"\r\n'
        self.v2 = b'id,name,region\r\n1,"Bob, K",APAC\r\n2,"Li, M",EMEA\r\n'
        source1 = self.root / "v1.csv"
        source1.write_bytes(self.v1)
        source2 = self.root / "v2.csv"
        source2.write_bytes(self.v2)
        self.catalog.import_csv("d", source1)
        self.catalog.import_csv("d", source2)
        self.data_name = "d-v2.csv"
        self.record2 = self.catalog.get("d", 2)
        self.expected_manifest_bytes = (
            json.dumps(
                {
                    "schemaVersion": 1,
                    "record": self.record2,
                    "file": self.data_name,
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
        # Pre-existing contents deliberately different from the new delivery,
        # so a test that only covered byte-identical overwrites would not pass.
        self.stale_csv = b"old,header\n9,9\n"
        self.stale_manifest = b'{"stale": true, "file": "d-v1.csv"}\n'
        self.extra_file = ("notes.txt", b"unrelated file, untouched\n")
        self.nested_file = ("sub/nested.bin", b"\x00\x01\x02")

    def tearDown(self):
        self.temporary.cleanup()

    def make_destination(self, *, csv_present=True, manifest_present=True):
        directory = self.root / "export"
        directory.mkdir()
        if csv_present:
            (directory / self.data_name).write_bytes(self.stale_csv)
        if manifest_present:
            (directory / "manifest.json").write_bytes(self.stale_manifest)
        relative, payload = self.extra_file
        (directory / relative).write_bytes(payload)
        relative, payload = self.nested_file
        nested = directory / relative
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_bytes(payload)
        return directory

    def assertWorkspaceUnchanged(self):
        # export only reads the workspace: catalog state and both stored
        # blobs must be byte-identical before and after.
        self.assertEqual(
            self.catalog.state_path.read_bytes(), self.workspace_state_bytes
        )
        for version, original in (
            (1, self.v1),
            (2, self.v2),
        ):
            record = self.catalog.get("d", version)
            blob = self.catalog.workspace / record["blob"]
            self.assertEqual(blob.read_bytes(), original)

    def snapshot_workspace(self):
        self.workspace_state_bytes = self.catalog.state_path.read_bytes()

    def assertNoDeliveryArtifacts(self, directory):
        leftovers = [
            path.name
            for path in directory.iterdir()
            if path.name.startswith(".") or path.suffix in (".tmp", ".bak")
        ]
        self.assertEqual(leftovers, [])

    def assertStaleContents(self, directory, *, csv_present, manifest_present):
        data_path = directory / self.data_name
        manifest_path = directory / "manifest.json"
        if csv_present:
            self.assertEqual(data_path.read_bytes(), self.stale_csv)
        else:
            self.assertFalse(data_path.exists())
        if manifest_present:
            self.assertEqual(manifest_path.read_bytes(), self.stale_manifest)
        else:
            self.assertFalse(manifest_path.exists())

    def assertUnrelatedFilesIntact(self, directory):
        relative, payload = self.extra_file
        self.assertEqual((directory / relative).read_bytes(), payload)
        relative, payload = self.nested_file
        self.assertEqual((directory / relative).read_bytes(), payload)

    def export_bytes(self, directory):
        return (directory / self.data_name).read_bytes(), (
            directory / "manifest.json"
        ).read_bytes()

    # ---- successful delivery ---------------------------------------------

    def test_successful_export_replaces_only_the_two_delivered_files(self):
        directory = self.make_destination()
        before = _directory_snapshot(directory)
        self.snapshot_workspace()

        manifest = self.catalog.export("d", 2, directory)

        data_bytes, manifest_bytes = self.export_bytes(directory)
        # CSV is the stored version's exact original bytes: CRLF and quoting
        # are preserved and the file differs from the pre-existing CSV.
        self.assertEqual(data_bytes, self.v2)
        self.assertNotEqual(data_bytes, self.stale_csv)
        # the returned manifest equals the on-disk JSON byte-for-byte and
        # still points at this selected version and data file.
        self.assertEqual(manifest_bytes, self.expected_manifest_bytes)
        self.assertEqual(json.loads(manifest_bytes), manifest)
        self.assertEqual(manifest["file"], self.data_name)
        self.assertEqual(manifest["record"]["version"], 2)
        self.assertEqual(manifest["record"]["dataset"], "d")
        self.assertEqual(manifest["record"]["content_sha256"], self.record2["content_sha256"])
        # only the two delivered files changed; every other name and its
        # contents are untouched.
        after = _directory_snapshot(directory)
        self.assertEqual(set(before) - {Path(self.data_name), Path("manifest.json")},
                         set(after) - {Path(self.data_name), Path("manifest.json")})
        for relative in set(before) & set(after):
            if relative in (Path(self.data_name), Path("manifest.json")):
                continue
            self.assertEqual(after[relative], before[relative], relative)
        self.assertUnrelatedFilesIntact(directory)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()
        # the result is internally consistent and verifies offline.
        self.assertTrue(Catalog(self.root / "offline").verify_export(directory)["passed"])

    def test_successful_export_without_previous_targets_creates_both(self):
        directory = self.root / "fresh"
        directory.mkdir()
        relative, payload = self.extra_file
        (directory / relative).write_bytes(payload)
        self.snapshot_workspace()

        self.catalog.export("d", 2, directory)

        data_bytes, manifest_bytes = self.export_bytes(directory)
        self.assertEqual(data_bytes, self.v2)
        self.assertEqual(manifest_bytes, self.expected_manifest_bytes)
        self.assertEqual((directory / relative).read_bytes(), payload)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()

    # ---- write failure after the CSV is placed ----------------------------

    def patch_manifest_write_to_fail(self):
        """Fail the payload write for the manifest (the second output file).

        The CSV has already been renamed into place by the time the manifest
        temporary file is written, so this drives the rollback path where a
        new CSV sits beside an undelivered manifest.
        """
        real_fdopen = os.fdopen
        call_count = {"n": 0}

        def fdopen(fd, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                return _FailingOutputFile(real_fdopen, fd, args, kwargs)
            return real_fdopen(fd, *args, **kwargs)

        return mock.patch.object(catalog_module.os, "fdopen", side_effect=fdopen)

    def test_manifest_write_failure_restores_original_csv_and_manifest(self):
        directory = self.make_destination()
        before = _directory_snapshot(directory)
        self.snapshot_workspace()

        with self.patch_manifest_write_to_fail():
            with self.assertRaises(OSError):
                self.catalog.export("d", 2, directory)

        # both originals are back at their prior bytes: never new CSV with
        # the old manifest, and neither file lost.
        self.assertEqual(_directory_snapshot(directory), before)
        self.assertStaleContents(directory, csv_present=True, manifest_present=True)
        self.assertUnrelatedFilesIntact(directory)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()

    def test_manifest_write_failure_with_no_prior_csv_leaves_no_csv(self):
        # only an old manifest exists; the CSV target is absent. After a
        # failed delivery the old manifest must remain and no half-delivered
        # CSV (nor its backup) may be left behind.
        directory = self.make_destination(csv_present=False, manifest_present=True)
        before = _directory_snapshot(directory)
        self.snapshot_workspace()

        with self.patch_manifest_write_to_fail():
            with self.assertRaises(OSError):
                self.catalog.export("d", 2, directory)

        self.assertEqual(_directory_snapshot(directory), before)
        self.assertStaleContents(directory, csv_present=False, manifest_present=True)
        self.assertFalse((directory / self.data_name).exists())
        self.assertUnrelatedFilesIntact(directory)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()

    def test_failure_when_neither_target_exists_creates_neither(self):
        directory = self.root / "empty-dest"
        directory.mkdir()
        relative, payload = self.extra_file
        (directory / relative).write_bytes(payload)
        before = _directory_snapshot(directory)
        self.snapshot_workspace()

        with self.patch_manifest_write_to_fail():
            with self.assertRaises(OSError):
                self.catalog.export("d", 2, directory)

        self.assertEqual(_directory_snapshot(directory), before)
        self.assertFalse((directory / self.data_name).exists())
        self.assertFalse((directory / "manifest.json").exists())
        self.assertEqual((directory / relative).read_bytes(), payload)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()

    # ---- rename / replace failure -----------------------------------------

    def patch_replace_to_fail(self, target_name):
        real_replace = Path.replace

        def failing_replace(self, target, *args, **kwargs):
            if Path(target).name == target_name:
                raise OSError("simulated replace failure")
            return real_replace(self, target, *args, **kwargs)

        return mock.patch.object(Path, "replace", failing_replace)

    def test_csv_replace_failure_restores_everything(self):
        directory = self.make_destination()
        before = _directory_snapshot(directory)
        self.snapshot_workspace()

        with self.patch_replace_to_fail(self.data_name):
            with self.assertRaises(OSError):
                self.catalog.export("d", 2, directory)

        self.assertEqual(_directory_snapshot(directory), before)
        self.assertStaleContents(directory, csv_present=True, manifest_present=True)
        self.assertUnrelatedFilesIntact(directory)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()

    def test_manifest_replace_failure_restores_csv_and_manifest(self):
        # The CSV replacement succeeds; the manifest's final rename fails.
        directory = self.make_destination()
        before = _directory_snapshot(directory)
        self.snapshot_workspace()

        with self.patch_replace_to_fail("manifest.json"):
            with self.assertRaises(OSError):
                self.catalog.export("d", 2, directory)

        self.assertEqual(_directory_snapshot(directory), before)
        self.assertStaleContents(directory, csv_present=True, manifest_present=True)
        self.assertUnrelatedFilesIntact(directory)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()

    def test_manifest_replace_failure_with_only_manifest_present(self):
        directory = self.make_destination(csv_present=False, manifest_present=True)
        before = _directory_snapshot(directory)
        self.snapshot_workspace()

        with self.patch_replace_to_fail("manifest.json"):
            with self.assertRaises(OSError):
                self.catalog.export("d", 2, directory)

        self.assertEqual(_directory_snapshot(directory), before)
        self.assertStaleContents(directory, csv_present=False, manifest_present=True)
        self.assertFalse((directory / self.data_name).exists())
        self.assertUnrelatedFilesIntact(directory)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()

    def test_failed_export_is_retryable(self):
        directory = self.make_destination()
        self.snapshot_workspace()

        with self.patch_manifest_write_to_fail():
            with self.assertRaises(OSError):
                self.catalog.export("d", 2, directory)
        # no retry or recovery entry is required; a plain re-export just works
        manifest = self.catalog.export("d", 2, directory)

        data_bytes, manifest_bytes = self.export_bytes(directory)
        self.assertEqual(data_bytes, self.v2)
        self.assertEqual(json.loads(manifest_bytes), manifest)
        self.assertUnrelatedFilesIntact(directory)
        self.assertNoDeliveryArtifacts(directory)
        self.assertWorkspaceUnchanged()
        self.assertTrue(Catalog(self.root / "offline").verify_export(directory)["passed"])


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

    def test_integer_bounds_keep_exact_value(self):
        big = 9007199254740993
        result = self.catalog.set_rules(
            "things",
            [{"id": "r", "column": "v", "type": "range", "min": -big, "max": big}],
        )
        rule = result["rules"][0]
        self.assertIsInstance(rule["min"], int)
        self.assertIsInstance(rule["max"], int)
        self.assertEqual((rule["min"], rule["max"]), (-big, big))
        # the saved revision stores the exact integers as well
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        stored = state["rules"]["things"][0]["rules"][0]
        self.assertEqual((stored["min"], stored["max"]), (-big, big))
        reloaded = json.loads(json.dumps(rule))
        self.assertEqual((reloaded["min"], reloaded["max"]), (-big, big))

    def test_distinct_large_integer_bounds_are_not_collapsed(self):
        # these two integers are equal once widened to float; configuration
        # must still reject min > max and not consume a revision number
        with self.assertRaises(ValueError):
            self.catalog.set_rules("things", [
                {"id": "r", "column": "v", "type": "range",
                 "min": 9007199254740993, "max": 9007199254740992},
            ])
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state.get("rules", {}).get("things", []), [])
        result = self.catalog.set_rules("things", [
            {"id": "r", "column": "v", "type": "required"},
        ])
        self.assertEqual(result["revision"], 1)

    def test_equal_integer_bounds_are_a_legal_closed_interval(self):
        big = 9007199254740992
        result = self.catalog.set_rules("things", [
            {"id": "r", "column": "v", "type": "range", "min": big, "max": big},
        ])
        self.assertEqual(result["revision"], 1)
        self.assertEqual(
            (result["rules"][0]["min"], result["rules"][0]["max"]), (big, big)
        )

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

    def test_range_distinguishes_integers_beyond_float_safe_range(self):
        # 2**53 is exactly representable as a float; 2**53 + 1 is a
        # distinct integer that float parsing rounds back down.
        boundary = 9007199254740992
        above = 9007199254740993
        self.catalog.import_csv(
            "r",
            self.csv_file(
                "v\n"
                f"{boundary}\n"          # at max: passes
                f"{above}\n"             # one over max: violates
                f"{boundary}.0\n"        # same number, decimal form: passes
                "9.007199254740992e15\n"  # scientific form of boundary: passes
                "9.007199254740993e15\n"  # scientific form of above: violates
                f"{-above}\n"            # below min when min = -boundary: violates
                f"{-boundary}\n"         # at min: passes
            ),
        )
        self.catalog.set_rules("r", [
            {"id": "mx", "column": "v", "type": "range", "max": boundary},
            {"id": "mn", "column": "v", "type": "range", "min": -boundary},
            {"id": "both", "column": "v", "type": "range",
             "min": -boundary, "max": boundary},
        ])
        by_id = {item["id"]: item for item in self.catalog.validate("r", 1)["results"]}
        # max-only: only values above the max violate; the large negative passes
        self.assertEqual(by_id["mx"]["violations"], [2, 5])
        self.assertEqual(by_id["mx"]["violationCount"], 2)
        # min-only: only the one value below the negative bound violates
        self.assertEqual(by_id["mn"]["violations"], [6])
        self.assertEqual(by_id["both"]["violations"], [2, 5, 6])

    def test_range_equal_integer_bound_endpoint_forms(self):
        big = 9007199254740993
        self.catalog.import_csv(
            "r",
            self.csv_file(
                "v\n"
                f"{big}\n"
                f"{big}.0\n"
                "9.007199254740993e15\n"
                "9.007199254740993E15\n"
                f"{big - 1}\n"
            ),
        )
        self.catalog.set_rules("r", [
            {"id": "r", "column": "v", "type": "range", "min": big, "max": big},
        ])
        result = self.catalog.validate("r", 1)["results"][0]
        # every spelling of the same integer is inside the closed interval
        self.assertEqual(result["violations"], [5])
        self.assertEqual(result["violationCount"], 1)

    def test_range_float_bounds_keep_endpoint_inclusion(self):
        self.catalog.import_csv(
            "r",
            self.csv_file("v\n0.1\n1e-1\n10.5\n1.05e1\n0.09999999999999999\n"),
        )
        self.catalog.set_rules("r", [
            {"id": "r", "column": "v", "type": "range", "min": 0.1, "max": 10.5},
        ])
        result = self.catalog.validate("r", 1)["results"][0]
        self.assertEqual(result["violations"], [5])

    def test_range_extreme_exponents_keep_float_verdicts(self):
        # overflowing magnitudes are still rejected as non-finite; values
        # underflowing the float range still compare as signed zero
        self.catalog.import_csv(
            "r",
            self.csv_file(
                "v\n"
                "1e309\n"        # row 1: overflow -> non-finite -> violates
                "-1e400\n"       # row 2: overflow -> violates
                "1e-400\n"       # row 3: underflow -> zero
                "-1e-400\n"      # row 4: underflow -> negative zero
                "0\n"            # row 5: zero
            ),
        )
        self.catalog.set_rules("r", [
            {"id": "r", "column": "v", "type": "range", "min": 0, "max": 0},
        ])
        result = self.catalog.validate("r", 1)["results"][0]
        # -0.0 (underflow) equals 0 and stays inside the closed interval
        self.assertEqual(result["violations"], [1, 2])

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

    def import_reference_side(self):
        self.catalog.import_csv(
            "客户", self.csv_file("编号,地区,备注\nC1,北,x\nC2,南,y\n", "cust-v1.csv")
        )
        self.catalog.import_csv(
            "客户",
            self.csv_file("编号,地区,备注\nC1,北,x\nC2,南,y\nC3,东,z\n", "cust-v2.csv"),
        )

    def reference_rule(self, **overrides):
        rule = {
            "id": "客户引用",
            "type": "reference",
            "columns": ["客户号", "地区"],
            "reference": {"dataset": "客户", "version": 2, "columns": ["编号", "地区"]},
        }
        rule.update(overrides)
        return rule

    # ---- configuration ---------------------------------------------------

    def test_valid_reference_rule_configuration(self):
        self.import_reference_side()
        self.catalog.import_csv("orders", self.csv_file("客户号,地区\nC1,北\n", "orders.csv"))
        result = self.catalog.set_rules("orders", [self.reference_rule()])
        self.assertEqual(result["revision"], 1)
        rule = result["rules"][0]
        self.assertEqual(rule["type"], "reference")
        self.assertEqual(rule["columns"], ["客户号", "地区"])
        self.assertEqual(
            rule["reference"],
            {"dataset": "客户", "version": 2, "columns": ["编号", "地区"]},
        )

    def test_single_column_reference_rule(self):
        self.catalog.import_csv("ref", self.csv_file("code\nA\nB\n", "ref.csv"))
        self.catalog.import_csv("d", self.csv_file("c\nA\n", "d.csv"))
        result = self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["c"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["code"]},
                }
            ],
        )
        self.assertEqual(result["revision"], 1)
        self.assertTrue(self.catalog.validate("d", 1)["passed"])

    def test_invalid_reference_configurations(self):
        self.import_reference_side()
        self.catalog.import_csv("orders", self.csv_file("客户号,地区\nC1,北\n", "orders.csv"))

        def reject(rule):
            with self.assertRaises(ValueError):
                self.catalog.set_rules("orders", [rule])

        reject({"id": "r", "type": "reference",
                "reference": {"dataset": "客户", "version": 2, "columns": ["编号"]}})  # no columns
        reject(self.reference_rule(reference=None))  # missing reference object
        reject(self.reference_rule(extra=1))  # extra attribute
        reject(self.reference_rule(column="客户号"))  # single-column form not allowed
        reject(self.reference_rule(min=1))
        reject(self.reference_rule(max=2))
        reject(self.reference_rule(columns=[]))  # empty columns
        reject(self.reference_rule(columns="客户号"))  # not an array
        reject(self.reference_rule(columns=["客户号", ""]))  # empty name
        reject(self.reference_rule(columns=["客户号", 7]))  # non-string
        reject(self.reference_rule(columns=["客户号", "客户号"]))  # duplicates
        reject(self.reference_rule(reference={"dataset": "客户", "version": 2,
                                              "columns": ["编号", "地区"], "x": 1}))
        reject(self.reference_rule(reference={"version": 2, "columns": ["编号", "地区"]}))
        reject(self.reference_rule(reference={"dataset": "", "version": 2,
                                              "columns": ["编号", "地区"]}))
        reject(self.reference_rule(reference={"dataset": 5, "version": 2,
                                              "columns": ["编号", "地区"]}))
        reject(self.reference_rule(reference={"dataset": "客户",
                                              "columns": ["编号", "地区"]}))  # no version
        reject(self.reference_rule(reference={"dataset": "客户", "version": 0,
                                              "columns": ["编号", "地区"]}))
        reject(self.reference_rule(reference={"dataset": "客户", "version": -1,
                                              "columns": ["编号", "地区"]}))
        reject(self.reference_rule(reference={"dataset": "客户", "version": True,
                                              "columns": ["编号", "地区"]}))
        reject(self.reference_rule(reference={"dataset": "客户", "version": 2.0,
                                              "columns": ["编号", "地区"]}))
        reject(self.reference_rule(reference={"dataset": "客户", "version": 2,
                                              "columns": []}))
        reject(self.reference_rule(reference={"dataset": "客户", "version": 2,
                                              "columns": ["编号", "编号"]}))
        reject(self.reference_rule(reference={"dataset": "客户", "version": 2,
                                              "columns": ["编号"]}))  # unequal lengths
        reject(self.reference_rule(columns=["客户号"],
                                   reference={"dataset": "客户", "version": 2,
                                              "columns": ["编号", "地区"]}))
        # old rule types reject the new attributes
        reject({"id": "r", "column": "客户号", "type": "required", "columns": ["客户号"]})
        reject({"id": "r", "column": "客户号", "type": "unique",
                "reference": {"dataset": "客户", "version": 2, "columns": ["编号"]}})
        # id uniqueness still applies across mixed types
        with self.assertRaises(ValueError):
            self.catalog.set_rules(
                "orders",
                [
                    self.reference_rule(),
                    {"id": "客户引用", "column": "地区", "type": "required"},
                ],
            )

    def test_reference_target_checked_at_config_time(self):
        self.import_reference_side()
        self.catalog.import_csv("orders", self.csv_file("客户号,地区\nC1,北\n", "orders.csv"))

        def reject(reference):
            with self.assertRaises(ValueError):
                self.catalog.set_rules("orders", [self.reference_rule(reference=reference)])

        reject({"dataset": "missing", "version": 1, "columns": ["编号", "地区"]})
        reject({"dataset": "客户", "version": 3, "columns": ["编号", "地区"]})
        reject({"dataset": "客户", "version": 1, "columns": ["编号", "不存在"]})
        # failed configurations consumed no revision number
        result = self.catalog.set_rules("orders", [self.reference_rule()])
        self.assertEqual(result["revision"], 1)

    def test_local_columns_checked_at_validation_time(self):
        self.import_reference_side()
        self.catalog.import_csv("orders", self.csv_file("客户号,区域\nC1,北\n", "orders.csv"))
        # 地区 is not a column of the local version; configuration still succeeds
        self.catalog.set_rules("orders", [self.reference_rule()])
        with self.assertRaises(ValueError) as context:
            self.catalog.validate("orders", 1)
        self.assertIn("orders@1", str(context.exception))

    # ---- matching semantics ------------------------------------------------

    def test_match_and_mismatch_violations(self):
        self.import_reference_side()
        self.catalog.import_csv(
            "orders",
            self.csv_file(
                "客户号,地区,金额\n"
                "C1,北,10\n"     # ok
                "C3,东,20\n"     # ok (only in reference version 2)
                "C9,北,30\n"     # unknown customer
                "C1,南,40\n"     # known customer, wrong region combination
                "C2,南,50\n"     # ok
                "C2,南,60\n",    # ok (duplicate local rows are each checked)
                "orders.csv",
            ),
        )
        self.catalog.set_rules("orders", [self.reference_rule()])
        report = self.catalog.validate("orders", 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["rowCount"], 6)
        self.assertEqual(len(report["results"]), 1)
        result = report["results"][0]
        self.assertEqual(result["id"], "客户引用")
        self.assertEqual(result["type"], "reference")
        self.assertEqual(result["columns"], ["客户号", "地区"])
        self.assertNotIn("column", result)
        reference = result["reference"]
        self.assertEqual(reference["dataset"], "客户")
        self.assertEqual(reference["version"], 2)
        self.assertEqual(reference["columns"], ["编号", "地区"])
        self.assertEqual(
            reference["content_sha256"], self.catalog.get("客户", 2)["content_sha256"]
        )
        self.assertEqual(result["violations"], [3, 4])
        self.assertEqual(result["violationCount"], 2)

    def test_raw_string_matching_no_trimming_or_numeric_conversion(self):
        self.catalog.import_csv("ref", self.csv_file("code\n1\n x\n", "ref.csv"))
        self.catalog.import_csv(
            "d", self.csv_file('c\n1\n01\n 1\nx\n x\n"1,5"\n', "d.csv")
        )
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["c"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["code"]},
                }
            ],
        )
        report = self.catalog.validate("d", 1)
        # "01", " 1", "x", "1,5" are not reference values; separators are plain
        self.assertEqual(report["results"][0]["violations"], [2, 3, 4, 6])

    def test_empty_local_value_and_duplicate_rows_reported_per_record(self):
        self.catalog.import_csv("ref", self.csv_file("a,b\nX,1\n", "ref.csv"))
        self.catalog.import_csv(
            "d", self.csv_file("a,b\nX,1\nX,\n,1\n,\nZ,9\nZ,9\n", "d.csv")
        )
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["a", "b"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["a", "b"]},
                }
            ],
        )
        report = self.catalog.validate("d", 1)
        # rows 2-4 have an empty side value; rows 5-6 repeat an unknown pair
        self.assertEqual(report["results"][0]["violations"], [2, 3, 4, 5, 6])

    def test_reference_side_empty_value_fails_whole_run(self):
        self.catalog.import_csv("ref", self.csv_file("a,b\nX,1\nY,\n", "ref.csv"))
        self.catalog.import_csv("d", self.csv_file("a,b\nX,1\n", "d.csv"))
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["a", "b"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["a", "b"]},
                }
            ],
        )
        with self.assertRaises(ValueError) as context:
            self.catalog.validate("d", 1)
        self.assertIn("ref@1", str(context.exception))
        # nothing was persisted
        self.assertEqual(self.catalog.validation_history("d", 1), [])

    def test_reference_side_duplicate_combination_fails_whole_run(self):
        self.catalog.import_csv("ref", self.csv_file("a,b\nX,1\nX,1\n", "ref.csv"))
        self.catalog.import_csv("d", self.csv_file("a,b\n", "d.csv"))  # header only
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["a"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["a"]},
                }
            ],
        )
        # fails even though the local side has no records at all
        with self.assertRaises(ValueError) as context:
            self.catalog.validate("d", 1)
        self.assertIn("ref@1", str(context.exception))

    def test_header_only_reference_and_empty_sides(self):
        self.catalog.import_csv("ref", self.csv_file("a,b\n", "ref.csv"))  # header only
        self.catalog.import_csv("d", self.csv_file("a,b\nX,1\nY,2\n", "d.csv"))
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["a", "b"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["a", "b"]},
                }
            ],
        )
        report = self.catalog.validate("d", 1)
        # a header-only reference version is legal; every local record violates
        self.assertEqual(report["results"][0]["violations"], [1, 2])
        self.assertFalse(report["passed"])
        # both sides without records pass
        self.catalog.import_csv("empty", self.csv_file("a,b\n", "empty.csv"))
        self.catalog.set_rules(
            "empty",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["a", "b"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["a", "b"]},
                }
            ],
        )
        self.assertTrue(self.catalog.validate("empty", 1)["passed"])

    def test_mixed_with_existing_rule_types_in_config_order(self):
        self.catalog.import_csv("ref", self.csv_file("code\nA\nB\n", "ref.csv"))
        self.catalog.import_csv("d", self.csv_file("c,v\nA,5\nQ,99\nA,9\n", "d.csv"))
        self.catalog.set_rules(
            "d",
            [
                {"id": "v-range", "column": "v", "type": "range", "min": 0, "max": 10},
                {
                    "id": "c-ref",
                    "type": "reference",
                    "columns": ["c"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["code"]},
                },
                {"id": "c-required", "column": "c", "type": "required"},
            ],
        )
        report = self.catalog.validate("d", 1)
        self.assertEqual(
            [item["id"] for item in report["results"]],
            ["v-range", "c-ref", "c-required"],
        )
        by_id = {item["id"]: item for item in report["results"]}
        self.assertEqual(by_id["v-range"]["violations"], [2])
        self.assertEqual(by_id["c-ref"]["violations"], [2])
        self.assertEqual(by_id["c-required"]["violations"], [])
        self.assertFalse(report["passed"])

    def test_mixed_range_large_integer_bounds_match_plain_path(self):
        # range judgement must be exact and identical whether the revision
        # mixes reference rules or not (both paths share one evaluator)
        self.catalog.import_csv("ref", self.csv_file("code\nA\n", "ref.csv"))
        self.catalog.import_csv(
            "d",
            self.csv_file(
                "c,v\nA,9007199254740992\nA,9007199254740993\nA,9.007199254740992e15\n",
                "d.csv",
            ),
        )
        rules = [
            {"id": "v-range", "column": "v", "type": "range", "max": 9007199254740992},
            {
                "id": "c-ref",
                "type": "reference",
                "columns": ["c"],
                "reference": {"dataset": "ref", "version": 1, "columns": ["code"]},
            },
        ]
        self.catalog.set_rules("d", rules)
        mixed = self.catalog.validate("d", 1)
        by_id = {item["id"]: item for item in mixed["results"]}
        self.assertEqual(by_id["v-range"]["violations"], [2])
        self.assertEqual(by_id["c-ref"]["violations"], [])
        self.assertFalse(mixed["passed"])
        # same data with only the range rule: identical range verdict
        self.catalog.set_rules("d", [rules[0]])
        plain = self.catalog.validate("d", 1, revision=2)
        self.assertEqual(plain["results"][0]["violations"], [2])

    def test_cleaned_versions_work_on_either_side(self):
        self.catalog.import_csv("ref", self.csv_file("code\n A \nB\n", "ref.csv"))
        self.catalog.clean("ref", 1, [{"type": "trim", "column": "code"}])
        self.catalog.import_csv("d", self.csv_file("c\nA\nB\nC\n", "d.csv"))
        self.catalog.clean("d", 1, [{"type": "drop_duplicates", "columns": ["c"]}])
        # cleaned version 2 of ref as the reference side, cleaned version 2 of
        # d as the local side
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["c"],
                    "reference": {"dataset": "ref", "version": 2, "columns": ["code"]},
                }
            ],
        )
        report = self.catalog.validate("d", 2)
        self.assertEqual(report["results"][0]["violations"], [3])

    def test_new_reference_version_keeps_old_revision_meaning(self):
        self.catalog.import_csv("ref", self.csv_file("code\nA\n", "ref-v1.csv"))
        self.catalog.import_csv("d", self.csv_file("c\nA\nB\n", "d.csv"))
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["c"],
                    "reference": {"dataset": "ref", "version": 1, "columns": ["code"]},
                }
            ],
        )
        first = self.catalog.validate("d", 1)
        self.assertEqual(first["results"][0]["violations"], [2])
        # a new version on the reference side does not change the pinned target
        self.catalog.import_csv("ref", self.csv_file("code\nA\nB\n", "ref-v2.csv"))
        again = self.catalog.validate("d", 1)
        self.assertEqual(again, first)
        self.assertEqual(
            again["results"][0]["reference"]["content_sha256"],
            self.catalog.get("ref", 1)["content_sha256"],
        )

    # ---- persistence and re-verification ------------------------------------

    def test_report_persists_and_revalidation_rechecks_every_side(self):
        self.import_reference_side()
        self.catalog.import_csv("orders", self.csv_file("客户号,地区\nC1,北\nC9,北\n", "orders.csv"))
        self.catalog.set_rules("orders", [self.reference_rule()])
        first = self.catalog.validate("orders", 1)
        second = self.catalog.validate("orders", 1)
        self.assertEqual(first, second)
        # exactly one report persisted, retrievable after a restart
        reloaded = Catalog(self.catalog.workspace)
        history = reloaded.validation_history("orders", 1)
        self.assertEqual(history, [first])
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(state["validations"]["orders"]["1"]), 1)

        # tampering with the reference side is noticed on revalidation
        reference_record = self.catalog.get("客户", 2)
        reference_blob = self.catalog.workspace / reference_record["blob"]
        reference_original = reference_blob.read_bytes()
        reference_blob.write_text("编号,地区,备注\nC1,北,x\n", encoding="utf-8")
        with self.assertRaises(ValueError) as context:
            reloaded.validate("orders", 1)
        self.assertIn("客户@2", str(context.exception))
        reference_blob.write_bytes(reference_original)

        # tampering with the local side is noticed as well
        local_record = self.catalog.get("orders", 1)
        local_blob = self.catalog.workspace / local_record["blob"]
        local_original = local_blob.read_bytes()
        local_blob.write_text("客户号,地区\nC1,北\n", encoding="utf-8")
        with self.assertRaises(ValueError) as context:
            reloaded.validate("orders", 1)
        self.assertIn("orders@1", str(context.exception))
        local_blob.write_bytes(local_original)

        # a missing reference file fails the run without touching the report
        reference_blob.unlink()
        with self.assertRaises(ValueError) as context:
            reloaded.validate("orders", 1)
        self.assertIn("客户@2", str(context.exception))
        reference_blob.write_bytes(reference_original)
        # the stored report survived every failed revalidation unchanged
        self.assertEqual(reloaded.validation_history("orders", 1), [first])
        self.assertEqual(reloaded.validate("orders", 1), first)

    def test_structurally_invalid_side_fails_whole_run(self):
        self.import_reference_side()
        self.catalog.import_csv("orders", self.csv_file("客户号,地区\nC1,北\n", "orders.csv"))
        self.catalog.set_rules("orders", [self.reference_rule()])
        # corrupt the reference blob in place, then fix the catalog hash so
        # only the structural problem remains
        record = self.catalog.get("客户", 2)
        blob = self.catalog.workspace / record["blob"]
        blob.write_text("编号,地区,备注\nC1,北\n", encoding="utf-8")  # ragged
        state = json.loads(self.catalog.state_path.read_text(encoding="utf-8"))
        state["datasets"]["客户"][1]["content_sha256"] = hashlib.sha256(
            blob.read_bytes()
        ).hexdigest()
        self.catalog.state_path.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaises(ValueError) as context:
            self.catalog.validate("orders", 1)
        self.assertIn("客户@2", str(context.exception))
        self.assertEqual(self.catalog.validation_history("orders", 1), [])

    def test_failed_report_write_leaves_no_partial_result(self):
        self.import_reference_side()
        self.catalog.import_csv("orders", self.csv_file("客户号,地区\nC1,北\n", "orders.csv"))
        self.catalog.set_rules("orders", [self.reference_rule()])
        with mock.patch.object(Catalog, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.catalog.validate("orders", 1)
        self.assertEqual(self.catalog.validation_history("orders", 1), [])
        self.assertEqual(len(self.catalog.list_datasets()["orders"]), 1)
        self.assertEqual(self.catalog.lineage("orders", 1), {"dataset": "orders", "version": 1, "chain": []})
        report = self.catalog.validate("orders", 1)
        self.assertTrue(report["passed"])
        self.assertEqual(len(self.catalog.validation_history("orders", 1)), 1)

    def test_self_reference_and_historical_revision(self):
        self.catalog.import_csv("d", self.csv_file("a,b\nX,1\n", "d-v1.csv"))
        self.catalog.import_csv("d", self.csv_file("a,b\nX,1\nY,2\n", "d-v2.csv"))
        self.catalog.set_rules(
            "d",
            [
                {
                    "id": "r",
                    "type": "reference",
                    "columns": ["a", "b"],
                    "reference": {"dataset": "d", "version": 2, "columns": ["a", "b"]},
                }
            ],
        )
        self.assertTrue(self.catalog.validate("d", 1)["passed"])
        # a version may also reference itself
        self.assertTrue(self.catalog.validate("d", 2)["passed"])
        # a later revision does not rewrite the historical one
        self.catalog.set_rules("d", [{"id": "r2", "column": "a", "type": "required"}])
        historical = self.catalog.validate("d", 1, revision=1)
        self.assertEqual(historical["rulesRevision"], 1)
        self.assertEqual(historical["results"][0]["type"], "reference")


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

    def test_bare_carriage_return_in_field_survives_noop_clean(self):
        # A field whose value contains a lone carriage return (not \r\n) is
        # legal on import; a content-preserving clean must write it back
        # quoted so it is not emitted as a record boundary.
        self.catalog.import_csv(
            "cr",
            self.csv_file('id,说明\r\n1,"甲\r乙"\r\n', "cr.csv"),
        )
        result = self.catalog.clean("cr", 1, [{"type": "trim", "column": "id"}])
        self.assertEqual(result["row_count"], 1)
        self.assertEqual(result["lineage"]["rowMapping"], [1])
        stored = (self.catalog.workspace / result["blob"]).read_bytes()
        header, rows = _read_csv_records(stored)
        self.assertEqual(header, ["id", "说明"])
        self.assertEqual(rows, [["1", "甲\r乙"]])
        # the carriage return is preserved verbatim inside a quoted field
        self.assertEqual(stored, 'id,说明\n1,"甲\r乙"\n'.encode("utf-8"))

    def test_bare_carriage_return_round_trips_through_compare_export_verify(self):
        self.catalog.import_csv(
            "cr",
            self.csv_file('id,说明\n1,"甲\r乙"\n', "cr.csv"),
        )
        cleaned = self.catalog.clean("cr", 1, [{"type": "trim", "column": "id"}])
        diff = self.catalog.compare("cr", 1, cleaned["version"], ["id"])["rowDiff"]
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["unchangedCount"], 1)
        destination = self.root / "out"
        self.catalog.export("cr", cleaned["version"], destination)
        report = self.catalog.verify_export(destination)
        self.assertTrue(report["passed"], report["issues"])

    def test_bare_carriage_return_in_renamed_header_survives(self):
        self.catalog.import_csv(
            "cr",
            self.csv_file('id,说明\n1,"甲\r乙"\n', "cr.csv"),
        )
        result = self.catalog.clean(
            "cr", 1, [{"type": "rename", "column": "说明", "to": "b\rc"}]
        )
        stored = (self.catalog.workspace / result["blob"]).read_bytes()
        header, rows = _read_csv_records(stored)
        self.assertEqual(header, ["id", "b\rc"])
        self.assertEqual(rows, [["1", "甲\r乙"]])
        self.assertEqual(result["schema"], {"id": "integer", "b\rc": "string"})
        self.assertEqual(result["lineage"]["columnMapping"], {"id": "id", "b\rc": "说明"})

    def test_header_with_bare_carriage_return_and_zero_rows_stays_empty(self):
        self.catalog.import_csv(
            "crh",
            self.csv_file('id,"a\rb"\n', "crh.csv"),
        )
        result = self.catalog.clean("crh", 1, [{"type": "trim", "column": "id"}])
        self.assertEqual(result["row_count"], 0)
        self.assertEqual(result["lineage"]["rowMapping"], [])
        self.assertEqual(result["schema"], {"id": "null", "a\rb": "null"})
        stored = (self.catalog.workspace / result["blob"]).read_bytes()
        header, rows = _read_csv_records(stored)
        self.assertEqual(header, ["id", "a\rb"])
        self.assertEqual(rows, [])

    def test_csv_serializer_quotes_bare_carriage_return_everywhere(self):
        from governance_workbench.catalog import _write_csv_table

        # A bare CR in any cell or header position must be emitted quoted so
        # the reader cannot take it for a record boundary, and the table must
        # parse back to exactly what was serialized.
        tables = [
            [["id", "甲\r乙"], ["1", "甲\r乙"]],
            [["a\rb"]],
            [["a\r", "b"], ["1", "2"]],
            [["a", "b"], ["1", "\r"]],
            [["a", "b"], ["1", "甲\r\n乙"]],
        ]
        for table in tables:
            text = _write_csv_table(table)
            # Every carriage return must live inside a quoted field; strip the
            # quoted spans and confirm no bare CR remains as a record boundary.
            bare = re.sub(r'"(?:""|[^"])*"', "", text)
            self.assertNotIn("\r", bare)
            parsed = [row for row in csv_module.reader(io.StringIO(text, newline="")) if row != []]
            self.assertEqual(parsed, table)

    def test_csv_serializer_matches_writer_for_values_without_bare_cr(self):
        from governance_workbench.catalog import _write_csv_table

        # Comma, quote, newline, CRLF and empty-field handling must keep the
        # exact pre-existing bytes; only the bare-CR guarantee is new.
        table = [
            ["id", "name", "note", "empty"],
            ["1", 'Ann "Q"', "line one\nline two", ""],
            ["2", "Bob, Jr.", "a\r\nb", ""],
            [""],
        ]
        buffer = io.StringIO()
        writer = csv_module.writer(buffer, lineterminator="\n")
        for row in table:
            writer.writerow(row)
        self.assertEqual(_write_csv_table(table), buffer.getvalue())

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

    def test_range_large_integer_bounds_via_cli(self):
        (self.root / "big.csv").write_text(
            "v\n9007199254740992\n9007199254740993\n9.007199254740992e15\n",
            encoding="utf-8",
        )
        self.assertEqual(self.run_cli("import", "d", str(self.root / "big.csv")).returncode, 0)

        rules_path = self.root / "big-rules.json"
        rules_path.write_text(json.dumps([
            {"id": "r", "column": "v", "type": "range", "max": 9007199254740992},
        ]), encoding="utf-8")
        result = self.run_cli("rules", "d", str(rules_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        rule = json.loads(result.stdout)["rules"][0]
        self.assertEqual(rule["max"], 9007199254740992)
        self.assertNotIn("min", rule)

        result = self.run_cli("validate", "d", "1")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["passed"])
        self.assertEqual(report["results"][0]["violations"], [2])
        self.assertEqual(report["results"][0]["violationCount"], 1)

        # min > max with float-collapsible integers: error JSON on stderr,
        # exit 2, no revision consumed
        bad_rules = self.root / "bad-big-rules.json"
        bad_rules.write_text(json.dumps([
            {"id": "r", "column": "v", "type": "range",
             "min": 9007199254740993, "max": 9007199254740992},
        ]), encoding="utf-8")
        result = self.run_cli("rules", "d", str(bad_rules))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})
        # the rejected configuration consumed no revision number
        result = self.run_cli("rules", "d", str(rules_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["revision"], 2)

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

    def test_reference_rule_commands_and_exit_codes(self):
        (self.root / "customers.csv").write_text("编号,地区\nC1,北\nC2,南\n", encoding="utf-8")
        (self.root / "orders.csv").write_text("客户号,地区\nC1,北\nC9,北\n", encoding="utf-8")
        self.assertEqual(self.run_cli("import", "客户", str(self.root / "customers.csv")).returncode, 0)
        self.assertEqual(self.run_cli("import", "orders", str(self.root / "orders.csv")).returncode, 0)

        rules_path = self.root / "rules.json"
        rules_path.write_text(json.dumps([
            {"id": "客户引用", "type": "reference", "columns": ["客户号", "地区"],
             "reference": {"dataset": "客户", "version": 1, "columns": ["编号", "地区"]}},
            {"id": "地区必填", "column": "地区", "type": "required"},
        ], ensure_ascii=False), encoding="utf-8")
        result = self.run_cli("rules", "orders", str(rules_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["revision"], 1)

        # violations on stdout with exit 1
        result = self.run_cli("validate", "orders", "1")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["passed"])
        reference_result = report["results"][0]
        self.assertEqual(reference_result["type"], "reference")
        self.assertEqual(reference_result["columns"], ["客户号", "地区"])
        self.assertEqual(reference_result["reference"]["dataset"], "客户")
        self.assertEqual(reference_result["reference"]["version"], 1)
        self.assertRegex(reference_result["reference"]["content_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(reference_result["violations"], [2])

        # persisted report comes back from the history command
        result = self.run_cli("validations", "orders", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [report])

        # an unknown reference target fails configuration with the envelope
        bad_rules = self.root / "bad-rules.json"
        bad_rules.write_text(json.dumps([
            {"id": "r", "type": "reference", "columns": ["客户号"],
             "reference": {"dataset": "客户", "version": 9, "columns": ["编号"]}},
        ]), encoding="utf-8")
        result = self.run_cli("rules", "orders", str(bad_rules))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(set(json.loads(result.stderr)), {"error"})

        # a tampered reference file fails revalidation with the envelope
        catalog = Catalog(self.workspace)
        blob = catalog.workspace / catalog.get("客户", 1)["blob"]
        blob.write_text("编号,地区\nC1,北\n", encoding="utf-8")
        result = self.run_cli("validate", "orders", "1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        payload = json.loads(result.stderr)
        self.assertEqual(set(payload), {"error"})
        self.assertIn("客户@1", payload["error"])

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


if __name__ == "__main__":
    unittest.main()
