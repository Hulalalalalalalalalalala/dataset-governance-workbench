from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import tempfile
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_RULE_TYPES = {"required", "unique", "range"}
_REFERENCE_TYPE = "reference"
_RULE_KEYS = {"id", "column", "type", "min", "max"}
_REFERENCE_RULE_KEYS = {"id", "type", "columns", "reference"}
_REFERENCE_KEYS = {"dataset", "version", "columns"}
_TYPE_NAMES = {"null", "boolean", "integer", "number", "string"}
_OPERATION_KEYS = {
    "trim": {"type", "column"},
    "rename": {"type", "column", "to"},
    "drop_duplicates": {"type", "columns"},
}
_NUMBER_RE = re.compile(r"[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?\Z")
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")


def _is_int(value: Any) -> bool:
    # bool is a subclass of int and is not accepted anywhere integers are.
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH_RE.fullmatch(value))


def _finite_number(value: str) -> float | None:
    """Parse a raw CSV cell as a finite number.

    Whitespace is never stripped, underscores and tokens such as ``inf`` or
    ``nan`` are rejected, so only literal numeric strings are accepted.
    """
    if not _NUMBER_RE.match(value):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _kind(value: str) -> str:
    if value == "":
        return "null"
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return "boolean"
    try:
        int(value)
        return "integer"
    except ValueError:
        pass
    try:
        float(value)
        return "number"
    except ValueError:
        return "string"


def _merge_kinds(values: set[str]) -> str:
    values.discard("null")
    if not values:
        return "null"
    if values <= {"integer"}:
        return "integer"
    if values <= {"integer", "number"}:
        return "number"
    if len(values) == 1:
        return next(iter(values))
    return "string"


def _ends_inside_quote(text: str) -> bool:
    """Return whether the text ends inside an unterminated quoted field.

    This is a faithful transcription of the non-strict csv reader's
    per-character field state (START_FIELD / IN_FIELD / IN_QUOTED_FIELD /
    AFTER_QUOTE), so it agrees with import parsing: text immediately after
    a closing quote is legal and does not reopen a field, while a quote
    opened at the start of a field and never closed runs to the end.
    """
    start_field, in_field, in_quoted, after_quote = 0, 1, 2, 3
    state = start_field
    for char in text:
        if state == start_field:
            if char == '"':
                state = in_quoted
            elif char in (",", "\r", "\n"):
                state = start_field
            else:
                state = in_field
        elif state == in_field:
            if char in (",", "\r", "\n"):
                state = start_field
        elif state == in_quoted:
            if char == '"':
                state = after_quote
        else:  # after_quote
            if char == '"':
                state = in_quoted
            elif char in (",", "\r", "\n"):
                state = start_field
            else:
                state = in_field
    return state == in_quoted


def _read_csv_records(content: bytes) -> tuple[list[str], list[list[str]]]:
    """Strictly parse CSV bytes into a header list and data records.

    The rules match export verification: UTF-8 decodable, a header row of
    non-empty, non-duplicate field names, and every data record with exactly
    as many fields as the header. Blank physical lines are not records and a
    newline inside a quoted field does not advance the record number. Parsing
    uses the same non-strict :mod:`csv` reader as every other stage, so text
    immediately following a closing quote stays legal and values are never
    trimmed or rewritten.
    """
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"CSV is not valid UTF-8: {error.reason}") from error
    if _ends_inside_quote(text):
        raise ValueError("CSV has a quoted field that is never closed")
    try:
        parsed = [row for row in csv.reader(io.StringIO(text, newline="")) if row != []]
    except csv.Error as error:
        raise ValueError(f"CSV could not be parsed: {error}") from error
    if not parsed:
        raise ValueError("CSV has no header row")
    header = parsed[0]
    empty_positions = [
        position + 1 for position, name in enumerate(header) if name == ""
    ]
    if empty_positions:
        raise ValueError(
            "CSV header has empty field name(s) at "
            f"position(s) {empty_positions}"
        )
    seen: set[str] = set()
    duplicates: list[str] = []
    for name in header:
        if name in seen and name not in duplicates:
            duplicates.append(name)
        seen.add(name)
    if duplicates:
        raise ValueError(
            "CSV header has duplicate field name(s): "
            + ", ".join(repr(name) for name in duplicates)
        )
    rows: list[list[str]] = []
    for record_number, record in enumerate(parsed[1:], start=1):
        if len(record) != len(header):
            raise ValueError(
                f"CSV data record {record_number} has {len(record)} field(s), "
                f"expected {len(header)}"
            )
        rows.append(record)
    return header, rows


@dataclass(frozen=True)
class DatasetVersion:
    dataset: str
    version: int
    source_name: str
    content_sha256: str
    row_count: int
    schema: dict[str, str]
    imported_at: str
    blob: str


class Catalog:
    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace).resolve()
        self.control = self.workspace / ".dgw"
        self.blobs = self.control / "blobs"
        self.state_path = self.control / "catalog.json"

    def _load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"schemaVersion": 1, "datasets": {}, "rules": {}, "validations": {}, "lineage": {}}
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        state.setdefault("rules", {})
        state.setdefault("validations", {})
        state.setdefault("lineage", {})
        return state

    def _save(self, state: dict[str, Any]) -> None:
        self.control.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.state_path)

    def import_csv(self, dataset: str, source: str | Path) -> DatasetVersion:
        if not dataset or any(character in dataset for character in "/\\\0"):
            raise ValueError("dataset must be a non-empty portable name")
        source_path = Path(source).resolve(strict=True)

        # Snapshot the source once as raw bytes: the hash, the parsed shape,
        # and the stored blob all derive from this same read, so replacing or
        # rewriting the source file mid-import can never publish a version
        # whose record disagrees with what was stored.
        with source_path.open("rb") as handle:
            content = handle.read()
        content_hash = hashlib.sha256(content).hexdigest()
        header, rows = _read_csv_records(content)

        observed = {name: set() for name in header}
        for row in rows:
            for position, name in enumerate(header):
                observed[name].add(_kind(row[position]))
        row_count = len(rows)

        self.blobs.mkdir(parents=True, exist_ok=True)
        blob = self.blobs / f"{content_hash}.csv"
        if blob.exists():
            # Content-addressed storage may be shared, but only trust an
            # existing file once its bytes match the claimed hash; a damaged
            # blob is reported, never overwritten or "repaired" for the
            # versions that already point at it.
            if _sha256(blob) != content_hash:
                raise OSError(
                    f"stored blob {blob.name} is corrupt: content does not "
                    "match its hash"
                )
        else:
            # Land the blob through a unique temporary file in the same
            # directory and atomically name it only after a full flush; a
            # write failure leaves no file at the content-addressed path.
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{content_hash}.", suffix=".tmp", dir=self.blobs
            )
            temporary = Path(temporary_name)
            try:
                # mkstemp defaults to 0600; match the ordinary create-mode
                # (0666 masked by the umask) that a plain file copy would use.
                umask = os.umask(0)
                os.umask(umask)
                os.fchmod(descriptor, 0o666 & ~umask)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.replace(blob)
            except BaseException:
                with suppress(OSError):
                    temporary.unlink()
                raise

        state = self._load()
        versions = state["datasets"].setdefault(dataset, [])
        record = DatasetVersion(
            dataset=dataset,
            version=len(versions) + 1,
            source_name=source_path.name,
            content_sha256=content_hash,
            row_count=row_count,
            schema={name: _merge_kinds(kinds) for name, kinds in observed.items()},
            imported_at=datetime.now(timezone.utc).isoformat(),
            blob=str(blob.relative_to(self.workspace)),
        )
        versions.append(asdict(record))
        self._save(state)
        return record

    def list_datasets(self) -> dict[str, list[dict[str, Any]]]:
        return self._load()["datasets"]

    def get(self, dataset: str, version: int) -> dict[str, Any]:
        versions = self._load()["datasets"].get(dataset, [])
        if version < 1 or version > len(versions):
            raise KeyError(f"unknown dataset version: {dataset}@{version}")
        return versions[version - 1]

    @staticmethod
    def _validate_compare_keys(keys: Any) -> list[str]:
        if not isinstance(keys, list) or not keys:
            raise ValueError("keys must be a non-empty list")
        for key in keys:
            if not isinstance(key, str) or not key:
                raise ValueError("keys must contain only non-empty strings")
        if len(set(keys)) != len(keys):
            raise ValueError("keys must not contain duplicates")
        return list(keys)

    def _row_diff(
        self,
        dataset: str,
        left: int,
        right: int,
        keys: list[str],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        # Verify both stored blobs against their version records before any
        # parsing, including when both sides are the same version.
        left_record = self._version_record(state, dataset, left)
        right_record = self._version_record(state, dataset, right)
        for record, version in ((left_record, left), (right_record, right)):
            blob_path = self.workspace / record["blob"]
            if not blob_path.exists():
                raise ValueError(f"stored data missing for {dataset}@{version}")
            if _sha256(blob_path) != record["content_sha256"]:
                raise ValueError(f"stored data hash mismatch for {dataset}@{version}")
        try:
            left_header, left_rows = self._read_stored_csv(
                self.workspace / left_record["blob"], dataset, left
            )
            if right_record["blob"] == left_record["blob"]:
                right_header, right_rows = left_header, left_rows
            else:
                right_header, right_rows = self._read_stored_csv(
                    self.workspace / right_record["blob"], dataset, right
                )
        except csv.Error as error:
            raise ValueError(f"stored CSV could not be parsed: {error}")

        for side, header, version in (
            ("left", left_header, left),
            ("right", right_header, right),
        ):
            missing = [name for name in keys if name not in header]
            if missing:
                raise ValueError(
                    f"key column(s) {missing} missing on the {side} side of {dataset}@{version}"
                )

        all_fields = sorted(set(left_header) | set(right_header))

        def index_side(header: list[str], rows: list[list[str]], side: str, version: int):
            key_positions = [header.index(name) for name in keys]
            field_positions = {
                name: header.index(name) for name in header
            }
            indexed: dict[tuple[str, ...], tuple[int, dict[str, Any]]] = {}
            for row_number, row in enumerate(rows, start=1):
                key = tuple(row[position] for position in key_positions)
                # An empty key cell invalidates the whole comparison; a
                # whitespace-only string is still a valid key value.
                if any(part == "" for part in key):
                    raise ValueError(
                        f"empty key value in {dataset}@{version} {side} row {row_number}"
                    )
                if key in indexed:
                    raise ValueError(
                        f"duplicate key {list(key)!r} in {dataset}@{version} {side}"
                    )
                values = {
                    name: (row[field_positions[name]] if name in field_positions else None)
                    for name in all_fields
                }
                indexed[key] = (row_number, values)
            return indexed

        left_index = index_side(left_header, left_rows, "left", left)
        right_index = index_side(right_header, right_rows, "right", right)

        added: list[dict[str, Any]] = []
        removed: list[dict[str, Any]] = []
        modified: list[dict[str, Any]] = []
        unchanged_count = 0
        for key, (right_row, right_values) in right_index.items():
            if key not in left_index:
                added.append({"key": list(key), "row": right_row, "values": right_values})
                continue
            left_row, left_values = left_index[key]
            changes = {
                field: {"from": left_values[field], "to": right_values[field]}
                for field in all_fields
                if left_values[field] != right_values[field]
            }
            if changes:
                modified.append(
                    {
                        "key": list(key),
                        "leftRow": left_row,
                        "rightRow": right_row,
                        "changes": changes,
                    }
                )
            else:
                unchanged_count += 1
        for key, (left_row, left_values) in left_index.items():
            if key not in right_index:
                removed.append({"key": list(key), "row": left_row, "values": left_values})

        added.sort(key=lambda item: item["row"])
        modified.sort(key=lambda item: item["rightRow"])
        removed.sort(key=lambda item: item["row"])
        return {
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchangedCount": unchanged_count,
        }

    def compare(
        self,
        dataset: str,
        left: int,
        right: int,
        keys: list[str] | None = None,
    ) -> dict[str, Any]:
        if keys is not None:
            key_columns = self._validate_compare_keys(keys)
            state = self._load()
            before = self._version_record(state, dataset, left)
            after = self._version_record(state, dataset, right)
        else:
            key_columns = None
            state = None
            before, after = self.get(dataset, left), self.get(dataset, right)
        before_schema, after_schema = before["schema"], after["schema"]
        result = {
            "dataset": dataset,
            "left": left,
            "right": right,
            "addedFields": sorted(after_schema.keys() - before_schema.keys()),
            "removedFields": sorted(before_schema.keys() - after_schema.keys()),
            "changedFields": {
                name: {"from": before_schema[name], "to": after_schema[name]}
                for name in sorted(before_schema.keys() & after_schema.keys())
                if before_schema[name] != after_schema[name]
            },
            "contentChanged": before["content_sha256"] != after["content_sha256"],
            "rowDelta": after["row_count"] - before["row_count"],
        }
        if key_columns is not None:
            result["rowDiff"] = self._row_diff(dataset, left, right, key_columns, state)
        return result

    def export(self, dataset: str, version: int, destination: str | Path) -> dict[str, Any]:
        record = self.get(dataset, version)
        destination_path = Path(destination).resolve()
        destination_path.mkdir(parents=True, exist_ok=True)
        source = self.workspace / record["blob"]
        data_path = destination_path / f"{dataset}-v{version}.csv"
        shutil.copyfile(source, data_path)
        manifest = {"schemaVersion": 1, "record": record, "file": data_path.name}
        lineage_records = self._load()["lineage"].get(dataset, {})
        if str(version) in lineage_records:
            # Cleaned versions carry their full lineage chain in the manifest.
            manifest["lineage"] = self.lineage(dataset, version)["chain"]
        manifest_path = destination_path / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return manifest

    # ------------------------------------------------------------------
    # Offline export verification
    # ------------------------------------------------------------------

    @staticmethod
    def _verified_manifest_record(record: Any) -> dict[str, Any]:
        """Validate the ``record`` object embedded in an export manifest."""
        if not isinstance(record, dict):
            raise ValueError("manifest record must be an object")
        dataset = record.get("dataset")
        if not isinstance(dataset, str) or not dataset:
            raise ValueError("manifest record.dataset must be a non-empty string")
        version = record.get("version")
        if not _is_int(version) or version < 1:
            raise ValueError("manifest record.version must be a positive integer")
        content_hash = record.get("content_sha256")
        if not _is_hash(content_hash):
            raise ValueError(
                "manifest record.content_sha256 must be 64 lowercase hexadecimal characters"
            )
        row_count = record.get("row_count")
        if not _is_int(row_count) or row_count < 0:
            raise ValueError("manifest record.row_count must be a non-negative integer")
        schema = record.get("schema")
        if not isinstance(schema, dict) or not schema:
            raise ValueError("manifest record.schema must be a non-empty object")
        for name, kind in schema.items():
            if not isinstance(name, str) or not name:
                raise ValueError("manifest record.schema field names must be non-empty strings")
            if not isinstance(kind, str) or kind not in _TYPE_NAMES:
                raise ValueError(
                    f"manifest record.schema declares an invalid type for field {name!r}"
                )
        return record

    @staticmethod
    def _verified_lineage_entry(entry: Any) -> dict[str, Any] | None:
        """Validate the linkage fields of one lineage chain entry."""
        if not isinstance(entry, dict):
            return None
        dataset = entry.get("dataset")
        if not isinstance(dataset, str) or not dataset:
            return None
        version = entry.get("version")
        if not _is_int(version) or version < 1:
            return None
        source_version = entry.get("sourceVersion")
        if not _is_int(source_version) or source_version < 1:
            return None
        if not _is_hash(entry.get("sourceSha256")) or not _is_hash(entry.get("contentSha256")):
            return None
        row_count = entry.get("rowCount")
        if not _is_int(row_count) or row_count < 0:
            return None
        return entry

    def _lineage_issues(
        self, chain: Any, record: dict[str, Any], issues: list[dict[str, str]]
    ) -> None:
        if not isinstance(chain, list):
            issues.append({"code": "lineage", "message": "lineage must be an array"})
            return
        entries: list[dict[str, Any] | None] = []
        for index, raw_entry in enumerate(chain):
            entry = self._verified_lineage_entry(raw_entry)
            if entry is None:
                issues.append(
                    {
                        "code": "lineage",
                        "message": f"lineage entry {index + 1} is missing required fields "
                        "or uses invalid field types",
                    }
                )
            entries.append(entry)

        for index, entry in enumerate(entries):
            if entry is None:
                continue
            if entry["dataset"] != record["dataset"]:
                issues.append(
                    {
                        "code": "lineage",
                        "message": f"lineage entry {index + 1} belongs to dataset "
                        f"{entry['dataset']!r}, expected {record['dataset']!r}",
                    }
                )
            if entry["sourceVersion"] >= entry["version"]:
                issues.append(
                    {
                        "code": "lineage",
                        "message": f"lineage entry {index + 1} has source version "
                        f"{entry['sourceVersion']} that is not below version {entry['version']}",
                    }
                )

        for index in range(1, len(entries)):
            previous, current = entries[index - 1], entries[index]
            if previous is None or current is None:
                continue
            if current["sourceVersion"] != previous["version"]:
                issues.append(
                    {
                        "code": "lineage",
                        "message": f"lineage entry {index + 1} continues version "
                        f"{current['sourceVersion']} but the previous entry is version "
                        f"{previous['version']}",
                    }
                )
            elif current["sourceSha256"] != previous["contentSha256"]:
                issues.append(
                    {
                        "code": "lineage",
                        "message": f"lineage entry {index + 1} source hash does not match "
                        "the content hash of the previous entry",
                    }
                )

        if entries:
            last = entries[-1]
            if last is not None:
                if last["version"] != record["version"]:
                    issues.append(
                        {
                            "code": "lineage",
                            "message": f"last lineage entry is version {last['version']} but "
                            f"the record is version {record['version']}",
                        }
                    )
                if last["contentSha256"] != record["content_sha256"]:
                    issues.append(
                        {
                            "code": "lineage",
                            "message": "last lineage entry content hash does not match the "
                            "record hash",
                        }
                    )
                if last["rowCount"] != record["row_count"]:
                    issues.append(
                        {
                            "code": "lineage",
                            "message": f"last lineage entry reports {last['rowCount']} records "
                            f"but the record reports {record['row_count']}",
                        }
                    )

    def verify_export(self, directory: str | Path) -> dict[str, Any]:
        """Verify an exported directory offline against its manifest.

        Only ``manifest.json`` and the CSV it names inside *directory* are
        read; no workspace state is consulted and nothing is written.
        Manifest or parameter problems raise ValueError, read failures
        OSError. Data discrepancies are returned as issue objects grouped
        by code: missing, hash, csv, rows, schema, lineage.
        """
        manifest_path = Path(directory) / "manifest.json"
        try:
            manifest_text = manifest_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"manifest is not valid UTF-8: {error}") from error
        try:
            manifest = json.loads(manifest_text)
        except json.JSONDecodeError as error:
            raise ValueError(f"manifest is not valid JSON: {error}") from error

        if not isinstance(manifest, dict):
            raise ValueError("manifest must be a JSON object")
        schema_version = manifest.get("schemaVersion")
        if not _is_int(schema_version) or schema_version != 1:
            raise ValueError("manifest schemaVersion must be the integer 1")
        if "record" not in manifest:
            raise ValueError("manifest is missing required field: record")
        if "file" not in manifest:
            raise ValueError("manifest is missing required field: file")
        record = self._verified_manifest_record(manifest["record"])
        file_name = manifest["file"]
        if (
            not isinstance(file_name, str)
            or not file_name
            or file_name in (".", "..")
            or "/" in file_name
            or "\\" in file_name
            or "\0" in file_name
        ):
            raise ValueError(
                "manifest file must be a non-empty file name without path separators"
            )

        # Resolve purely lexically (no target content is read) and refuse
        # anything that escapes the export directory, including via links.
        base = Path(directory).resolve()
        try:
            resolved = (base / file_name).resolve(strict=False)
        except (OSError, RuntimeError):
            # Python 3.12 reports a symlink loop as RuntimeError. The
            # underlying message embeds a machine path and is intentionally
            # not surfaced.
            raise ValueError(
                f"manifest file {file_name!r} could not be safely resolved "
                "(broken or looping reference)"
            )
        if resolved != base and base not in resolved.parents:
            raise ValueError(
                f"manifest file {file_name!r} resolves outside the export directory"
            )

        issues: list[dict[str, str]] = []
        lineage = manifest.get("lineage")
        if lineage is not None:
            # Missing or null lineage means no chain was shipped; an empty
            # array is likewise a chain-free (legacy) export.
            self._lineage_issues(lineage, record, issues)

        if not resolved.exists():
            issues.append(
                {
                    "code": "missing",
                    "message": f"data file {file_name!r} listed in the manifest is missing",
                }
            )
        else:
            data = resolved.read_bytes()
            content_hash = hashlib.sha256(data).hexdigest()
            if content_hash != record["content_sha256"]:
                issues.append(
                    {
                        "code": "hash",
                        "message": "CSV content hash does not match the manifest record",
                    }
                )

            header: list[str] | None = None
            rows: list[list[str]] = []
            header_ok = False
            records_ok = False
            can_parse = True
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as error:
                issues.append(
                    {"code": "csv", "message": f"CSV is not valid UTF-8: {error.reason}"}
                )
                text = ""
                can_parse = False
            if can_parse and _ends_inside_quote(text):
                issues.append(
                    {"code": "csv", "message": "CSV has a quoted field that is never closed"}
                )
                can_parse = False
            if can_parse:
                parse_failed = False
                try:
                    # Non-strict parsing matches import semantics: only the
                    # explicitly enumerated structural problems are failures.
                    parsed = [
                        row
                        for row in csv.reader(io.StringIO(text, newline=""))
                        if row != []
                    ]
                except csv.Error as error:
                    issues.append(
                        {"code": "csv", "message": f"CSV structure is invalid: {error}"}
                    )
                    parsed = []
                    parse_failed = True
                if not parsed and not parse_failed:
                    issues.append({"code": "csv", "message": "CSV has no header row"})
                elif parsed:
                    header = parsed[0]
                    rows = parsed[1:]
                    empty_positions = [
                        position + 1 for position, name in enumerate(header) if name == ""
                    ]
                    if empty_positions:
                        issues.append(
                            {
                                "code": "csv",
                                "message": "CSV header has empty field name(s) at "
                                f"position(s) {empty_positions}",
                            }
                        )
                    seen: set[str] = set()
                    duplicates: list[str] = []
                    for name in header:
                        if name in seen and name not in duplicates:
                            duplicates.append(name)
                        seen.add(name)
                    if duplicates:
                        issues.append(
                            {
                                "code": "csv",
                                "message": "CSV header has duplicate field name(s): "
                                + ", ".join(repr(name) for name in duplicates),
                            }
                        )
                    header_ok = not empty_positions and not duplicates
                    ragged = [
                        row_number
                        for row_number, row in enumerate(rows, start=1)
                        if len(row) != len(header)
                    ]
                    if ragged:
                        issues.append(
                            {
                                "code": "csv",
                                "message": f"CSV record(s) {ragged} do not have the same "
                                f"number of fields as the header ({len(header)})",
                            }
                        )
                    records_ok = header_ok and not ragged

            if header is not None:
                # Record numbering ignores blank physical lines and quoted
                # newlines already, so the count stays determinable even when
                # individual records are ragged.
                if len(rows) != record["row_count"]:
                    issues.append(
                        {
                            "code": "rows",
                            "message": f"CSV contains {len(rows)} data record(s) but the "
                            f"manifest record lists {record['row_count']}",
                        }
                    )

            if header_ok:
                # The field set is fixed by the header and stays checkable
                # even when some data records are ragged.
                assert header is not None
                expected_schema = record["schema"]
                actual_fields = set(header)
                missing_fields = sorted(name for name in expected_schema if name not in actual_fields)
                extra_fields = sorted(name for name in actual_fields if name not in expected_schema)
                if missing_fields or extra_fields:
                    details = []
                    if missing_fields:
                        details.append("missing from CSV: " + ", ".join(missing_fields))
                    if extra_fields:
                        details.append("unexpected in CSV: " + ", ".join(extra_fields))
                    issues.append(
                        {
                            "code": "schema",
                            "message": "CSV field set does not match the manifest record ("
                            + "; ".join(details)
                            + ")",
                        }
                    )
                if records_ok:
                    # Type inference needs consistent column counts so each
                    # value can be aligned with its header position.
                    observed = {name: set() for name in header}
                    for row in rows:
                        for position, name in enumerate(header):
                            observed[name].add(_kind(row[position]))
                    inferred = {
                        name: _merge_kinds(kinds) for name, kinds in observed.items()
                    }
                    for name in sorted(expected_schema):
                        if name in inferred and inferred[name] != expected_schema[name]:
                            issues.append(
                                {
                                    "code": "schema",
                                    "message": f"field {name!r} infers as {inferred[name]!r} "
                                    f"but the manifest record declares "
                                    f"{expected_schema[name]!r}",
                                }
                            )

        category_order = {
            "missing": 0,
            "hash": 1,
            "csv": 2,
            "rows": 3,
            "schema": 4,
            "lineage": 5,
        }
        issues.sort(key=lambda issue: category_order[issue["code"]])
        return {
            "dataset": record["dataset"],
            "version": record["version"],
            "passed": not issues,
            "issues": issues,
        }

    @staticmethod
    def _validate_rules_payload(rules: Any) -> list[dict[str, Any]]:
        if not isinstance(rules, list) or not rules:
            raise ValueError("rules must be a non-empty array")
        normalized: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for index, rule in enumerate(rules):
            where = f"rules[{index}]"
            if not isinstance(rule, dict):
                raise ValueError(f"{where} must be an object")
            rule_type = rule.get("type")
            identifier = rule.get("id")
            if not isinstance(identifier, str) or not identifier:
                raise ValueError(f"{where}.id must be a non-empty string")
            if identifier in seen_ids:
                raise ValueError(f"duplicate rule id: {identifier}")
            if rule_type == _REFERENCE_TYPE:
                if set(rule) != _REFERENCE_RULE_KEYS:
                    raise ValueError(
                        f"{where} must have exactly the attributes "
                        f"{sorted(_REFERENCE_RULE_KEYS)}"
                    )
                columns = rule["columns"]
                if not isinstance(columns, list) or not columns:
                    raise ValueError(f"{where}.columns must be a non-empty array")
                if any(not isinstance(name, str) or not name for name in columns):
                    raise ValueError(f"{where}.columns must contain only non-empty strings")
                if len(set(columns)) != len(columns):
                    raise ValueError(f"{where}.columns must not contain duplicates")
                reference = rule["reference"]
                if not isinstance(reference, dict):
                    raise ValueError(f"{where}.reference must be an object")
                if set(reference) != _REFERENCE_KEYS:
                    raise ValueError(
                        f"{where}.reference must have exactly the attributes "
                        f"{sorted(_REFERENCE_KEYS)}"
                    )
                ref_dataset = reference["dataset"]
                if not isinstance(ref_dataset, str) or not ref_dataset:
                    raise ValueError(
                        f"{where}.reference.dataset must be a non-empty string"
                    )
                ref_version = reference["version"]
                if not _is_int(ref_version) or ref_version < 1:
                    raise ValueError(
                        f"{where}.reference.version must be a positive integer"
                    )
                ref_columns = reference["columns"]
                if not isinstance(ref_columns, list) or not ref_columns:
                    raise ValueError(
                        f"{where}.reference.columns must be a non-empty array"
                    )
                if any(not isinstance(name, str) or not name for name in ref_columns):
                    raise ValueError(
                        f"{where}.reference.columns must contain only non-empty strings"
                    )
                if len(set(ref_columns)) != len(ref_columns):
                    raise ValueError(f"{where}.reference.columns must not contain duplicates")
                if len(columns) != len(ref_columns):
                    raise ValueError(
                        f"{where}.columns and reference.columns must have the same length"
                    )
                entry: dict[str, Any] = {
                    "id": identifier,
                    "type": _REFERENCE_TYPE,
                    "columns": list(columns),
                    "reference": {
                        "dataset": ref_dataset,
                        "version": ref_version,
                        "columns": list(ref_columns),
                    },
                }
            else:
                if rule_type not in _RULE_TYPES:
                    raise ValueError(
                        f"{where}.type must be one of "
                        f"{sorted(_RULE_TYPES | {_REFERENCE_TYPE})}"
                    )
                extra = set(rule) - _RULE_KEYS
                if extra:
                    raise ValueError(f"{where} has unknown attributes: {sorted(extra)}")
                column = rule.get("column")
                if not isinstance(column, str) or not column:
                    raise ValueError(f"{where}.column must be a non-empty column name")
                entry = {"id": identifier, "column": column, "type": rule_type}
                if rule_type == "range":
                    if "min" not in rule and "max" not in rule:
                        raise ValueError(f"{where} range requires min or max")
                    bounds: dict[str, float] = {}
                    for key in ("min", "max"):
                        if key not in rule:
                            continue
                        bound = rule[key]
                        # bool is a subclass of int; boundaries must be finite
                        # numbers rather than booleans.
                        if not isinstance(bound, (int, float)) or isinstance(bound, bool):
                            raise ValueError(f"{where}.{key} must be a finite number")
                        bound = float(bound)
                        if not math.isfinite(bound):
                            raise ValueError(f"{where}.{key} must be a finite number")
                        bounds[key] = bound
                    if "min" in bounds and "max" in bounds and bounds["min"] > bounds["max"]:
                        raise ValueError(f"{where} min must not be greater than max")
                    entry.update(bounds)
                elif "min" in rule or "max" in rule:
                    raise ValueError(f"{where} bounds are only valid for range rules")
            seen_ids.add(identifier)
            normalized.append(entry)
        return normalized

    def _stored_header(self, state: dict[str, Any], dataset: str, version: int) -> list[str]:
        """Read just the header of a stored version's CSV.

        Rule configuration only needs the reference dataset, version, and
        columns to exist; the stored blob is not re-hashed here (validation
        re-verifies every side on every run).
        """
        record = self._version_record(state, dataset, version)
        blob_path = self.workspace / record["blob"]
        if not blob_path.exists():
            raise ValueError(f"stored data missing for {dataset}@{version}")
        try:
            with blob_path.open("r", encoding="utf-8", newline="") as handle:
                parsed = [row for row in csv.reader(handle) if row != []]
        except csv.Error as error:
            raise ValueError(f"stored CSV could not be parsed: {error}") from error
        if not parsed:
            raise ValueError(f"stored CSV for {dataset}@{version} has no header")
        header = parsed[0]
        if any(name == "" for name in header):
            raise ValueError(f"stored CSV for {dataset}@{version} has an empty header field")
        if len(set(header)) != len(header):
            raise ValueError(f"stored CSV for {dataset}@{version} has duplicate header fields")
        return header

    def set_rules(self, dataset: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
        state = self._load()
        if dataset not in state["datasets"]:
            raise ValueError(f"unknown dataset: {dataset}")
        normalized = self._validate_rules_payload(rules)
        # Reference rules pin a fixed dataset/version combination: at
        # configuration time the reference dataset, version, and reference
        # columns must exist. The left-side columns are checked when the
        # selected data version is validated. Any failure here happens
        # before the revision is appended, so no revision is consumed.
        for rule in normalized:
            if rule["type"] != _REFERENCE_TYPE:
                continue
            reference = rule["reference"]
            ref_dataset = reference["dataset"]
            ref_version = reference["version"]
            self._version_record(state, ref_dataset, ref_version)
            header = self._stored_header(state, ref_dataset, ref_version)
            missing = [name for name in reference["columns"] if name not in header]
            if missing:
                raise ValueError(
                    f"reference column(s) {missing} missing for "
                    f"{ref_dataset}@{ref_version}"
                )
        history = state["rules"].setdefault(dataset, [])
        revision = len(history) + 1
        history.append(
            {
                "revision": revision,
                "rules": normalized,
                "set_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        self._save(state)
        return {"dataset": dataset, "revision": revision, "rules": normalized}

    def _rules_revision(self, state: dict[str, Any], dataset: str, revision: int | None) -> tuple[int, list[dict[str, Any]]]:
        history = state["rules"].get(dataset, [])
        if not history:
            raise ValueError(f"no rules configured for dataset: {dataset}")
        if revision is None:
            entry = history[-1]
        else:
            if revision < 1 or revision > len(history):
                raise ValueError(f"unknown rule revision {revision} for {dataset}")
            entry = history[revision - 1]
        return entry["revision"], [dict(rule) for rule in entry["rules"]]

    def _reference_set(
        self,
        state: dict[str, Any],
        dataset: str,
        version: int,
        columns: list[str],
    ) -> tuple[set[tuple[str, ...]], str]:
        """Build the set of combinations a reference rule accepts.

        Every reference side is fully re-verified on every validation: the
        stored blob must exist and match the version record, the CSV must be
        structurally valid, the reference columns must be present, and no
        reference value may be empty and no complete combination may repeat.
        Any of these fails the whole validation, even when the validated
        side has no records. Returns the combination set and the verified
        content hash.
        """
        record = self._version_record(state, dataset, version)
        blob_path = self.workspace / record["blob"]
        if not blob_path.exists():
            raise ValueError(f"stored data missing for {dataset}@{version}")
        content_hash = _sha256(blob_path)
        if content_hash != record["content_sha256"]:
            raise ValueError(f"stored data hash mismatch for {dataset}@{version}")
        header, rows = self._read_stored_csv(blob_path, dataset, version)
        missing = [name for name in columns if name not in header]
        if missing:
            raise ValueError(
                f"reference column(s) {missing} missing for {dataset}@{version}"
            )
        positions = [header.index(name) for name in columns]
        combinations: set[tuple[str, ...]] = set()
        for row_number, row in enumerate(rows, start=1):
            key = tuple(row[position] for position in positions)
            if any(part == "" for part in key):
                raise ValueError(
                    f"empty reference value in {dataset}@{version} data record {row_number}"
                )
            if key in combinations:
                raise ValueError(
                    f"duplicate reference combination {list(key)!r} in {dataset}@{version}"
                )
            combinations.add(key)
        return combinations, content_hash

    @staticmethod
    def _check_standard_rule(
        rule: dict[str, Any],
        value: str,
        row_number: int,
        result: dict[str, Any],
        seen_unique: dict[str, dict[str, list[int]]],
    ) -> None:
        """Apply a required/unique/range rule to one raw cell value."""
        rule_type = rule["type"]
        if rule_type == "required":
            if value == "":
                result["violations"].append(row_number)
        elif rule_type == "unique":
            if value != "":
                seen_unique[rule["id"]].setdefault(value, []).append(row_number)
        else:
            if value == "":
                return
            number = _finite_number(value)
            if number is None or not (
                ("min" not in rule or number >= rule["min"])
                and ("max" not in rule or number <= rule["max"])
            ):
                result["violations"].append(row_number)

    def _reverify_reference_validation(
        self,
        rules: list[dict[str, Any]],
        reference_sets: dict[str, tuple[set[tuple[str, ...]], str]],
        stored_report: dict[str, Any],
        blob_path: Path,
        dataset: str,
        version: int,
    ) -> None:
        """Re-verify every side of a reference rule when reusing a report.

        Even when the stored report is returned unchanged, all reference
        side hashes must match both the version record and the stored
        report, and the validated side's CSV structure and columns must
        still be intact. Any failure discards the run without touching the
        stored report.
        """
        stored_by_id = {item["id"]: item for item in stored_report["results"]}
        for rule in rules:
            if rule["type"] != _REFERENCE_TYPE:
                continue
            reference = rule["reference"]
            _, ref_hash = reference_sets[rule["id"]]
            stored_result = stored_by_id.get(rule["id"])
            stored_reference = (
                stored_result.get("reference") if stored_result is not None else None
            )
            if (
                not isinstance(stored_reference, dict)
                or stored_reference.get("content_sha256") != ref_hash
            ):
                raise ValueError(
                    f"stored reference hash for "
                    f"{reference['dataset']}@{reference['version']} no longer matches"
                )
        header, _rows = self._read_stored_csv(blob_path, dataset, version)
        for rule in rules:
            if rule["type"] == _REFERENCE_TYPE:
                missing = [name for name in rule["columns"] if name not in header]
                if missing:
                    raise ValueError(
                        f"column(s) {missing} missing for {dataset}@{version}"
                    )
            else:
                if rule["column"] not in header:
                    raise ValueError(
                        f"missing column {rule['column']!r} for {dataset}@{version}"
                    )

    def validate(
        self,
        dataset: str,
        version: int,
        revision: int | None = None,
    ) -> dict[str, Any]:
        state = self._load()
        record = self._version_record(state, dataset, version)
        rule_revision, rules = self._rules_revision(state, dataset, revision)

        has_reference = any(rule["type"] == _REFERENCE_TYPE for rule in rules)

        # Reference sides are resolved before anything else: a missing file,
        # hash mismatch, structurally invalid CSV, missing reference column,
        # or an empty/duplicated reference combination fails the whole run,
        # even when the validated side has no records.
        reference_sets: dict[str, tuple[set[tuple[str, ...]], str]] = {}
        if has_reference:
            for rule in rules:
                if rule["type"] == _REFERENCE_TYPE:
                    reference = rule["reference"]
                    reference_sets[rule["id"]] = self._reference_set(
                        state,
                        reference["dataset"],
                        reference["version"],
                        reference["columns"],
                    )

        stored = state["validations"].setdefault(dataset, {})
        existing = stored.get(str(version), {}).get(str(rule_revision))
        if existing is not None:
            # The stored blob hash is re-verified against both the catalog
            # record and the stored report on every invocation even when the
            # report itself is reused.
            blob_path = self.workspace / record["blob"]
            if not blob_path.exists():
                raise ValueError(f"stored data missing for {dataset}@{version}")
            current_hash = _sha256(blob_path)
            if current_hash != record["content_sha256"] or current_hash != existing["content_sha256"]:
                raise ValueError(f"stored data hash mismatch for {dataset}@{version}")
            if has_reference:
                self._reverify_reference_validation(
                    rules,
                    reference_sets,
                    existing["report"],
                    blob_path,
                    dataset,
                    version,
                )
            return dict(existing["report"])

        blob_path = self.workspace / record["blob"]
        if not blob_path.exists():
            raise ValueError(f"stored data missing for {dataset}@{version}")
        content_hash = _sha256(blob_path)
        if content_hash != record["content_sha256"]:
            raise ValueError(f"stored data hash mismatch for {dataset}@{version}")

        results: dict[str, dict[str, Any]] = {
            rule["id"]: {"rule": rule, "violations": []} for rule in rules
        }
        seen_unique: dict[str, dict[str, list[int]]] = {
            rule["id"]: {} for rule in rules if rule["type"] == "unique"
        }

        if has_reference:
            # Reference rules require a strictly valid stored CSV: a ragged
            # record is a structural failure rather than a missing value.
            header, rows = self._read_stored_csv(blob_path, dataset, version)
            for rule in rules:
                if rule["type"] == _REFERENCE_TYPE:
                    missing = [name for name in rule["columns"] if name not in header]
                    if missing:
                        raise ValueError(
                            f"column(s) {missing} missing for {dataset}@{version}"
                        )
                else:
                    if rule["column"] not in header:
                        raise ValueError(
                            f"missing column {rule['column']!r} for {dataset}@{version}"
                        )
            for row_number, row in enumerate(rows, start=1):
                for rule in rules:
                    result = results[rule["id"]]
                    if rule["type"] == _REFERENCE_TYPE:
                        positions = [header.index(name) for name in rule["columns"]]
                        key = tuple(row[position] for position in positions)
                        combinations, _ = reference_sets[rule["id"]]
                        # An empty left-side value or a combination absent
                        # from the reference set is a violation; every row is
                        # reported, including repeated occurrences.
                        if any(part == "" for part in key) or key not in combinations:
                            result["violations"].append(row_number)
                        continue
                    value = row[header.index(rule["column"])]
                    self._check_standard_rule(
                        rule, value, row_number, result, seen_unique
                    )
            row_count = len(rows)
        else:
            with blob_path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                fieldnames = reader.fieldnames or []
                for rule in rules:
                    if rule["column"] not in fieldnames:
                        raise ValueError(
                            f"missing column {rule['column']!r} for {dataset}@{version}"
                        )
                row_number = 0
                for row in reader:
                    row_number += 1
                    for rule in rules:
                        value = row[rule["column"]]
                        if value is None:
                            value = ""
                        self._check_standard_rule(
                            rule,
                            value,
                            row_number,
                            results[rule["id"]],
                            seen_unique,
                        )
            row_count = row_number

        for rule_id, groups in seen_unique.items():
            duplicates = sorted(
                line for lines in groups.values() if len(lines) > 1 for line in lines
            )
            results[rule_id]["violations"] = duplicates

        report_results = []
        for rule in rules:
            result = results[rule["id"]]
            violations = result["violations"]
            if rule["type"] == _REFERENCE_TYPE:
                _, ref_hash = reference_sets[rule["id"]]
                report_results.append(
                    {
                        "id": rule["id"],
                        "type": _REFERENCE_TYPE,
                        "columns": list(rule["columns"]),
                        "reference": {
                            "dataset": rule["reference"]["dataset"],
                            "version": rule["reference"]["version"],
                            "columns": list(rule["reference"]["columns"]),
                            "content_sha256": ref_hash,
                        },
                        "violations": violations,
                        "violationCount": len(violations),
                    }
                )
            else:
                report_results.append(
                    {
                        "id": rule["id"],
                        "column": rule["column"],
                        "type": rule["type"],
                        "violations": violations,
                        "violationCount": len(violations),
                    }
                )
        total_violations = sum(item["violationCount"] for item in report_results)
        report = {
            "dataset": dataset,
            "version": version,
            "content_sha256": content_hash,
            "rulesRevision": rule_revision,
            "rowCount": row_count,
            "passed": total_violations == 0,
            "results": report_results,
        }

        # Persist only after the full report is built; a write failure discards
        # this report instead of leaving a partial entry behind.
        stored.setdefault(str(version), {})[str(rule_revision)] = {
            "content_sha256": content_hash,
            "report": report,
        }
        self._save(state)
        return dict(report)

    def validation_history(self, dataset: str, version: int) -> list[dict[str, Any]]:
        state = self._load()
        if dataset not in state["datasets"]:
            raise ValueError(f"unknown dataset: {dataset}")
        versions = state["datasets"][dataset]
        if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > len(versions):
            raise ValueError(f"unknown data version: {dataset}@{version}")
        entries = state["validations"].get(dataset, {}).get(str(version), {})
        return [
            dict(entries[key]["report"])
            for key in sorted(entries, key=lambda item: int(item))
        ]

    def _version_record(self, state: dict[str, Any], dataset: str, version: Any) -> dict[str, Any]:
        if dataset not in state["datasets"]:
            raise ValueError(f"unknown dataset: {dataset}")
        versions = state["datasets"][dataset]
        if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > len(versions):
            raise ValueError(f"unknown data version: {dataset}@{version}")
        return versions[version - 1]

    @staticmethod
    def _validate_operations_payload(operations: Any) -> list[dict[str, Any]]:
        if not isinstance(operations, list) or not operations:
            raise ValueError("operations must be a non-empty array")
        normalized: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            where = f"operations[{index}]"
            if not isinstance(operation, dict):
                raise ValueError(f"{where} must be an object")
            operation_type = operation.get("type")
            if operation_type not in _OPERATION_KEYS:
                raise ValueError(f"{where}.type must be one of {sorted(_OPERATION_KEYS)}")
            expected = _OPERATION_KEYS[operation_type]
            if set(operation) != expected:
                raise ValueError(f"{where} must have exactly the attributes {sorted(expected)}")
            if operation_type in ("trim", "rename"):
                if not isinstance(operation["column"], str) or not operation["column"]:
                    raise ValueError(f"{where}.column must be a non-empty string")
            if operation_type == "rename":
                if not isinstance(operation["to"], str) or not operation["to"]:
                    raise ValueError(f"{where}.to must be a non-empty string")
            if operation_type == "drop_duplicates":
                columns = operation["columns"]
                if not isinstance(columns, list) or not columns:
                    raise ValueError(f"{where}.columns must be a non-empty array")
                if any(not isinstance(name, str) or not name for name in columns):
                    raise ValueError(f"{where}.columns must contain only non-empty strings")
                if len(set(columns)) != len(columns):
                    raise ValueError(f"{where}.columns must not contain duplicates")
            normalized.append(dict(operation))
        return normalized

    @staticmethod
    def _read_stored_csv(blob_path: Path, dataset: str, version: int) -> tuple[list[str], list[list[str]]]:
        with blob_path.open("r", encoding="utf-8", newline="") as handle:
            # Blank physical lines are not data records, matching DictReader.
            parsed = [row for row in csv.reader(handle) if row != []]
        if not parsed:
            raise ValueError(f"stored CSV for {dataset}@{version} has no header")
        header = parsed[0]
        if any(name == "" for name in header):
            raise ValueError(f"stored CSV for {dataset}@{version} has an empty header field")
        if len(set(header)) != len(header):
            raise ValueError(f"stored CSV for {dataset}@{version} has duplicate header fields")
        rows: list[list[str]] = []
        for record in parsed[1:]:
            if len(record) != len(header):
                raise ValueError(
                    f"stored CSV for {dataset}@{version} has a record with "
                    f"{len(record)} fields, expected {len(header)}"
                )
            rows.append(list(record))
        return header, rows

    def clean(self, dataset: str, version: int, operations: Any) -> dict[str, Any]:
        """Clean a stored version and append the result as a new immutable version.

        ``operations`` is a parsed non-empty JSON array, or a path to a file
        containing one. Any failure (unknown dataset/version, missing or
        tampered blob, unreadable or invalid operations, malformed stored CSV,
        write failure) leaves the catalog untouched and consumes no version
        number.
        """
        if isinstance(operations, (str, Path)):
            with open(operations, encoding="utf-8") as handle:
                operations = json.load(handle)
        steps_plan = self._validate_operations_payload(operations)

        state = self._load()
        record = self._version_record(state, dataset, version)
        blob_path = self.workspace / record["blob"]
        if not blob_path.exists():
            raise ValueError(f"stored data missing for {dataset}@{version}")
        source_hash = _sha256(blob_path)
        if source_hash != record["content_sha256"]:
            raise ValueError(f"stored data hash mismatch for {dataset}@{version}")

        header, rows = self._read_stored_csv(blob_path, dataset, version)

        columns = list(header)
        origins = list(header)  # source column behind each current column
        sources = list(range(1, len(rows) + 1))  # 1-based source record numbers
        steps: list[dict[str, Any]] = []
        for operation in steps_plan:
            operation_type = operation["type"]
            step: dict[str, Any] = {"operation": dict(operation), "inputRows": len(rows)}
            if operation_type == "trim":
                column = operation["column"]
                if column not in columns:
                    raise ValueError(f"unknown column {column!r} for trim")
                position = columns.index(column)
                modified = []
                for index, row in enumerate(rows):
                    stripped = row[position].strip()
                    if stripped != row[position]:
                        row[position] = stripped
                        modified.append(sources[index])
                step["modifiedRows"] = modified
            elif operation_type == "rename":
                column = operation["column"]
                target = operation["to"]
                if column not in columns:
                    raise ValueError(f"unknown column {column!r} for rename")
                if target in columns:
                    raise ValueError(f"rename target {target!r} conflicts with an existing column")
                columns[columns.index(column)] = target
                step["from"] = column
                step["to"] = target
            else:
                selected = operation["columns"]
                for name in selected:
                    if name not in columns:
                        raise ValueError(f"unknown column {name!r} for drop_duplicates")
                positions = [columns.index(name) for name in selected]
                seen: set[tuple[str, ...]] = set()
                kept_rows: list[list[str]] = []
                kept_sources: list[int] = []
                deleted = []
                for row, source in zip(rows, sources):
                    key = tuple(row[position] for position in positions)
                    if key in seen:
                        deleted.append(source)
                    else:
                        seen.add(key)
                        kept_rows.append(row)
                        kept_sources.append(source)
                rows, sources = kept_rows, kept_sources
                step["deletedRows"] = deleted
            step["outputRows"] = len(rows)
            steps.append(step)

        # Deterministic serialization: identical source and operations always
        # produce identical CSV bytes.
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(columns)
        writer.writerows(rows)
        content = buffer.getvalue().encode("utf-8")
        content_hash = hashlib.sha256(content).hexdigest()
        self.blobs.mkdir(parents=True, exist_ok=True)
        blob = self.blobs / f"{content_hash}.csv"
        if not blob.exists():
            blob.write_bytes(content)

        observed = {name: set() for name in columns}
        for row in rows:
            for position, name in enumerate(columns):
                observed[name].add(_kind(row[position]))

        versions = state["datasets"][dataset]
        new_version = len(versions) + 1
        new_record = DatasetVersion(
            dataset=dataset,
            version=new_version,
            source_name=f"{dataset}-v{new_version}-cleaned.csv",
            content_sha256=content_hash,
            row_count=len(rows),
            schema={name: _merge_kinds(kinds) for name, kinds in observed.items()},
            imported_at=datetime.now(timezone.utc).isoformat(),
            blob=str(blob.relative_to(self.workspace)),
        )
        entry = {
            "dataset": dataset,
            "version": new_version,
            "sourceVersion": version,
            "sourceSha256": source_hash,
            "operations": steps_plan,
            "steps": steps,
            "columnMapping": {name: origins[index] for index, name in enumerate(columns)},
            "rowMapping": list(sources),
            "rowCount": len(rows),
            "contentSha256": content_hash,
        }
        # Version and lineage are persisted in a single save; a write failure
        # leaves no version, no lineage record, and no consumed version number.
        versions.append(asdict(new_record))
        state["lineage"].setdefault(dataset, {})[str(new_version)] = entry
        self._save(state)
        result = asdict(new_record)
        result["lineage"] = entry
        return result

    def lineage(self, dataset: str, version: int) -> dict[str, Any]:
        """Return the full cleaning chain for a version, source-first.

        Plain imported versions are chain starts and yield an empty chain.
        """
        state = self._load()
        self._version_record(state, dataset, version)
        records = state["lineage"].get(dataset, {})
        chain: list[dict[str, Any]] = []
        current = version
        while str(current) in records:
            entry = records[str(current)]
            chain.append(json.loads(json.dumps(entry)))
            current = entry["sourceVersion"]
        chain.reverse()
        return {"dataset": dataset, "version": version, "chain": chain}
