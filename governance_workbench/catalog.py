from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_RULE_TYPES = {"required", "unique", "range"}
_RULE_KEYS = {"id", "column", "type", "min", "max"}
_OPERATION_KEYS = {
    "trim": {"type", "column"},
    "rename": {"type", "column", "to"},
    "drop_duplicates": {"type", "columns"},
}
_NUMBER_RE = re.compile(r"[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?\Z")


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
        with source_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ValueError("CSV requires unique, non-empty headers")
            observed = {name: set() for name in reader.fieldnames}
            row_count = 0
            for row in reader:
                row_count += 1
                for name in reader.fieldnames:
                    observed[name].add(_kind(row[name] or ""))

        content_hash = _sha256(source_path)
        self.blobs.mkdir(parents=True, exist_ok=True)
        blob = self.blobs / f"{content_hash}.csv"
        if not blob.exists():
            shutil.copyfile(source_path, blob)

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
    def _validate_keys(keys: Any) -> list[str]:
        if not isinstance(keys, list) or not keys:
            raise ValueError("keys must be a non-empty list of column names")
        normalized: list[str] = []
        for index, key in enumerate(keys):
            if not isinstance(key, str) or not key:
                raise ValueError(f"keys[{index}] must be a non-empty string")
            normalized.append(key)
        if len(set(normalized)) != len(normalized):
            raise ValueError("keys must not contain duplicate column names")
        return normalized

    def compare(
        self,
        dataset: str,
        left: int,
        right: int,
        keys: list[str] | None = None,
    ) -> dict[str, Any]:
        if keys is not None:
            # Keyed comparison re-verifies both stored blobs against their
            # version records and parses both CSVs before reporting anything;
            # any failure rejects the whole comparison with no partial diff.
            state = self._load()
            before = self._version_record(state, dataset, left)
            after = self._version_record(state, dataset, right)
        else:
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
        if keys is not None:
            result["rowDiff"] = self._row_diff(dataset, left, right, before, after, keys)
        return result

    def _row_diff(
        self,
        dataset: str,
        left: int,
        right: int,
        before: dict[str, Any],
        after: dict[str, Any],
        keys: list[str],
    ) -> dict[str, Any]:
        key_columns = self._validate_keys(keys)
        sides = (
            ("left", left, before),
            ("right", right, after),
        )
        parsed: dict[str, tuple[list[str], list[list[str]]]] = {}
        for side_name, version, record in sides:
            blob_path = self.workspace / record["blob"]
            if not blob_path.exists():
                raise ValueError(f"stored data missing for {dataset}@{version}")
            content_hash = _sha256(blob_path)
            if content_hash != record["content_sha256"]:
                raise ValueError(f"stored data hash mismatch for {dataset}@{version}")
            header, rows = self._read_stored_csv(blob_path, dataset, version)
            for key in key_columns:
                if key not in header:
                    raise ValueError(f"key column {key!r} missing for {dataset}@{version}")
            parsed[side_name] = (header, rows)

        def index_rows(
            side_name: str, header: list[str], rows: list[list[str]]
        ) -> dict[tuple[str, ...], tuple[int, list[str]]]:
            positions = [header.index(name) for name in key_columns]
            indexed: dict[tuple[str, ...], tuple[int, list[str]]] = {}
            for number, row in enumerate(rows, start=1):
                key_values = tuple(row[position] for position in positions)
                if any(value == "" for value in key_values):
                    raise ValueError(
                        f"empty key value in {side_name} record {number} "
                        f"for {dataset}@{left if side_name == 'left' else right}"
                    )
                if key_values in indexed:
                    raise ValueError(
                        f"duplicate key in {side_name} record {number} "
                        f"for {dataset}@{left if side_name == 'left' else right}"
                    )
                indexed[key_values] = (number, row)
            return indexed

        left_header, left_rows = parsed["left"]
        right_header, right_rows = parsed["right"]
        left_index = index_rows("left", left_header, left_rows)
        right_index = index_rows("right", right_header, right_rows)

        all_columns = sorted(set(left_header) | set(right_header))
        added: list[dict[str, Any]] = []
        removed: list[dict[str, Any]] = []
        modified: list[dict[str, Any]] = []
        unchanged_count = 0

        for key_values, (right_number, right_row) in right_index.items():
            if key_values not in left_index:
                added.append(
                    {
                        "key": list(key_values),
                        "row": right_number,
                        "values": dict(sorted(zip(right_header, right_row))),
                    }
                )
                continue
            left_number, left_row = left_index[key_values]
            changes: dict[str, dict[str, str | None]] = {}
            for name in all_columns:
                left_value = left_row[left_header.index(name)] if name in left_header else None
                right_value = right_row[right_header.index(name)] if name in right_header else None
                if left_value != right_value:
                    changes[name] = {"from": left_value, "to": right_value}
            if changes:
                modified.append(
                    {
                        "key": list(key_values),
                        "leftRow": left_number,
                        "rightRow": right_number,
                        "changes": changes,
                    }
                )
            else:
                unchanged_count += 1

        for key_values, (left_number, left_row) in left_index.items():
            if key_values not in right_index:
                removed.append(
                    {
                        "key": list(key_values),
                        "row": left_number,
                        "values": dict(sorted(zip(left_header, left_row))),
                    }
                )

        added.sort(key=lambda item: item["row"])
        removed.sort(key=lambda item: item["row"])
        modified.sort(key=lambda item: item["rightRow"])
        return {
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchangedCount": unchanged_count,
        }

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
            extra = set(rule) - _RULE_KEYS
            if extra:
                raise ValueError(f"{where} has unknown attributes: {sorted(extra)}")
            identifier = rule.get("id")
            if not isinstance(identifier, str) or not identifier:
                raise ValueError(f"{where}.id must be a non-empty string")
            if identifier in seen_ids:
                raise ValueError(f"duplicate rule id: {identifier}")
            column = rule.get("column")
            if not isinstance(column, str) or not column:
                raise ValueError(f"{where}.column must be a non-empty column name")
            rule_type = rule.get("type")
            if rule_type not in _RULE_TYPES:
                raise ValueError(f"{where}.type must be one of {sorted(_RULE_TYPES)}")
            entry: dict[str, Any] = {"id": identifier, "column": column, "type": rule_type}
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

    def set_rules(self, dataset: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
        state = self._load()
        if dataset not in state["datasets"]:
            raise ValueError(f"unknown dataset: {dataset}")
        normalized = self._validate_rules_payload(rules)
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

    def validate(
        self,
        dataset: str,
        version: int,
        revision: int | None = None,
    ) -> dict[str, Any]:
        state = self._load()
        if dataset not in state["datasets"]:
            raise ValueError(f"unknown dataset: {dataset}")
        versions = state["datasets"][dataset]
        if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > len(versions):
            raise ValueError(f"unknown data version: {dataset}@{version}")
        record = versions[version - 1]
        rule_revision, rules = self._rules_revision(state, dataset, revision)

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
            return dict(existing["report"])

        blob_path = self.workspace / record["blob"]
        if not blob_path.exists():
            raise ValueError(f"stored data missing for {dataset}@{version}")
        content_hash = _sha256(blob_path)
        if content_hash != record["content_sha256"]:
            raise ValueError(f"stored data hash mismatch for {dataset}@{version}")

        with blob_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames or []
            for rule in rules:
                if rule["column"] not in fieldnames:
                    raise ValueError(
                        f"missing column {rule['column']!r} for {dataset}@{version}"
                    )
            results: dict[str, dict[str, Any]] = {
                rule["id"]: {"rule": rule, "violations": []} for rule in rules
            }
            seen_unique: dict[str, dict[str, list[int]]] = {
                rule["id"]: {} for rule in rules if rule["type"] == "unique"
            }
            row_number = 0
            for row in reader:
                row_number += 1
                for rule in rules:
                    value = row[rule["column"]]
                    if value is None:
                        value = ""
                    result = results[rule["id"]]
                    rule_type = rule["type"]
                    if rule_type == "required":
                        if value == "":
                            result["violations"].append(row_number)
                    elif rule_type == "unique":
                        if value != "":
                            seen_unique[rule["id"]].setdefault(value, []).append(row_number)
                    else:
                        if value == "":
                            continue
                        number = _finite_number(value)
                        if number is None or not (
                            ("min" not in rule or number >= rule["min"])
                            and ("max" not in rule or number <= rule["max"])
                        ):
                            result["violations"].append(row_number)

        for rule_id, groups in seen_unique.items():
            duplicates = sorted(
                line for lines in groups.values() if len(lines) > 1 for line in lines
            )
            results[rule_id]["violations"] = duplicates

        report_results = []
        for rule in rules:
            result = results[rule["id"]]
            violations = result["violations"]
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
            "rowCount": row_number,
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
            try:
                parsed = [row for row in csv.reader(handle) if row != []]
            except csv.Error as error:
                raise ValueError(
                    f"stored CSV for {dataset}@{version} is unparseable: {error}"
                ) from error
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
