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
_OP_TYPES = {"trim", "rename", "drop_duplicates"}
_OP_KEYS = {
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
    lineage: dict[str, Any] | None = None


class Catalog:
    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace).resolve()
        self.control = self.workspace / ".dgw"
        self.blobs = self.control / "blobs"
        self.state_path = self.control / "catalog.json"

    def _load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"schemaVersion": 1, "datasets": {}, "rules": {}, "validations": {}}
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        state.setdefault("rules", {})
        state.setdefault("validations", {})
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

    def compare(self, dataset: str, left: int, right: int) -> dict[str, Any]:
        before, after = self.get(dataset, left), self.get(dataset, right)
        before_schema, after_schema = before["schema"], after["schema"]
        return {
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

    def export(self, dataset: str, version: int, destination: str | Path) -> dict[str, Any]:
        record = self.get(dataset, version)
        destination_path = Path(destination).resolve()
        destination_path.mkdir(parents=True, exist_ok=True)
        source = self.workspace / record["blob"]
        data_path = destination_path / f"{dataset}-v{version}.csv"
        shutil.copyfile(source, data_path)
        manifest = {
            "schemaVersion": 1,
            "record": record,
            "file": data_path.name,
            "lineage": self.lineage(dataset, version),
        }
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

    @staticmethod
    def _validate_operations(operations: Any) -> list[dict[str, Any]]:
        if not isinstance(operations, list) or not operations:
            raise ValueError("operations must be a non-empty array")
        normalized: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            where = f"operations[{index}]"
            if not isinstance(operation, dict):
                raise ValueError(f"{where} must be an object")
            operation_type = operation.get("type")
            if operation_type not in _OP_TYPES:
                raise ValueError(f"{where}.type must be one of {sorted(_OP_TYPES)}")
            expected = _OP_KEYS[operation_type]
            extra = set(operation) - expected
            missing = expected - set(operation)
            if extra:
                raise ValueError(f"{where} has unknown attributes: {sorted(extra)}")
            if missing:
                raise ValueError(f"{where} is missing attributes: {sorted(missing)}")
            entry: dict[str, Any] = {"type": operation_type}
            if operation_type == "trim":
                column = operation["column"]
                if not isinstance(column, str) or not column:
                    raise ValueError(f"{where}.column must be a non-empty string")
                entry["column"] = column
            elif operation_type == "rename":
                column, target = operation["column"], operation["to"]
                if not isinstance(column, str) or not column:
                    raise ValueError(f"{where}.column must be a non-empty string")
                if not isinstance(target, str) or not target:
                    raise ValueError(f"{where}.to must be a non-empty string")
                entry["column"] = column
                entry["to"] = target
            else:
                columns = operation["columns"]
                if not isinstance(columns, list) or not columns:
                    raise ValueError(f"{where}.columns must be a non-empty array")
                for column in columns:
                    if not isinstance(column, str) or not column:
                        raise ValueError(f"{where}.columns must contain non-empty strings")
                if len(set(columns)) != len(columns):
                    raise ValueError(f"{where}.columns must not contain duplicates")
                entry["columns"] = list(columns)
            normalized.append(entry)
        return normalized

    def clean(
        self,
        dataset: str,
        version: int,
        operations: list[dict[str, Any]],
    ) -> DatasetVersion:
        if not dataset or any(character in dataset for character in "/\\\0"):
            raise ValueError("dataset must be a non-empty portable name")
        state = self._load()
        versions = state["datasets"].get(dataset)
        if not versions:
            raise ValueError(f"unknown dataset: {dataset}")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > len(versions):
            raise ValueError(f"unknown data version: {dataset}@{version}")
        source_record = versions[version - 1]

        normalized_ops = self._validate_operations(operations)

        # Verify the stored blob against the recorded hash before doing any
        # work; a missing or tampered source rejects the whole cleaning.
        blob_path = self.workspace / source_record["blob"]
        if not blob_path.exists():
            raise ValueError(f"stored data missing for {dataset}@{version}")
        source_hash = _sha256(blob_path)
        if source_hash != source_record["content_sha256"]:
            raise ValueError(f"stored data hash mismatch for {dataset}@{version}")

        with blob_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        if not rows:
            raise ValueError("stored CSV is empty")
        headers = list(rows[0])
        if not headers or any(not name for name in headers) or len(set(headers)) != len(headers):
            raise ValueError("CSV requires unique, non-empty headers")
        # Blank lines are not data records (csv.DictReader skips them on
        # import); any other row whose field count differs from the headers
        # rejects the whole cleaning.
        data_rows = [list(row) for row in rows[1:] if row]
        for index, row in enumerate(data_rows, start=1):
            if len(row) != len(headers):
                raise ValueError(f"row {index} column count does not match headers")

        current_headers = list(headers)
        current_rows = data_rows
        field_mapping = {name: name for name in headers}
        # Source row numbers are 1-based data record numbers of the source
        # version; quoted newlines do not advance them because csv.reader
        # already folds them into the containing record.
        row_mapping = list(range(1, len(data_rows) + 1))
        steps: list[dict[str, Any]] = []

        for operation in normalized_ops:
            operation_type = operation["type"]
            if operation_type == "trim":
                column = operation["column"]
                if column not in current_headers:
                    raise ValueError(f"missing column {column!r} for {dataset}@{version}")
                index = current_headers.index(column)
                modified = []
                for position, row in enumerate(current_rows):
                    value = row[index]
                    stripped = value.strip()
                    if stripped != value:
                        row[index] = stripped
                        modified.append(row_mapping[position])
                steps.append(
                    {
                        "type": "trim",
                        "column": column,
                        "inputRows": len(current_rows),
                        "outputRows": len(current_rows),
                        "modifiedRows": modified,
                    }
                )
            elif operation_type == "rename":
                column, target = operation["column"], operation["to"]
                if column not in current_headers:
                    raise ValueError(f"missing column {column!r} for {dataset}@{version}")
                if target in current_headers:
                    raise ValueError(f"column {target!r} already exists for {dataset}@{version}")
                index = current_headers.index(column)
                current_headers[index] = target
                field_mapping[target] = field_mapping.pop(column)
                steps.append(
                    {
                        "type": "rename",
                        "column": column,
                        "to": target,
                        "inputRows": len(current_rows),
                        "outputRows": len(current_rows),
                    }
                )
            else:
                columns = operation["columns"]
                for column in columns:
                    if column not in current_headers:
                        raise ValueError(f"missing column {column!r} for {dataset}@{version}")
                indices = [current_headers.index(column) for column in columns]
                seen: set[tuple[str, ...]] = set()
                deleted = []
                kept_rows = []
                kept_mapping = []
                for position, row in enumerate(current_rows):
                    # Comparison uses the raw string combination of the
                    # current step; empty strings participate and numeric
                    # text is never converted.
                    key = tuple(row[index] for index in indices)
                    if key in seen:
                        deleted.append(row_mapping[position])
                    else:
                        seen.add(key)
                        kept_rows.append(row)
                        kept_mapping.append(row_mapping[position])
                current_rows = kept_rows
                row_mapping = kept_mapping
                steps.append(
                    {
                        "type": "drop_duplicates",
                        "columns": list(columns),
                        "inputRows": len(current_rows) + len(deleted),
                        "outputRows": len(current_rows),
                        "deletedRows": deleted,
                    }
                )

        # Emit canonical CSV bytes so repeated runs on the same source and
        # operations are byte-identical; quoting is never round-tripped from
        # the source file.
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(current_headers)
        writer.writerows(current_rows)
        output_bytes = buffer.getvalue().encode("utf-8")
        output_hash = hashlib.sha256(output_bytes).hexdigest()

        self.blobs.mkdir(parents=True, exist_ok=True)
        output_blob = self.blobs / f"{output_hash}.csv"
        output_blob.write_bytes(output_bytes)

        observed = {name: set() for name in current_headers}
        for row in current_rows:
            for name, value in zip(current_headers, row):
                observed[name].add(_kind(value))
        schema = {name: _merge_kinds(kinds) for name, kinds in observed.items()}

        new_version = len(versions) + 1
        lineage = {
            "sourceVersion": version,
            "sourceContentSha256": source_hash,
            "operations": normalized_ops,
            "steps": steps,
            "fieldMapping": field_mapping,
            "rowMapping": row_mapping,
        }
        record = DatasetVersion(
            dataset=dataset,
            version=new_version,
            source_name=f"clean:{source_record['source_name']}",
            content_sha256=output_hash,
            row_count=len(current_rows),
            schema=schema,
            imported_at=datetime.now(timezone.utc).isoformat(),
            blob=str(output_blob.relative_to(self.workspace)),
            lineage=lineage,
        )
        versions.append(asdict(record))
        # The state save is the commit point; a failure here leaves no new
        # version or lineage record and consumes no version number.
        self._save(state)
        return record

    def lineage(self, dataset: str, version: int) -> dict[str, Any]:
        state = self._load()
        versions = state["datasets"].get(dataset)
        if not versions:
            raise ValueError(f"unknown dataset: {dataset}")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > len(versions):
            raise ValueError(f"unknown data version: {dataset}@{version}")
        record = versions[version - 1]
        chain: list[dict[str, Any]] = []
        current = record
        while current.get("lineage"):
            entry = current["lineage"]
            source_version = entry["sourceVersion"]
            if not isinstance(source_version, int) or source_version < 1 or source_version > len(versions):
                raise ValueError(f"broken lineage for {dataset}@{current['version']}")
            chain.append(
                {
                    "version": current["version"],
                    "sourceVersion": source_version,
                    "sourceContentSha256": entry["sourceContentSha256"],
                    "operations": entry["operations"],
                    "steps": entry["steps"],
                    "fieldMapping": entry["fieldMapping"],
                    "rowMapping": entry["rowMapping"],
                }
            )
            current = versions[source_version - 1]
        return {
            "dataset": dataset,
            "version": version,
            "content_sha256": record["content_sha256"],
            "chain": chain,
        }
