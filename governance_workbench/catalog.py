from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


_RULE_TYPES = frozenset({"required", "unique", "range"})
_RULE_ATTRIBUTES = {
    "required": frozenset({"id", "column", "type"}),
    "unique": frozenset({"id", "column", "type"}),
    "range": frozenset({"id", "column", "type", "min", "max"}),
}


def _validate_rules(rules: Any) -> None:
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a non-empty array")
    seen_ids: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"rule at index {index} must be an object")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError(f"rule at index {index}: id must be a non-empty string")
        if rule_id in seen_ids:
            raise ValueError(f"rule at index {index}: duplicate id {rule_id!r}")
        seen_ids.add(rule_id)
        column = rule.get("column")
        if not isinstance(column, str) or not column:
            raise ValueError(f"rule {rule_id!r}: column must be a non-empty string")
        rule_type = rule.get("type")
        if rule_type not in _RULE_TYPES:
            raise ValueError(f"rule {rule_id!r}: unknown type {rule_type!r}")
        extra = set(rule) - _RULE_ATTRIBUTES[rule_type]
        if extra:
            raise ValueError(f"rule {rule_id!r}: extra attributes {sorted(extra)}")
        if rule_type == "range":
            has_min, has_max = "min" in rule, "max" in rule
            if not has_min and not has_max:
                raise ValueError(f"rule {rule_id!r}: range requires min or max")
            for bound_name in ("min", "max"):
                if bound_name in rule:
                    value = rule[bound_name]
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not math.isfinite(value)
                    ):
                        raise ValueError(
                            f"rule {rule_id!r}: {bound_name} must be a finite number"
                        )
            if has_min and has_max and rule["min"] > rule["max"]:
                raise ValueError(f"rule {rule_id!r}: min must not exceed max")


def _cell(row: list[str], column_index: int) -> str:
    return row[column_index] if column_index < len(row) else ""


def _find_violations(rule: dict[str, Any], rows: list[list[str]], column_index: int) -> list[int]:
    rule_type = rule["type"]
    if rule_type == "required":
        return [
            line
            for line, row in enumerate(rows, start=1)
            if _cell(row, column_index) == ""
        ]
    if rule_type == "unique":
        groups: dict[str, list[int]] = {}
        for line, row in enumerate(rows, start=1):
            value = _cell(row, column_index)
            if value == "":
                continue
            groups.setdefault(value, []).append(line)
        violations: list[int] = []
        for lines in groups.values():
            if len(lines) > 1:
                violations.extend(lines)
        violations.sort()
        return violations
    violations = []
    for line, row in enumerate(rows, start=1):
        value = _cell(row, column_index)
        if value == "":
            continue
        try:
            number = float(value)
        except ValueError:
            violations.append(line)
            continue
        if not math.isfinite(number):
            violations.append(line)
            continue
        if "min" in rule and number < rule["min"]:
            violations.append(line)
        if "max" in rule and number > rule["max"]:
            violations.append(line)
    return violations


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
            return {"schemaVersion": 1, "datasets": {}}
        return json.loads(self.state_path.read_text(encoding="utf-8"))

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
        manifest = {"schemaVersion": 1, "record": record, "file": data_path.name}
        manifest_path = destination_path / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return manifest

    def _persist(self, state: dict[str, Any]) -> None:
        try:
            self._save(state)
        except OSError as exc:
            raise ValueError(f"failed to persist catalog state: {exc}") from exc

    def _record(self, dataset: str, version: int) -> dict[str, Any]:
        versions = self._load()["datasets"].get(dataset, [])
        if version < 1 or version > len(versions):
            raise ValueError(f"unknown dataset version: {dataset}@{version}")
        return versions[version - 1]

    def set_rules(self, dataset: str, rules: list[dict[str, Any]]) -> int:
        if not dataset or any(character in dataset for character in "/\\\0"):
            raise ValueError("dataset must be a non-empty portable name")
        _validate_rules(rules)
        state = self._load()
        rules_store = state.setdefault("rules", {}).setdefault(dataset, {"revisions": []})
        revisions = rules_store.setdefault("revisions", [])
        revision = len(revisions) + 1
        revisions.append(
            {
                "revision": revision,
                "rules": [dict(rule) for rule in rules],
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        self._persist(state)
        return revision

    def _report(
        self,
        dataset: str,
        version: int,
        record: dict[str, Any],
        revision: int,
        rules: list[dict[str, Any]],
        blob: Path,
    ) -> dict[str, Any]:
        with blob.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            try:
                header = next(reader)
            except StopIteration:
                raise ValueError(f"stored data empty for {dataset}@{version}")
            columns = {name: index for index, name in enumerate(header)}
            rows = list(reader)
        rule_results = []
        for rule in rules:
            column = rule["column"]
            if column not in columns:
                raise ValueError(f"rule {rule['id']!r}: column {column!r} not found in data")
            violations = _find_violations(rule, rows, columns[column])
            rule_results.append(
                {"id": rule["id"], "violations": violations, "count": len(violations)}
            )
        return {
            "dataset": dataset,
            "version": version,
            "content_sha256": record["content_sha256"],
            "rule_revision": revision,
            "row_count": record["row_count"],
            "passed": all(item["count"] == 0 for item in rule_results),
            "rules": rule_results,
        }

    def validate(
        self, dataset: str, version: int, revision: int | None = None
    ) -> dict[str, Any]:
        record = self._record(dataset, version)
        state = self._load()
        revisions = state.get("rules", {}).get(dataset, {}).get("revisions", [])
        if not revisions:
            raise ValueError(f"no rules configured for dataset {dataset!r}")
        if revision is None:
            revision = max(item["revision"] for item in revisions)
        elif not any(item["revision"] == revision for item in revisions):
            raise ValueError(f"unknown rule revision {revision} for dataset {dataset!r}")
        blob = self.workspace / record["blob"]
        if not blob.is_file():
            raise ValueError(f"stored data missing for {dataset}@{version}")
        if _sha256(blob) != record["content_sha256"]:
            raise ValueError(f"stored data hash mismatch for {dataset}@{version}")
        by_version = (
            state.setdefault("validations", {})
            .setdefault(dataset, {})
            .setdefault(str(version), {})
        )
        key = str(revision)
        if key in by_version:
            return by_version[key]
        rules = next(item["rules"] for item in revisions if item["revision"] == revision)
        report = self._report(dataset, version, record, revision, rules, blob)
        by_version[key] = report
        self._persist(state)
        return report

    def validation_history(self, dataset: str, version: int) -> list[dict[str, Any]]:
        state = self._load()
        by_version = state.get("validations", {}).get(dataset, {}).get(str(version), {})
        return [by_version[key] for key in sorted(by_version, key=lambda item: int(item))]
