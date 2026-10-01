from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from .catalog import Catalog


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _fail(message: str) -> int:
    print(json.dumps({"error": message}, ensure_ascii=False), file=sys.stderr)
    return 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="dataset-governance")
    root.add_argument("--workspace", default=".")
    commands = root.add_subparsers(dest="command", required=True)

    import_command = commands.add_parser("import")
    import_command.add_argument("dataset")
    import_command.add_argument("source")

    commands.add_parser("list")

    compare = commands.add_parser("compare")
    compare.add_argument("dataset")
    compare.add_argument("left", type=int)
    compare.add_argument("right", type=int)
    compare.add_argument("--keys", nargs="+", default=None)

    export = commands.add_parser("export")
    export.add_argument("dataset")
    export.add_argument("version", type=int)
    export.add_argument("destination")

    rules = commands.add_parser("rules")
    rules.add_argument("dataset")
    rules.add_argument("rules_file")

    validate = commands.add_parser("validate")
    validate.add_argument("dataset")
    validate.add_argument("version", type=int)
    validate.add_argument("--revision", type=int, default=None)

    validations = commands.add_parser("validations")
    validations.add_argument("dataset")
    validations.add_argument("version", type=int)

    clean = commands.add_parser("clean")
    clean.add_argument("dataset")
    clean.add_argument("version", type=int)
    clean.add_argument("operations_file")

    lineage = commands.add_parser("lineage")
    lineage.add_argument("dataset")
    lineage.add_argument("version", type=int)

    commands.add_parser("demo")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    catalog = Catalog(args.workspace)
    if args.command == "import":
        _print(catalog.import_csv(args.dataset, args.source).__dict__)
    elif args.command == "list":
        _print(catalog.list_datasets())
    elif args.command == "compare":
        try:
            _print(catalog.compare(args.dataset, args.left, args.right, args.keys))
        except (ValueError, OSError) as error:
            return _fail(str(error))
    elif args.command == "export":
        _print(catalog.export(args.dataset, args.version, args.destination))
    elif args.command == "rules":
        try:
            with open(args.rules_file, encoding="utf-8") as handle:
                payload = json.load(handle)
            _print(catalog.set_rules(args.dataset, payload))
        except (ValueError, OSError) as error:
            return _fail(str(error))
    elif args.command == "validate":
        try:
            report = catalog.validate(args.dataset, args.version, args.revision)
        except (ValueError, OSError) as error:
            return _fail(str(error))
        _print(report)
        return 0 if report["passed"] else 1
    elif args.command == "validations":
        try:
            _print(catalog.validation_history(args.dataset, args.version))
        except (ValueError, OSError) as error:
            return _fail(str(error))
    elif args.command == "clean":
        try:
            _print(catalog.clean(args.dataset, args.version, args.operations_file))
        except (ValueError, OSError) as error:
            return _fail(str(error))
    elif args.command == "lineage":
        try:
            _print(catalog.lineage(args.dataset, args.version))
        except (ValueError, OSError) as error:
            return _fail(str(error))
    elif args.command == "demo":
        first_version = len(catalog.list_datasets().get("customers", [])) + 1
        with TemporaryDirectory() as directory:
            first = Path(directory) / "customers-v1.csv"
            second = Path(directory) / "customers-v2.csv"
            first.write_text("id,name\n1,Ada\n2,Lin\n", encoding="utf-8")
            second.write_text("id,name,region\n1,Ada,EU\n2,Lin,APAC\n3,Sam,US\n", encoding="utf-8")
            catalog.import_csv("customers", first)
            catalog.import_csv("customers", second)
        _print(catalog.compare("customers", first_version, first_version + 1))
    return 0
