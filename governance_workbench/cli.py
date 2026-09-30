from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .catalog import Catalog


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


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

    export = commands.add_parser("export")
    export.add_argument("dataset")
    export.add_argument("version", type=int)
    export.add_argument("destination")

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
        _print(catalog.compare(args.dataset, args.left, args.right))
    elif args.command == "export":
        _print(catalog.export(args.dataset, args.version, args.destination))
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
