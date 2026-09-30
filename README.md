# Dataset Governance Workbench

A small, dependency-free Python command-line workbench for importing CSV datasets into a versioned local catalog. The baseline records inferred schemas and content hashes, compares versions, and produces reproducible export manifests.

## Quick start

```bash
python3 -m governance_workbench --workspace .demo-workspace demo
python3 -m governance_workbench --workspace .demo-workspace list
python3 -m unittest discover -s tests -v
```

## Commands

- `import`: add a CSV file as the next immutable version of a dataset.
- `list`: print the catalog as JSON.
- `compare`: compare the schema and content identity of two versions.
- `export`: copy one stored version and write a checksum-bound manifest.
- `rules 数据集 JSON文件`: configure a non-empty array of quality rules, returning the dataset's next immutable rule revision (1-based, contiguous).
- `validate 数据集 版本号 [--revision 修订号]`: validate a stored data version against a rule revision (latest if omitted); exit 0 when the report passes, 1 when violations are found, 2 on error.
- `validations 数据集 版本号`: list persisted validation reports for a data version, ascending by rule revision (empty array when none).
- `demo`: build two sample versions and show a comparison.

All catalog state lives below the selected workspace. Source CSV files are copied into a content-addressed blob directory, so later source-file changes do not alter recorded versions.

### Rule configuration

Each rule object contains a unique non-empty string `id`, a non-empty `column`, and a `type` of `required`, `unique`, or `range`. Range rules require `min` or `max`, each a finite number (never a boolean), endpoints included, with `min <= max`; non-range rules reject bounds. Unknown types, duplicate ids, missing required attributes, and extra attributes are all rejected.

### Validation semantics

- Row numbers count CSV data records starting at 1; a quoted newline inside a field does not advance the row number.
- An empty string is a missing value and surrounding whitespace is never stripped.
- `required` reports rows with missing values; `unique` compares non-empty raw strings and reports every row of each duplicated group; `range` skips missing values and flags non-numeric, non-finite, or out-of-bounds values.
- Column names match verbatim.
- Reports persist across restarts. Re-validating the same data version and rule revision returns the identical stored report (the stored blob hash is still re-verified each time). Validation never modifies CSVs, infers structure, or creates data versions.
- Errors (invalid configuration, unknown dataset/version/revision, no rules, missing columns, missing stored data or hash mismatch) produce a stderr-only `{"error": "原因"}` envelope and exit code 2 for the new commands.
