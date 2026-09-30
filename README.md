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
- `demo`: build two sample versions and show a comparison.
- `rules <dataset> <rules.json>`: set the next immutable rule revision for a dataset. The file contains a JSON array of rules; each rule has a unique non-empty `id`, a non-empty `column`, and a `type` of `required`, `unique`, or `range`. `range` takes a finite, non-boolean `min` and/or `max` (inclusive, `min <= max`); the other types accept no bounds.
- `validate <dataset> <version> [--revision <n>]`: validate a data version against a rule revision (latest when omitted). Prints a JSON report; exits `1` when violations are found, `0` when clean.
- `validations <dataset> <version>`: list persisted validation reports for a data version, ordered by rule revision ascending.

Rule violations use CSV record line numbers starting at 1 (quoted newlines do not advance them). An empty string is a missing value; whitespace is not stripped. `required` reports missing rows, `unique` compares non-empty raw strings and reports every row in duplicate groups, and `range` skips missing values and flags non-numeric, non-finite, or out-of-bounds values.

Validation reports persist across restarts. Re-validating the same data version and rule revision keeps a single report with identical content, though the stored data hash is verified on every run. Errors (invalid configuration, missing dataset/version/revision, missing column, missing or tampered stored data) exit `2` with empty stdout and a `{"error": ...}` line on stderr.

All catalog state lives below the selected workspace. Source CSV files are copied into a content-addressed blob directory, so later source-file changes do not alter recorded versions.
