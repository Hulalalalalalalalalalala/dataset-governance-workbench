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
- `compare`: compare the schema and content identity of two versions. Add `--keys 列 [列 ...]` to additionally report row-level changes (`rowDiff`) matched by the given key columns.
- `export`: copy one stored version and write a checksum-bound manifest.
- `rules 数据集 JSON文件`: configure a non-empty array of quality rules, returning the dataset's next immutable rule revision (1-based, contiguous).
- `validate 数据集 版本号 [--revision 修订号]`: validate a stored data version against a rule revision (latest if omitted); exit 0 when the report passes, 1 when violations are found, 2 on error.
- `validations 数据集 版本号`: list persisted validation reports for a data version, ascending by rule revision (empty array when none).
- `clean 数据集 版本号 操作文件`: clean a stored version and append the result as the dataset's next immutable version, returning its row count and inferred schema. The new version supports `compare`, `validate`, and `export`; source data, rule revisions, and validation reports are untouched.
- `lineage 数据集 版本号`: show the full cleaning chain for a version, source-first. Plain imported versions are chain starts (empty chain).
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

### Cleaning operations

The operations file is a non-empty JSON array executed in order. Three object shapes are accepted, with exactly the attributes shown:

- `{"type": "trim", "column": "字段"}`: strip leading/trailing whitespace from each value, keeping inner content.
- `{"type": "rename", "column": "旧名", "to": "新名"}`: rename a column in place; the target must not collide with an existing column.
- `{"type": "drop_duplicates", "columns": ["字段"]}`: keep the first record of each column-value combination, preserving order. Comparison uses the raw strings at that step: empty strings participate and numeric text is never converted.

Column names are non-empty strings matched verbatim, and later operations refer to renamed columns. The dedup column list must be non-empty without duplicates. Missing/extra attributes, unknown operations, wrong types, unknown columns, a stored CSV with empty or duplicate headers, or records whose column count differs from the header all reject the whole cleaning.

Before cleaning, the stored blob is re-hashed against the version record. On any failure — unknown dataset or version, missing file, hash mismatch, unreadable or unparseable operations file, write failure — no version or lineage record is added and no version number is consumed. Repeating the same source version and operations yields identical output CSV bytes, row mappings, and step statistics, but every successful run still appends a version, even when nothing changes or only the header remains.

### Lineage

Each cleaned version records its direct source version, the source content hash, the full operation sequence, per-step input/output row counts, and the mapping from current columns back to source columns. `trim` steps record the modified source row numbers, `drop_duplicates` steps the deleted ones, and `rename` steps the before/after names. Every result row maps to a source data-record number counting from 1; a quoted newline inside a field does not count as a new record. Cleaning a cleaned version extends the chain, and `lineage` shows the whole chain source-first; the records persist across restarts and legacy workspaces work without re-importing. Exporting a cleaned version keeps the original manifest fields and adds the full chain under `lineage`.

### Keyed comparison

Without `--keys`, `compare` keeps its original schema/content output unchanged. With `--keys` (or the optional `keys` argument to `Catalog.compare`, a non-empty list of non-empty, unique column names present on both sides), the result gains a `rowDiff` object:

- `added` / `removed`: rows keyed only on the right / left, each with `key` (raw cell values in the specified column order), `row` (that side's 1-based data-record number), and `values` (every field on the union of the two headers, `null` for fields absent on that side).
- `modified`: matched keys with at least one changed field, with `key`, `leftRow`, `rightRow`, and `changes` mapping each changed field to `{"from": ..., "to": ...}`.
- `unchangedCount`: matched keys with no field changes. Reordering rows alone is not a modification.

Keys are matched on raw strings — no trimming, no numeric conversion (`"1"` ≠ `"01"`), and separators inside key values have no special meaning. Whitespace-only strings are valid keys, but an empty-string key cell rejects the whole comparison, as does a duplicated complete key on either side. A field existing only on one side compares as `null` versus the raw value, which is distinct from an empty string; a rename therefore appears as a removed field plus an added field at the schema level and as per-row `null`/value changes. Two header-only sides are a valid empty result. `added` and `modified` are ordered by right record number, `removed` by left record number, and field objects use stable name order.

Every keyed comparison re-verifies the SHA-256 of both stored files against the version records, including same-version comparisons. Unknown dataset/version, missing or unreadable file, hash mismatch, unparseable CSV, empty or duplicate headers, records with the wrong column count, or invalid key parameters fail the whole comparison with no partial diff. On the command line, failures print only `{"error": "原因"}` to stderr and exit 2; in Python, parameter or data errors raise `ValueError` and read failures may raise `OSError`. Comparison never modifies persisted state.
