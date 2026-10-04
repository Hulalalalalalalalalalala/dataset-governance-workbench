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
- `verify-export 导出目录`: offline-verify that an export directory still matches its manifest. Reads only `manifest.json` and the CSV it names — never the workspace — and writes nothing.
- `rules 数据集 JSON文件`: configure a non-empty array of quality rules, returning the dataset's next immutable rule revision (1-based, contiguous).
- `validate 数据集 版本号 [--revision 修订号]`: validate a stored data version against a rule revision (latest if omitted); exit 0 when the report passes, 1 when violations are found, 2 on error.
- `validations 数据集 版本号`: list persisted validation reports for a data version, ascending by rule revision (empty array when none).
- `clean 数据集 版本号 操作文件`: clean a stored version and append the result as the dataset's next immutable version, returning its row count and inferred schema. The new version supports `compare`, `validate`, and `export`; source data, rule revisions, and validation reports are untouched.
- `lineage 数据集 版本号`: show the full cleaning chain for a version, source-first. Plain imported versions are chain starts (empty chain).
- `demo`: build two sample versions and show a comparison.

All catalog state lives below the selected workspace. Source CSV files are copied into a content-addressed blob directory, so later source-file changes do not alter recorded versions.

### Importing

A successful import guarantees the stored version is readable by cleaning, keyed comparison, export, and offline verification, so import applies the same structural rules those stages do. A file is accepted only when it:

- decodes as UTF-8;
- has a header row whose field names are all non-empty and unique; and
- has exactly as many fields in every data record as the header.

No header row, an empty field name, a duplicate field name, a missing or extra column, an unterminated quoted field, or any other parse error rejects the whole import. Error reasons distinguish these cases; a field-count error reports the 1-based data record number and the actual and expected column counts. Blank physical lines are not records and a newline inside a quoted field does not advance the record number, so a header-only file imports with zero rows and every field inferring as `null`. The empty string stays distinct from whitespace-only strings, the existing type inference rules are unchanged, text immediately following a closing quote remains legal, and values are never trimmed, padded, or rewritten.

The source is read once as raw bytes; the content hash, row count, schema, and stored blob all describe that exact snapshot, with newlines and quoting preserved byte-for-byte. Replacing or rewriting the source file during the import therefore cannot publish a version whose record disagrees with its stored bytes, and changing the source afterward has no effect on the version. Identical content shares one blob, but an existing content-addressed file is reused only after re-hashing confirms it matches; a damaged blob is reported as an error and is never overwritten or repaired on behalf of older versions. Re-importing the same valid content still appends a new version every time.

A missing or unreadable source, invalid data, or a failure while writing the blob or catalog state adds no dataset or version and consumes no version number: rules, validation reports, lineage, and existing data are untouched, no half-finished import is visible after a restart, and retrying once writes succeed uses the original next version number. Blob writes land via an atomic rename in the blob directory and catalog state is saved atomically. These strict checks apply only to new imports; existing workspaces keep their historical versions without re-importing. On the command line, import failures print only `{"error": "原因"}` to stderr and exit 2 (no success record, no traceback); in Python, parameter and data problems raise `ValueError` and read/write failures raise `OSError`.

### Rule configuration

Each rule object contains a unique non-empty string `id` and a `type` of `required`, `unique`, `range`, or `reference`. `required`, `unique`, and `range` rules carry a non-empty `column`. Range rules require `min` or `max`, each a finite number (never a boolean), endpoints included, with `min <= max`; non-range rules reject bounds. Unknown types, duplicate ids, missing required attributes, and extra attributes are all rejected.

A `reference` rule instead carries `columns` (this side's fields) and a `reference` object naming another fixed version, e.g. `{"id": "客户引用", "type": "reference", "columns": ["客户号", "地区"], "reference": {"dataset": "客户", "version": 2, "columns": ["编号", "地区"]}}`. The two column arrays correspond by position and must be non-empty, equal in length, free of duplicates, and contain only non-empty strings; the reference version must be a positive integer (never a boolean) and the dataset a non-empty string. The referenced dataset, version, and columns must exist when the rules are saved (a failed configuration adds no revision and consumes no number); the local columns are checked when a data version is validated. Imported and cleaned versions may serve on either side, and versions appended later on the reference side do not change what an existing revision points at. Reference rules mix freely with the other rule types in one revision.

### Validation semantics

- Row numbers count CSV data records starting at 1; a quoted newline inside a field does not advance the row number.
- An empty string is a missing value and surrounding whitespace is never stripped.
- `required` reports rows with missing values; `unique` compares non-empty raw strings and reports every row of each duplicated group; `range` skips missing values and flags non-numeric, non-finite, or out-of-bounds values.
- Bounds are compared against the exact decimal value the cell text denotes, never against a binary-float rounding of it: `1`, `1.0`, and `1e0` are the same number, `+0` and `-0` both equal zero, but `1.00000000000000001` is genuinely above a maximum of `1` and `-1e-400` is genuinely below a minimum of `0` — no fraction is dropped and no subnormal-magnitude value is flushed to zero. Integer boundaries keep their full precision (with max `9007199254740992`, the endpoint passes in plain, decimal, or scientific form while `9007199254740992.1` violates); a float boundary is understood as the decimal text it usually displays, so a cell `0.1` sits exactly on a `0.1` bound rather than off by its binary storage error. Endpoints stay inclusive for min-only, max-only, and two-sided rules. Text whose magnitude overflows a float (e.g. `1e309`) remains a violation, as do booleans, `NaN`, and infinities; such rows never interrupt the run.
- `reference` matches complete column combinations as raw strings — no trimming, no numeric conversion, and separators inside values have no special meaning. A record violates when any of its referenced values is an empty string or its complete combination does not exist on the reference side; repeated records are reported one by one. An empty value or a duplicate complete combination on the reference side fails the whole run, even when the local side has no records. A header-only reference version is legal and makes every local record a violation; when both sides have no records the rule passes.
- Column names match verbatim.
- Reports persist across restarts. Re-validating the same data version and rule revision returns the identical stored report, but the local blob is re-snapshotted and re-verified every time — an existing report never excuses a stale or missing file. Validation never modifies CSVs, infers structure, or creates data versions.
- Each side (the local version and every referenced version) is read exactly once as raw bytes. The content hash, the row count, and every violation line all derive from that single snapshot, so they are guaranteed to describe one and the same content: if the stored file is rewritten, replaced, or deleted after the snapshot is taken, the run still completes from the bytes already in memory and never mixes in later fields or records. A version referenced by several rules, or serving simultaneously as the local side and a reference target, is snapshotted once and seen identically everywhere. Such a later change is observed on the next invocation, which then fails; a successful prior report is neither recomputed nor repaired.
- Reference-rule results use `columns` for the local fields and a `reference` object with the referenced dataset, version, columns, and `content_sha256`; that hash names exactly the target bytes used for matching. Counts and `passed` keep their usual meaning. Every validation involving reference rules re-verifies the local side and all referenced sides even when a report already exists: a missing file, hash mismatch, missing field, or invalid CSV structure on any side fails the whole run — no partial report is returned and no stored report is overwritten — and the error names the dataset and version involved.
- If any side's bytes do not hash to the version record's SHA-256 (or, when reusing a report, to the hash recorded in that report), the whole validation fails before any rule result is produced and no report is added or overwritten. A missing file or read failure is reported the same way and names the dataset and version involved.
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

### Offline export verification

`verify-export 导出目录` (or `Catalog.verify_export(directory)`) checks that an exported directory still agrees with its manifest without touching the workspace: only `manifest.json` and the CSV it names are read, and no file is written or cached, so every invocation re-checks from scratch. The export command and manifest shape are unchanged, and verification tolerates older manifests that ship no `lineage` as well as unknown extra fields.

The report is a JSON object `{"dataset", "version", "passed", "issues"}`, where `issues` is an array of `{"code", "message"}` objects (empty on success). Every independently determinable problem is returned, ordered by category: `missing` → `hash` → `csv` → `rows` → `schema` → `lineage`.

- **hash**: the CSV's raw bytes hashed with SHA-256 must equal `record.content_sha256`.
- **csv**: structural validity — decodes as UTF-8, has a header row with non-empty, non-duplicate field names, every data record has the same column count as the header, and no quoted field is left unterminated. A missing data file is reported separately as **missing**.
- **rows**: the number of data records must equal `record.row_count`. Blank physical lines are not records, a quoted newline does not advance the record number, and a header-only file has zero records.
- **schema**: the header field set must equal the record's, and each field's type inferred with the existing import semantics must match the declared type.
- **lineage**: with a non-empty `lineage` array, every entry must belong to the same dataset, each source version must be below its result version, adjacent entries must connect by version and hash, and the last entry's version, content hash, and row count must equal the record. No ancestor data is required. A missing field or an empty array means no chain was shipped.

Manifest problems are hard errors rather than report entries: a missing or unreadable manifest, invalid JSON or UTF-8, a `schemaVersion` that is not the integer `1`, a missing or mistyped required field, a non-positive-integer version, a negative row count, a non-64-character-lowercase-hex hash (booleans never count as integers), or an invalid `file` name. `file` must be a non-empty plain name (not `.` or `..`, no path separators, no NUL) that stays inside the export directory, including when it reaches outside through a symbolic link; such references are refused before the target is read. On the command line these errors print only `{"error": "原因"}` to stderr and exit 2, data discrepancies print the report to stdout with exit 1, and a clean verification exits 0. In Python, manifest and parameter problems raise `ValueError` and read failures raise `OSError`.
