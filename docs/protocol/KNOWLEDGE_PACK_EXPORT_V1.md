# Knowledge Pack Export V1

Status: `IMPLEMENTED / LIVE_GATE_PENDING`

## 1. Purpose

This contract turns the latest snapshot-bound content projection into a
cross-device knowledge pack, then exports it as a new Markdown artifact only
after explicit user confirmation. It does not expose raw paths, locators,
document bodies, device secrets, or internal asset identifiers.

## 2. KnowledgePackV1

Public schema: `data-steward.knowledge-pack/v1`.

Required public fields are `pack_id`, `kind`, `title`, `summary`, `topics`,
`review_points`, `citations`, `source`, `cross_device`, `created_at`, and
`projection_sha256`. Supported kinds are `learning`, `meeting`, `project`, and
`general`. A citation exposes only a stable ordinal, platform, source display
name, file display name, optional modification time, and a `basis` value. Basis
is `content_projection` when the content/OCR projection was actually selected,
or `catalog_metadata` when one deterministic metadata-only citation represents
an otherwise missing current device. UI and Markdown must label this distinction;
metadata-only citations must never imply body understanding.

The Hub validates every citation against the current catalog snapshot. Missing,
duplicated, stale, unsupported-platform, or over-budget citations fail closed.
The private snapshot hash, catalog locator, root ID, device ID, and asset ID are
not present in the public wire representation.

## 3. Export capability and endpoints

Device requests require `artifact.export`. `POST /v1/artifacts/prepare` also
requires `content.analyze`. Existing credentials are never expanded silently;
the device must complete an explicit permission migration.

Operator routes use `/v1/operator/artifacts/*`; authenticated device routes use
`/v1/artifacts/*`:

- `POST /prepare`: `{kind, request}` → bounded preview and sources;
- `POST /execute`: schema, pack ID, preview hash, and idempotency key → receipt;
- `GET /status`: latest durable state and unchanged-only undo availability;
- `POST /undo`: schema and opaque undo token → receipt.

The execute key is bound to one preview in the client and reused after an
ambiguous response. Repeated identical execution converges to the same receipt;
changed inputs with the same key fail closed.

## 4. Filesystem boundary

The Host executor writes only UTF-8 Markdown without BOM, at most 128 KiB, into
the direct child directory `Data Steward 输出` below the currently authorized PC
root. The filename is relative, sanitized, bounded, and must end in `.md`.

Creation uses exclusive-create semantics and never overwrites an existing file.
The output directory and target must not be symlinks or reparse points. The
SQLite journal stores metadata, hashes, and state only—not Markdown or absolute
paths.

## 5. Recovery and undo

Durable states are `PREPARED → COMPLETED → UNDOING → UNDONE`. On restart or an
ambiguous response, status compares the bounded file against the recorded size
and SHA-256. An exact file converges to `COMPLETED`; a missing/changed file enters
`recovery_required`.

Undo deletes only an exact byte-for-byte match. If the user edits, replaces, or
removes the file, Data Steward does not overwrite or delete anything and returns
`artifact_modified` or `recovery_required`. Source files are never changed by
knowledge-pack export.

## 6. Retry policy

There is no background retry loop. A transient network failure is shown once;
the user waits for network stability and manually refreshes status or retries
the same confirmation-bound operation.
