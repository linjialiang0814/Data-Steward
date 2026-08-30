# Data Steward Read-only Plan v1

## 1. Purpose

`data-steward-readonly-plan/1` is the S3-B boundary between an untrusted
Hermes/model proposal and Data Steward's existing authorized PC executor. It
does not grant access and it does not contain an arbitrary action language.

## 2. Supported intents

| Intent | Query | Deterministic executor operation |
| --- | --- | --- |
| `count_images` | `null` | Count direct child files with an allow-listed image extension |
| `search_names` | A bounded substring present in the user message | Search direct child filenames |
| `unsupported` | `null` | No execution |

Only `windows_pc` is supported. A supported plan has exactly two ordered
steps: `inspect_authorized_scope`, then `search_authorized_assets`. The second
step depends on the first. Parallel calls, writes and arbitrary paths are not
representable.

## 3. Required fields

The top-level object has exactly:

```text
protocol_version / intent / target_device / scope_ref / query / risk
requires_confirmation / citations / steps / answer
```

For a supported plan:

- `protocol_version = data-steward-readonly-plan/1`;
- `risk = read_only` and `requires_confirmation = false`;
- citations are exactly the current process-lifetime scope reference and
  `capability:files.read`;
- the host verifies Chinese target, action and asset terms in the original
  user text; a model cannot turn unrelated chat into a file operation;
- `search_names.query` must occur verbatim in the user text;
- a host-computed SHA-256 binds the complete model plan to the user message.

## 4. Trust and failure rules

Hermes never receives an absolute path, directory display name, file list or
file content during planning. Its result is rejected for unknown/duplicate
fields, duplicate JSON keys, non-finite values, surrounding Markdown,
invented citations, a changed step graph, paths, write tools or partial model
output.

The Hub performs capability authentication before calling the planner. A
planner timeout or invalid response is attempted once and then falls back to
the proven S2 deterministic parser. The existing PC scope service remains the
only component that can scan the authorized directory.

The Hub revalidates the compiled Plan object immediately before translation
to an executor intent. Adapter injection therefore cannot bypass the source,
scope, citation, digest or user-grounding checks merely by returning a Python
object of the expected shape.

Only one model call may be in flight per Planner instance. A concurrent call
is rejected as `planner_busy` without queueing, provider access or retry, then
uses the deterministic fallback.

## 5. Non-goals

S3-B does not implement archive writes, long-term memory, recursive content
search, OCR, arbitrary devices or a general command runner. Those require
separate policy, confirmation and executor contracts.
