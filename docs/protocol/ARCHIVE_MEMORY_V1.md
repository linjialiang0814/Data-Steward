# Data Steward Archive Memory v1

> Status: implemented for P0-S3-C MVP
> Scope: one PC-authorized directory class; virtual suggestions only

## 1. Product boundary

Archive Memory is owned by Data Steward, not by the Hermes runtime. Hermes has
already passed the S3-B live planning gate; S3-C keeps learning deterministic,
local and auditable so a provider outage cannot erase or invent a user habit.

The v1 rule is `category-v1`: classify direct child files into images,
documents, media, archives and other. A recommendation creates virtual
collections only. There is deliberately no move, rename, delete, file-content
read or write API in this component.

## 2. Commands

The MVP accepts only these explicit Chinese commands:

- `智能整理电脑授权目录`
- `给出电脑授权目录的归档建议`
- `接受归档建议 sg-<12 lowercase hex>`
- `拒绝归档建议 sg-<12 lowercase hex>`
- `批准整理习惯 mem-<12 lowercase hex>`
- `按我的习惯整理电脑授权目录`
- `忘记整理习惯 mem-<12 lowercase hex>`

Ambiguous physical-mutation requests do not enter this state machine.

## 3. Learning state machine

```text
suggestion: pending -> accepted | rejected
memory: learning --(3 distinct accepted suggestions)--> candidate
memory: candidate --(explicit user approval)--> active
memory: learning | candidate | active --(explicit forget)--> forgotten
```

Duplicate suggestion requests and duplicate accepts are idempotent. Three
accepted suggestions are evidence, not consent: only an explicit approval
activates cross-conversation recall. A forgotten v1 memory is fail-closed and
cannot silently reactivate.

## 4. Scope and privacy

The memory scope is the product class `pc-authorized-directory`, so an approved
classification habit survives Hub restart and reauthorization. Every recall
still requires a currently authorized directory and a fresh `files.read`
capability check. Because the action is virtual and user-triggered, the rule
does not gain physical write authority when applied to a newly authorized
directory.

Persisted evidence contains only:

- opaque suggestion/memory IDs;
- hashed conversation-message reference;
- opaque current authorization root ID;
- category counts;
- SHA-256 of the sorted metadata evidence;
- decision, support count, version and timestamps.

Filename, full path, file content, provider prompt/response, credential and
device serial are forbidden from Archive Memory storage and conversation
receipts.

## 5. Authorization and synchronization

Generating or recalling a suggestion requires `session.sync` plus
`files.read`. Accept/reject/approve/forget operate on product memory and need
the already-required `session.sync`; they do not scan files. The Hub persists
one derived assistant event (`data-steward-memory`) and publishes it through
the existing ordered shared-session channel.

## 6. Known MVP limits

- one fixed category rule; no semantic/OCR clustering;
- direct child files only;
- no editing of a learned rule and no re-learning after explicit forget;
- no physical archive execution or undo is claimed;
- confidence is represented by the visible evidence threshold, not a model
  probability.
