# Steward Hub domain core

`steward_hub` is the P0-S1-T02A standard-library domain core for durable
shared-session events. It contains no HTTP, WebSocket, device pairing, service
listener, or third-party Python dependency.

## Runtime

- Python 3.12
- `sqlite3` with WAL, foreign keys, explicit transactions, and busy timeout
- File-backed temporary databases for tests and smoke validation

## Validation

From the repository root in PowerShell:

```powershell
$env:PYTHONPATH = (Resolve-Path 'services/steward_hub/src').Path
python -m unittest discover -s services/steward_hub/tests -v
python services/steward_hub/tool/smoke_shared_session.py
```

The canonical event ordering field is `conversation_seq`. Delivery semantics
for a future network layer are at-least-once delivery plus idempotent
consumption, not network exactly-once.

The smoke emits a reproducible `semantic_projection_hash` over stable protocol
meaning. It excludes random `event_id`, payload `message_id`, and
`occurred_at`. Production IDs remain random UUIDs. Separately,
`persisted_round_trip_equal=true` proves that the complete event objects,
including random IDs, timestamps, payload, and payload hash, survive a
same-database close and reopen unchanged.

## Confirmed knowledge-pack export (S6-D)

The runtime can combine the current bounded cross-device content projection into
a `KnowledgePackV1` preview and, only after explicit confirmation, create one
UTF-8 Markdown file under the authorized PC root's `Data Steward 输出` child
directory. Device calls require the separately approved `artifact.export`
capability. Creation is exclusive, durable response-loss recovery is
idempotent, and undo deletes only a byte-for-byte unchanged generated artifact.
Hermes never receives a raw filesystem write tool. See
`docs/protocol/KNOWLEDGE_PACK_EXPORT_V1.md` for the wire and safety contract.

## Optional Hermes Agent boundary (S3-A)

`steward_hub.agent_adapter` is a standard-library-only readiness adapter for
the optional local Hermes runtime. It accepts only literal IPv4 loopback HTTP,
disables proxies, requires a runtime bearer, enforces total request deadlines
and 64 KiB response limits, and performs no automatic retry. It verifies the
pinned runtime version, authenticated capability contract and that every
built-in Hermes API toolset is disabled.

The adapter states are `disabled`, `unavailable`, `ready` and `degraded`.
Every non-ready state selects deterministic product fallback. S3-A deliberately
does not submit prompts or execute plans; Data Steward remains the owner of
authorization, policy, execution, receipts, audit and long-term memory.

S3-B adds `agent_planning.py`, a stateless Chat API client and strict read-only
plan compiler. The optional planner is injected into `create_app`; it cannot
grant capabilities or access paths. Valid plans are translated into the
existing `PcFileScopeService`, while unavailable or invalid model output falls
back once to the S2 deterministic parser without retry.

## Listener safety gate (B4)

The production HTTPS runtime defaults to `loopback-only` and literal
`127.0.0.1`. `pairing-only` and `authenticated-service` accept only a concrete
RFC1918 IPv4 and require the explicit `--acknowledge-private-lan-risk` flag on
every start. Wildcard, hostname, IPv6, public, and unacknowledged binds are
rejected before TLS identity, SQLite, or socket work. `pairing-only` exposes
only health and pairing routes; it does not expose conversation, WebSocket,
operator, or API-documentation routes.

Data Steward never changes Windows Firewall. Any supervised private-network
trial must follow `docs/operations/WINDOWS_PRIVATE_LAN_LISTEN.md`, begin in
pairing-only mode, and remove its manually created temporary rule afterward.
The legacy unauthenticated `steward_hub.server` remains loopback-only and must
never be used on a LAN.

## Loopback transport Spike

P0-S1-T02B adds a FastAPI/Uvicorn adapter that is forced to
`127.0.0.1`, one worker, reload disabled. It has no authentication, pairing,
or TLS and must not be exposed to a phone or LAN.

The ignored local environment is installed from official PyPI and verified
against `requirements.lock`:

```powershell
services/steward_hub/.venv/Scripts/python.exe -m pip check
```

S6-B adds bounded local extraction for UTF-8 TXT/Markdown, DOCX, PPTX and
text-layer PDF files inside the explicitly authorized PC root. DOCX/PPTX are
parsed as guarded ZIP/XML containers; PDF text uses pinned `pypdf==6.14.2`.
Each non-text document is parsed in an owned subprocess with a deadline and a
credential-minimized environment. Encrypted PDFs, attachments, macros,
embedded objects, external relationships and malformed/oversized containers
fail closed. Original bytes are not persisted. Derived excerpts and study-pack
payloads are CurrentUser-DPAPI sealed, revision-bound, expiring, and cleared on
content opt-out or PC scope revoke.

S6-C adds an authenticated Android OCR projection surface at
`POST /v1/content/android-ocr` and per-root deletion at
`DELETE /v1/content/android-ocr/{root_id}`. The phone performs OCR locally;
the Hub never receives image bytes, URI values or paths. It accepts at most six
revision-bound JPG/JPEG/PNG projections per request, requires
`content.analyze`, seals derived text with CurrentUser DPAPI, expires it after
seven days and excludes confidence below 0.55 from Hermes content context.
The upload is idempotent, and network recovery remains a single user-triggered
latest-only outbox attempt.

Controlled local start:

```powershell
$env:PYTHONPATH = (Resolve-Path 'services/steward_hub/src').Path
services/steward_hub/.venv/Scripts/python.exe -m steward_hub.server `
  --database "$env:TEMP/data-steward-local-hub.sqlite3" `
  --host 127.0.0.1 --port 43123 --workers 1
```

Transport validation:

```powershell
services/steward_hub/.venv/Scripts/python.exe `
  services/steward_hub/tool/smoke_transport.py
```

The smoke uses a random loopback port and temporary SQLite file, starts the
Hub twice, sends graceful shutdown through a parent-only stdin pipe, and
verifies that no child PID remains.

Replay cursors are checked against the durable server watermark
`conversation.next_seq - 1`. A cursor ahead of that state is rejected with
`cursor_ahead`; it is never echoed or silently clamped. Clients recover by
retrying from their last verified `conversation_seq`.

Before a persisted event reaches REST or WebSocket, the adapter recomputes
SHA-256 over the exact UTF-8 `payload_json`, compares it deterministically with
the stored hash, strictly validates the payload object, and requires
`payload.accepted_seq == event.conversation_seq`. Corrupt evidence fails closed
without exposing payload, hash, message ID, or database path.

## Loopback HTTPS + fingerprint pinning (B2B-A / R1)

Production TLS identity loading lives under `steward_hub.tls_identity`
(CurrentUser DPAPI + encrypted PKCS#8 + exact DACL). The loopback HTTPS entry
point is `python -m steward_hub.https_runtime` and binds only to `127.0.0.1`.
DPAPI-decrypted key passwords are wiped immediately after `SSLContext` load;
the Uvicorn factory holds only the ready context. Auth fingerprints must be
exact lowercase 64-hex (`^[0-9a-f]{64}$`).

Test/smoke pin-first client: `steward_hub.pin_client` (not the Flutter product
client). Git OpenSSL CLI remains a **test fixture only**. Product first-run
generation uses locked `cryptography==49.0.0` via
`steward_hub.tls_identity.provision_or_load_identity` (temporary directories only
until permanent LocalAppData identity is explicitly approved). Publish uses
`os.rename` as the commit point with recoverable `.provision_owner` marker;
steady-state final contains only the four identity files. Permanent paths resolve via Windows Known Folder `FOLDERID_LocalAppData` to
`DataSteward\hub\tls-identity-v1` (docs template:
`%LOCALAPPDATA%\DataSteward\hub\tls-identity-v1`). Product bootstrap is
`provision_or_load_permanent_identity()` (no path override; ignores
`LOCALAPPDATA` env). No TLS password is read from environment variables.

```powershell
services/steward_hub/.venv/Scripts/python.exe -m pip check
services/steward_hub/.venv/Scripts/python.exe `
  services/steward_hub/tool/provision_permanent_identity.py
services/steward_hub/.venv/Scripts/python.exe `
  services/steward_hub/tool/smoke_permanent_identity_https.py
services/steward_hub/.venv/Scripts/python.exe `
  services/steward_hub/tool/smoke_product_identity_provisioning.py
```

Directed validation:

```powershell
$env:PYTHONPATH = (Resolve-Path 'services/steward_hub/src').Path
services/steward_hub/.venv/Scripts/python.exe -m unittest `
  discover -s services/steward_hub/tests -p 'test_tls_identity_and_https.py' -v
services/steward_hub/.venv/Scripts/python.exe `
  services/steward_hub/tool/smoke_loopback_https_pinning.py
```

Authorized hosts may already hold the permanent Known Folder identity created
in B2B-B2 (device-local OS resource; not in Git). Do not recreate/rotate it
casually, open LAN ports, or write the Windows Certificate Store from this
package in P0. B3A/B3B/B3C and the B3D Dart contract are implemented on
loopback; LAN/Huawei network evidence remains gated by B4/C2.

## Live credential transitions (B3C)

When `create_app` is explicitly configured with a per-process operator token
digest, the loopback Hub exposes trusted operator status, grant-change, and
revoke routes under `/v1/operator/devices/{device_id}`. They require a separate
`DataSteward-Operator` bearer over pinned HTTPS; a device credential cannot
grant itself permissions.

Credential mutations use exact epoch CAS and completion-certain Store
execution. Protected REST operations and WSS sends are coordinated with the
same per-device transition barrier, so a request/frame completes before the
durable transition or is rejected after it. Operator routes do not exist when
the digest is omitted. See
`docs/protocol/PAIRING_AUTH_V1.md` for the public authentication and
credential-transition contract.

## Dart/Android secure pairing client (B3D)

The Flutter application now contains strict pairing codecs/state under
`lib/secure_pairing`, a direct pin-first HTTPS/WSS client, and an Android
Keystore AES-256-GCM MethodChannel vault. The Python/Dart real-process Smoke is
`tool/smoke_dart_android_pairing_client.py`; it uses only temporary identity,
database, and loopback resources.

Direct phone access must still satisfy the pinned TLS, capability, revocation,
and user-confirmation boundaries documented in `docs/protocol/PAIRING_AUTH_V1.md`.

## Intelligent archive suggestions and product memory (S3-C)

`steward_hub.archive_memory` adds a product-owned, SQLite-backed habit state
machine to the supervised shared-session runtime. It classifies only metadata
from the currently authorized PC directory and returns virtual collections;
it has no file-mutation API. Three distinct accepted suggestions form a
candidate, and a separate explicit approval is required before the rule can be
recalled in another conversation. Forgetting is immediate and fail-closed.

The component stores category counts, opaque IDs and SHA-256 evidence—not file
names, paths or contents. Suggest/recall require `files.read`; all receipts use
the existing durable conversation and live synchronization path. See
`docs/protocol/ARCHIVE_MEMORY_V1.md`.

## Proactive Hermes action cards (S6-E)

`steward_hub.proactive_suggestion` adds an opt-in, durable suggestion inbox.
The Host derives a bounded candidate set from the current catalog and existing
safe workflows; Hermes can select exactly one candidate through
`action_propose_typed_card`, but it receives no filesystem write tool.

Suggestions require a stable snapshot, are deduplicated across restart, use a
30-minute cooldown and a three-per-day limit, and pause a category after two
dismissals on the same day. Provider or network errors are not automatically
retried. Accepting a card only reveals its opaque action target and enters the
existing preview flow. File organization or Markdown export still requires a
separate explicit confirmation and retains its existing unchanged-only undo.
See `docs/protocol/PROACTIVE_ACTION_CARD_V1.md`.
