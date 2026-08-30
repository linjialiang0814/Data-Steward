# PAIRING_AUTH_V1

> Protocol version: `pairing_auth/1`  
> Status: IMPLEMENTED_THROUGH_B4 (Huawei LAN evidence pending C2)  
> Transport: TLS 1.2+ with certificate fingerprint pinning before any secret is sent  
> Crypto: mature TLS, OS CSPRNG, **SHA-256 digests only**, constant-time compare; no homemade ciphers; no E2EE claim

## 1. Goals

1. First-time pairing of Huawei Android (later Pad) to Windows Hub.
2. Client-generated per-device secrets; Hub stores digests only and activates after dual confirm.
3. Same identity semantics for REST and WebSocket.
4. Remain loopback-only until a later LAN listen gate task.

## 2. Locked encoding and entropy

| Item | Rule |
|---|---|
| CSPRNG | OS CSPRNG only (`secrets` / platform equivalent) |
| OTT | **256-bit** (32 bytes) random |
| `device_credential_secret` | **256-bit** (32 bytes) random; client-generated |
| `claim_secret` | **256-bit** (32 bytes) random; client-generated |
| `client_nonce` | **128-bit** (16 bytes) random |
| Wire encoding for raw secrets | **base64url**, no padding (`=` stripped) |
| OTT / secret wire length | 32 bytes → **43** base64url chars; 16 bytes → **22** chars |
| Digest algorithm | **SHA-256** over the **raw secret bytes** (not over the base64url string) |
| Digest wire/storage | lowercase hex, **64** chars |
| Digest security note | SHA-256(digest-only auth) is acceptable here because secrets are ≥256-bit CSPRNG, not low-entropy passwords |
| Constant-time compare | Required for all digest and secret equality checks |
| `device_id` / session ids | ULID (Crockford base32), **26** chars |
| Forbidden | MAC, IP, serial as identity; secrets in URL query/fragment; homemade KDF/cipher |

Reject any secret/OTT whose decoded length ≠ expected byte length.

## 3. Identifiers and fields

| Field | Meaning | Rules |
|---|---|---|
| `protocol_version` | `pairing_auth/1` | Mismatch → `protocol_version_rejected` |
| `hub_id` | Stable Hub public id | ULID; not secret |
| `boot_id` | Per Hub process boot | ULID; new on every start |
| `device_id` | Hub-issued device id | ULID; assigned at `client_hello`; **only** in `X-DataSteward-Device-Id` for auth (not inside Bearer) |
| `cert_fingerprint` | Hub leaf TLS pin | SHA-256(DER) lowercase hex, 64 chars, no colons on wire |
| `pairing_session_id` | Hub pairing session | ULID |
| `pairing_attempt_id` | Client attempt id | ULID; client-generated; idempotency key for `client_hello` |
| `pairing_token` / OTT | One-time pairing token | 256-bit; **QR or manual entry only**; never mDNS; never logs/UI errors |
| `pairing_token_digest` | Hub storage | `SHA-256(raw_ott_bytes)` hex |
| `device_credential_secret` | Long-lived client secret | 256-bit; Keystore; Hub never receives after pairing except in auth Bearer |
| `device_credential_digest` | Hub storage / hello field | `SHA-256(raw_device_credential_secret_bytes)` hex |
| `claim_secret` | Binds attempt to client | 256-bit; submitted in `client_hello` body once to establish claim; afterward proven via `Authorization: Pairing <claim_secret>`; Hub stores digest only |
| `claim_secret_digest` | Hub storage | `SHA-256(raw_claim_secret_bytes)` hex |
| `client_nonce` | Attempt freshness | 128-bit base64url |
| `requested_capabilities` | Client request set | Sorted unique strings; client cannot self-grant |
| `granted_capabilities` | Hub user-approved set | ⊆ request after user edit; **only** this authorizes |
| `capability_epoch` | Monotonic grant generation | int; starts at 1 on activate; bumps on grant change |
| `short_verification_code` | Human confirm | 8 chars **DataSteward Human32** (see §6.1.1); not a network authenticator; **not** Crockford Base32 |
| `expires_at` (QR) | Display hint only | RFC3339 UTC; **server TTL is authoritative** |

## 4. Discovery

### 4.1 mDNS (allowed / forbidden)

Service: `_datasteward._tcp.local`.

**Allowed TXT / advertisement fields:**

- `hub_id`
- `protocol_version`
- `host` / `port` (or equivalent SRV+A)
- `cert_fingerprint`
- `pairing_available` = `true` \| `false`

**Forbidden in mDNS:**

- raw OTT / `pairing_token`
- `device_credential_secret` / digests of long-term credentials for auth bypass
- `claim_secret`
- short verification code
- any field that alone completes pairing

mDNS is untrusted discovery only. Client must still pin TLS fingerprint and obtain OTT via QR or explicit manual entry.

### 4.2 QR (OTT channel)

```json
{
  "protocol_version": "pairing_auth/1",
  "hub_id": "<ulid>",
  "base_url": "https://<host>:<port>",
  "cert_fingerprint": "<64-hex>",
  "pairing_session_id": "<ulid>",
  "pairing_token": "<43-char-base64url>",
  "expires_at": "<rfc3339-utc-display-hint>"
}
```

Rules:

- OTT only via PC-local QR display or explicit manual entry UI (segmented OTT entry ≠ short verification code).
- `expires_at` is UX only; Hub enforces server-side TTL from `created_at` + configured duration (default **120s**).
- `base_url` must be `https://`; reject `http://` and `0.0.0.0`.
- Never log full QR JSON (contains OTT).

## 5. Pairing session state machine

Hub listen modes remain orthogonal (see §15). Pairing session states:

```text
PAIRING_IDLE
  -> create session + show QR -> PAIRING_ACTIVE

PAIRING_ACTIVE
  -> valid client_hello -> AWAITING_CONFIRM
  -> timeout|cancel|operator_disable|hub_restart -> terminal abort

AWAITING_CONFIRM
  -> hub_user_confirm AND client_confirm (both, order-independent) -> ACTIVE_PAIR
  -> either side reject | short_code mismatch threshold | timeout | cancel | hub_restart -> terminal abort

ACTIVE_PAIR (session terminal success)
  -> return to PAIRING_IDLE for next device (session row remains for audit)

Terminal abort reasons (examples):
  ABORTED_TIMEOUT | ABORTED_CANCEL | ABORTED_MISMATCH | ABORTED_HUB_RESTART
  | ABORTED_SUPERSEDED | ABORTED_PROTOCOL
```

Credential row states (separate table):

```text
PENDING  -> (dual confirm + txn) -> ACTIVE
PENDING  -> timeout|abort|cleanup -> PURGED (row deleted or status=EXPIRED)
ACTIVE   -> revoke -> REVOKED
ACTIVE   -> capability grant change -> ACTIVE (capability_epoch++)
```

Invariants:

1. Hub **never** generates or re-sends `device_credential_secret`.
2. Incomplete/abort paths never leave `ACTIVE` credential for that attempt.
3. MVP: at most one non-terminal pairing session per Hub.
4. OTT digest is bound to `pairing_session_id`; after terminal success or hard abort, OTT cannot be reused.

## 6. Client-bound pairing flow

```text
1. PC: create pairing_session (store ott_digest, server TTL, boot_id); show QR (includes OTT).
2. Phone: scan QR or manual entry; TLS connect; pin cert_fingerprint; abort if mismatch.
3. Phone: CSPRNG generate device_credential_secret (256-bit), claim_secret (256-bit),
   client_nonce (128-bit), pairing_attempt_id (ULID); store secrets in Keystore/private store.
4. Phone -> POST client_hello (only after pin OK) with fields in §8.1.
5. Hub: validate OTT digest, TTL, session state; create/return PENDING device_id;
   store pending digests + requested_capabilities; compute short_verification_code from transcript;
   return pending device_id + short code material as needed for display.
6. Phone UI and PC UI each display short_verification_code derived from the same transcript.
7. User confirms on phone (client_confirm) and on PC (hub local confirm), approving/reducing capabilities on PC.
8. When both confirms present: single DB transaction sets credential ACTIVE, writes granted_capabilities,
   capability_epoch=1, consumes OTT, terminal success session.
9. Phone authenticates with device_id + local secret. No server "issue secret" / ACK of raw secret.
```

### 6.1 Short verification code transcript

Canonical transcript bytes (UTF-8) are the concatenation of lines, each `key=value\n`, keys in this exact order:

```text
protocol_version
hub_id
cert_fingerprint
pairing_session_id
pairing_attempt_id
ott_digest
device_credential_digest
claim_secret_digest
client_nonce
requested_capabilities_digest
```

Where:

- digests are 64-char lowercase hex;
- `client_nonce` is the base64url wire form;
- `requested_capabilities_digest` = SHA-256 hex of UTF-8 JSON array of capabilities sorted lexicographically.

Then encode `SHA-256(transcript_bytes)[0:5]` with **DataSteward Human32** (§6.1.1) to an 8-character `short_verification_code`.

PC and phone **must** compute independently. Different clients using the same QR produce different `pairing_attempt_id` / secrets / nonce ⇒ different short codes. User only approves the code shown on their own phone.

**Deprecated (forbidden):** transcript of only `hub_id|fingerprint|session_id|ott_digest`.  
**Forbidden naming:** calling this alphabet “Crockford Base32” (it is not).

### 6.1.1 DataSteward Human32 (locked)

Chosen over standard Crockford Base32 because the alphabet omits `0`, `1`, `I`, `O` for human verification.

| Item | Rule |
|---|---|
| Name | **DataSteward Human32** |
| Alphabet (index 0..31 in this exact order) | `23456789ABCDEFGHJKLMNPQRSTUVWXYZ` |
| Input | First **5** bytes of `SHA-256(transcript_bytes)` |
| Bit order | Interpret those 5 bytes as a **big-endian** unsigned 40-bit integer |
| Output | 8 characters: for `i = 0..7`, take bits `[39-5i : 35-5i]` (MSB first) as a 5-bit index into the alphabet |
| Interop | Python Hub and Dart client **must** share fixed golden-vector tests (below); any mismatch is a release blocker |

Reference algorithm (normative semantics; implementations use mature language primitives only):

```text
n = uint40_be(sha256(transcript)[0:5])
for i in 0..7:
  code[i] = ALPHABET[(n >> (35 - 5*i)) & 31]
```

#### Golden vectors (fixtures only; not live secrets)

Each transcript is the exact UTF-8 concatenation of the listed `key=value\n` lines (final newline included). Implementations must assert identical 8-char codes.

**Vector 1** — expected code `2EJ9Y5EW`  
SHA-256 = `03207f0d9c3c4998db07588b0c51e8641f0e14b4d396ca7707032c0986648869`  
first5 = `03207f0d9c`

```text
protocol_version=pairing_auth/1
hub_id=01ARZ3NDEKTSV4RRFFQ69G5FAV
cert_fingerprint=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
pairing_session_id=01ARZ3NDEKTSV4RRFFQ69G5FAW
pairing_attempt_id=01ARZ3NDEKTSV4RRFFQ69G5FAX
ott_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
device_credential_digest=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
claim_secret_digest=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
client_nonce=AAAAAAAAAAAAAAAAAAAAAA
requested_capabilities_digest=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
```

**Vector 2** — expected code `J5PLXKDR`  
SHA-256 = `80eb2ec57787d852061234e9238a58bfbd8fa18d471d4df51de3fc126dcc6908`  
first5 = `80eb2ec577`

```text
protocol_version=pairing_auth/1
hub_id=01BX5ZZKBKACTAV9WEVGEMMVRZ
cert_fingerprint=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
pairing_session_id=01BX5ZZKBKACTAV9WEVGEMMVS0
pairing_attempt_id=01BX5ZZKBKACTAV9WEVGEMMVS1
ott_digest=0000000000000000000000000000000000000000000000000000000000000000
device_credential_digest=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
claim_secret_digest=1111111111111111111111111111111111111111111111111111111111111111
client_nonce=BBBBBBBBBBBBBBBBBBBBBB
requested_capabilities_digest=2222222222222222222222222222222222222222222222222222222222222222
```

**Vector 3** — expected code `ZHSEF84R`  
SHA-256 = `fbf0c69857d3e9384292b890fc278a321a4b1c150dd6f5aebe58c3faf9a2cc3f`  
first5 = `fbf0c69857`

```text
protocol_version=pairing_auth/1
hub_id=01HXYZEXAMPLE000000000001
cert_fingerprint=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
pairing_session_id=01HXYZEXAMPLE000000000002
pairing_attempt_id=01HXYZEXAMPLE000000000003
ott_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
device_credential_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
claim_secret_digest=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
client_nonce=CCCCCCCCCCCCCCCCCCCCCC
requested_capabilities_digest=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
```

B2/C1 test plan **must** include these three vectors in both Python and Dart, plus a cross-language equality check.

### 6.2 `client_hello` idempotency

Key: `(pairing_session_id, pairing_attempt_id)`.

| Case | Behavior |
|---|---|
| First hello with valid OTT | Create PENDING credential + return same response fields |
| Retry: same `pairing_attempt_id` and **byte-identical** hello inputs | Return original pending result (idempotent) |
| Same `pairing_attempt_id` but any material field changed | Fail-closed `pairing_attempt_conflict` |
| Different `pairing_attempt_id` on same session while another PENDING exists | MVP: reject `pairing_busy` (single attempt); attacker race cannot change bound transcript for the user’s attempt |
| OTT already consumed / session terminal | `pairing_expired` or `pairing_rejected` |

### 6.3 Confirm response loss recovery

- Hub does **not** resend long-term secrets (none exist server-side).
- If final success response is lost: client calls redacted `GET .../status` **with Pairing claim auth** and/or attempts device REST auth with local secret.
- `ACTIVE` ⇒ success; `PENDING` ⇒ continue waiting/confirm; terminal abort ⇒ user restarts pairing.
- Pending rows expire by **server clock** (default pending TTL **300s** from hello) and become non-authable.
- Status without a valid claim is always rejected (no anonymous session probing).

## 7. Capabilities

| Field | Who sets | Role |
|---|---|---|
| `requested_capabilities` | Client | Wish list only |
| `granted_capabilities` | Hub PC user via trusted local UI | Sole authorization source |
| `capability_epoch` | Hub | Increments on grant change; stale epoch rejected |

Rules:

1. Client cannot self-grant.
2. PC UI shows request; user may approve subset (e.g. request `fs.write`, grant only `session.sync`).
3. Privilege expansion requires a new local approval (new epoch).
4. Transcript/`requested_capabilities_digest` binds what the phone claimed at hello; PC confirm UI must show that request; server stores both request and grant.
5. Every privileged REST/WS action requires capability ∈ `granted_capabilities` and matching epoch policy (§12).

## 8. REST surfaces

### 8.1 Pre-device-credential pairing endpoints

Category name: **pre-device-credential pairing endpoints** (not “unauthenticated”).

Only when listen mode is `pairing-only` or `authenticated-service` with pairing enabled.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/pairing/sessions/{pairing_session_id}/client_hello` | None (OTT in body establishes claim) | Bind attempt + pending digest; **sole** endpoint that may submit OTT without prior claim auth |
| `POST` | `/v1/pairing/sessions/{pairing_session_id}/client_confirm` | `Authorization: Pairing <claim_secret>` | Phone confirms short code |
| `GET` | `/v1/pairing/sessions/{pairing_session_id}/status` | `Authorization: Pairing <claim_secret>` | Redacted status for recovery |

Hub user confirm is **local to the Hub process/UI**, not a phone-exposed grant API.

**Removed:** any `redeem` that returns a server-generated long-term secret; anonymous `status`.

#### Pairing claim authorization (locked)

```http
Authorization: Pairing <43-char-claim-secret-base64url>
```

Rules:

1. Required on `client_confirm` and `status`.
2. Hub loads attempt by `pairing_session_id` + `pairing_attempt_id`, reads `claim_secret_digest`, SHA-256-decodes the header secret, constant-time compares.
3. Missing header → `401` `claim_missing`. Wrong secret → `401` `claim_invalid`. Attempt/session expired or purged → `401` `claim_expired` (or `410` `pairing_expired` when session TTL is the cause).
4. Attempt A’s claim used against attempt B → `401` `claim_invalid` (no existence oracle beyond stable codes).
5. `Authorization` values **must never** appear in logs, UI, traces, or responses.
6. `client_confirm` JSON **must not** repeat raw `claim_secret`.
7. `status` still returns only redacted fields (no OTT, secrets, digests).

#### `client_hello` request

```json
{
  "protocol_version": "pairing_auth/1",
  "pairing_attempt_id": "<ulid>",
  "pairing_token": "<43-char-base64url>",
  "claim_secret": "<43-char-base64url>",
  "device_credential_digest": "<64-hex>",
  "client_nonce": "<22-char-base64url>",
  "requested_capabilities": ["session.sync", "fs.read"],
  "platform": "android",
  "display_name": "<optional short label>"
}
```

TLS fingerprint pin **must** succeed before this request is sent.  
This is the **only** pre-device-credential call that may carry raw OTT and the initial `claim_secret` in the JSON body.

#### `client_hello` response `200`

```json
{
  "protocol_version": "pairing_auth/1",
  "pairing_session_id": "<ulid>",
  "pairing_attempt_id": "<ulid>",
  "device_id": "<ulid>",
  "credential_status": "PENDING",
  "short_verification_code": "<8-char-Human32>",
  "server_time": "<rfc3339-utc>",
  "pending_expires_at_hint": "<rfc3339-utc>"
}
```

#### `client_confirm` request

Headers:

```http
Authorization: Pairing <43-char-claim-secret-base64url>
X-DataSteward-Protocol: pairing_auth/1
```

Body (no `claim_secret` field):

```json
{
  "protocol_version": "pairing_auth/1",
  "pairing_attempt_id": "<ulid>",
  "short_verification_code": "<8-char-Human32>"
}
```

#### `client_confirm` response `200`

```json
{
  "protocol_version": "pairing_auth/1",
  "pairing_attempt_id": "<ulid>",
  "device_id": "<ulid>",
  "credential_status": "PENDING|ACTIVE",
  "granted_capabilities": ["session.sync"],
  "capability_epoch": 1
}
```

`ACTIVE` only when Hub local confirm already recorded; otherwise `PENDING`.

#### `status` request

```http
GET /v1/pairing/sessions/{pairing_session_id}/status?pairing_attempt_id=<ulid>
Authorization: Pairing <43-char-claim-secret-base64url>
X-DataSteward-Protocol: pairing_auth/1
```

#### `status` response `200` (redacted)

```json
{
  "protocol_version": "pairing_auth/1",
  "pairing_session_id": "<ulid>",
  "pairing_attempt_id": "<ulid>",
  "session_state": "PAIRING_ACTIVE|AWAITING_CONFIRM|ACTIVE_PAIR|ABORTED_*",
  "credential_status": "PENDING|ACTIVE|UNKNOWN|EXPIRED",
  "device_id": "<ulid-or-null>",
  "capability_epoch": 0
}
```

Never returns OTT, secrets, digests, or Authorization material.

#### Required negative / recovery tests (B2+)

| Case | Expected |
|---|---|
| `status` without `Authorization: Pairing` | `401` `claim_missing` |
| `status` with wrong claim | `401` `claim_invalid` |
| Attempt A claim used on attempt B status | `401` `claim_invalid` |
| Correct claim after lost `client_confirm` response | `200` redacted status succeeds |
| Hub/App logs for above | no `Authorization` header values; no raw `claim_secret` |

### 8.2 Device-credential authenticated REST

```http
Authorization: Bearer <device_credential_secret_base64url>
X-DataSteward-Protocol: pairing_auth/1
X-DataSteward-Device-Id: <device_id>
X-DataSteward-Capability-Epoch: <int>
```

Locked rules:

- `device_id` appears **only** in `X-DataSteward-Device-Id` (required). Bearer is **only** the 43-char base64url secret (no embedded device_id).
- No secrets in query/fragment/body for GET auth.
- Hub loads the row by `device_id` and **first** constant-time compares
  `SHA-256(raw_secret)` with the stored digest. A mismatch returns
  `auth_invalid` without exposing lifecycle state. Only after possession is
  proven may the Hub classify `ACTIVE` / `REVOKED` / `PENDING` / `EXPIRED`.
  An `ACTIVE` credential must then present an epoch exactly equal to the
  current `capability_epoch` and hold every capability required by the
  operation; mismatch → `capability_epoch_stale`, missing grant →
  `capability_denied`.

### 8.3 Trusted local operator credential transitions

These routes are absent unless the Hub is configured with a SHA-256 digest of
a per-process 256-bit operator bearer:

```text
GET  /v1/operator/devices/{device_id}
POST /v1/operator/devices/{device_id}/revoke
PUT  /v1/operator/devices/{device_id}/capabilities
```

They require exactly one
`Authorization: DataSteward-Operator <43-char-base64url-secret>` and
`X-DataSteward-Protocol: pairing_auth/1` over pinned loopback HTTPS. The raw
operator bearer is never stored by the Hub. A device credential cannot call
these routes, and capability expansion remains a trusted PC-user action.

Both mutations use exact expected-epoch CAS. Identical grants/repeated revoke
are no-op successes. GET provides redacted post-timeout reconciliation.

### 8.4 Limits (pre-device-credential pairing endpoints)

| Limit | Value |
|---|---|
| Max JSON body | **16 KiB** |
| Request timeout | **10 s** |
| `client_hello` rate | **10 / minute / source address** (loopback tests use logical source key) |
| `client_confirm` rate | **20 / minute / source address** (failed claim auth counts) |
| `status` rate | **30 / minute / source address** (failed claim auth counts) |
| Short-code mismatch | **5** per attempt then abort session |
| Claim auth failures | count toward confirm/status rate limits; no extra oracle delay required beyond constant-time compare |

Exceed → `429` `rate_limited` (retryable after `Retry-After`) or `413` `payload_too_large` (not auth-retry).

## 9. WebSocket authentication and live revoke

### 9.1 Order

```text
1. TLS + pin
2. Client first frame: auth { kind, protocol_version, device_id, capability_epoch, credential }
3. Server constant-time validates the credential digest before exposing
   lifecycle status, then validates `ACTIVE`, exact epoch, and capabilities
4. auth_ok | auth_failed
5. Only after auth_ok: subscribe / replay
```

Subscribe before auth → close `policy_violation`; no events.

The B3B first frame is one strict text JSON object with these exact keys:

```json
{
  "kind": "auth",
  "protocol_version": "pairing_auth/1",
  "device_id": "<26-char ULID>",
  "capability_epoch": 1,
  "credential": "<43-char unpadded base64url secret>"
}
```

The complete decoded message is limited to 4096 UTF-8 bytes and must arrive
within 10 seconds (validated configuration maximum 30 seconds). Duplicate,
missing, or extra keys; binary messages; non-finite JSON numbers; boolean or
non-canonical epochs; and malformed credentials fail closed. WebSocket
fragmentation is handled by the transport implementation, but the reassembled
message remains subject to the same application limit.

The first frame is the only credential channel. Credentials in the query or
upgrade `Authorization` header are rejected. The raw credential is converted
to its digest at the codec boundary and is never stored in the registry. The
route clears its received ASGI message mapping immediately after decoding,
before Store verification begins, on both success and failure. This shortens
the application-held reference lifetime; it is not a claim that Python can
zero every immutable string allocation in process memory.
Authenticated-service requires the raw query string to be exactly one
canonical non-negative `after_seq` parameter. Conversation lookup and cursor
validation occur only after successful registry insertion and `auth_ok`.

Success is sent only after registry insertion:

```json
{"kind":"auth_ok","protocol_version":"pairing_auth/1","capability_epoch":1}
```

Authentication failures use a flat, allow-listed `auth_failed` frame and then
close with `1008`; oversized frames use `1009`; bounded backend or registry
unavailability uses `1013`. Corrupt post-auth stream state uses `1011`.
Registry close callbacks accept only sendable standard close codes (`1000`,
`1001`, `1002`, `1003`, `1007` through `1014`) or application codes `3000`
through `4999`; reserved wire sentinel codes are rejected before use.

The B3B process harness establishes TCP/TLS, obtains the peer DER certificate,
verifies the SHA-256 pin, and only then transfers the verified
`ssl.SSLSocket` to the WebSocket library. The library is deliberately given a
`ws://` URI to prevent a second TLS wrap, but the helper rejects any transferred
object that is not an `ssl.SSLSocket`. Proxy discovery, compression, caller
headers, automatic retry, repeated connect, and repeated auth frames are
disabled. A wrong pin therefore produces zero HTTP Upgrade attempts, zero auth
frames, and zero credential Store writes.

### 9.2 Connection registry and immediate revoke

Hub maintains `device_id → set(active WebSocket connection leases)`.

The app-scoped registry is bounded to 16 concurrent handshakes, 32 total
authenticated connections, and 4 connections per device. It uses exactly 32
fixed lock stripes rather than an unbounded device-id lock map. A lease stores
only device id, authenticated epoch, a close handle, and a closure signal.

Authentication and registry insertion share the same device lock stripe used
by the B3C credential transition. Protected REST requests also register a
bounded operation lease under that stripe. A transition prevents new leases,
waits existing REST operations, acquires every live connection send gate,
commits, then detaches connections while still holding the stripe and closes
sockets after releasing it. A later authentication therefore rechecks committed
credential state and cannot survive a revoke/epoch transition race.

Once a transition operation starts, the registry owns the transition,
detach, authorization signal, and bounded close sequence. Caller cancellation
is deferred until that owned operation settles, so a durable commit cannot be
split from registry detachment. Each handshake or lease owns one single-flight
close task; concurrent transition/shutdown callers reuse it instead of
calling socket close concurrently. A timed-out lease remains in the registry's
closing quarantine and continues to consume capacity until the route
unregisters it; the registry
must never report zero while such a connection may still be alive. Route
cleanup order is subscription/queue/tasks first, then registry lease, then
closure signal.

The transition callback has a completion-certain contract: it must not raise
while a durable mutation may still commit later. A started
`PairingStoreExecutor.run` worker can continue after its caller receives a
timeout, so B3C uses `run_completion_certain`: capacity may reject before
admission, but an admitted mutation is awaited to its final result even when
the caller is cancelled. Adding another coroutine timeout is not an accepted
mutation boundary.

On `revoke` or `capability_epoch` change:

1. Transaction commits new DB status/epoch first.
2. Close **all** registry connections for that `device_id`.
3. Clear subscriptions; drop any queued business events for those sockets.
4. Subsequent REST and reconnect → permanent `auth_revoked` or `capability_epoch_stale` (no auto-retry).

Tests **must** cover revoke while connected, not only fresh handshake failure.

## 10. Hub restart and SQLite session semantics

- `pairing_session` **may** persist in SQLite for audit and atomic transitions.
- Each Hub start generates new `boot_id`.
- Non-terminal sessions store `boot_id`.
- On startup, atomically mark all non-terminal sessions with other `boot_id` as `ABORTED_HUB_RESTART`.
- Old OTT digests for aborted sessions are permanently unusable.
- TTL uses **server wall clock** (`created_at` / `expires_at_server`).
- QR `expires_at` is display-only.
- In-process waits may use monotonic clocks; **cross-restart must not** trust monotonic values.
- `ACTIVE` device credentials survive restart; PENDING past TTL are purged/expired on startup sweep.

## 11. Error codes (locked)

| `error_code` | HTTP | Retry |
|---|---|---|
| `protocol_version_rejected` | 400 | No |
| `pairing_expired` | 410 | No (new QR) |
| `pairing_rejected` | 409 | No |
| `pairing_busy` | 409 | No / user wait |
| `pairing_attempt_conflict` | 409 | No |
| `claim_missing` | 401 | No (client must send Pairing auth) |
| `claim_invalid` | 401 | No |
| `claim_expired` | 401 | No (restart pairing) |
| `short_code_mismatch` | 401 | Limited then abort |
| `auth_invalid` | 401 | No |
| `auth_revoked` | 401 | No |
| `capability_denied` | 403 | No |
| `capability_epoch_stale` | 409 | No auto; refresh grants |
| `policy_violation` | 400 / WS close | No |
| `auth_unavailable` | 503 | Wait for service stability; no tight loop |
| `rate_limited` | 429 | After `Retry-After` |
| `payload_too_large` | 413 | No |
| `transient_network` | transport | Wait stable; one flow |

Error body: `{ "error_code", "message_key" }` only. No OTT, secrets, `Authorization` echoes (`Bearer` or `Pairing`), or full fingerprints.

## 12. Log / UI redaction

Never log: OTT, `claim_secret`, `device_credential_secret`, any `Authorization` header value (`Bearer` or `Pairing`), TLS private keys, full QR JSON.  
Allowed: `pairing_session_id`, `pairing_attempt_id`, `device_id`, `error_code`, truncated fingerprint (first/last 4 hex) in debug.  
UI errors use `message_key` only. Traces must redact Authorization.

## 13. SQLite draft

### `hub_identity`

`hub_id`, `cert_fingerprint`, `listen_mode`, `created_at`, `rotated_at`, `tls_key_ref` (opaque handle/path per B1A choice — not raw key).

### `hub_runtime`

`boot_id`, `started_at`.

### `pairing_session`

`pairing_session_id`, `boot_id`, `pairing_token_digest`, `state`, `expires_at_server`, `terminal_reason`, `created_at`, `consumed_at`.

### `pairing_attempt`

`pairing_attempt_id`, `pairing_session_id`, `device_id`, `claim_secret_digest`, `device_credential_digest`, `client_nonce`, `requested_capabilities_json`, `requested_capabilities_digest`, `short_verification_code`, `client_confirmed_at`, `hub_confirmed_at`, `pending_expires_at`, `hello_payload_hash`, `created_at`.

### `device_credential`

`device_id`, `hub_id`, `credential_digest`, `status` (`PENDING|ACTIVE|REVOKED|EXPIRED`), `requested_capabilities_json`, `granted_capabilities_json`, `capability_epoch`, `display_name`, `platform`, `paired_at`, `revoked_at`, `last_auth_at`.

### `auth_audit`

Redacted events only.

## 14. Secure storage boundaries

### Android

- `device_credential_secret`, `claim_secret` (until pairing done): Keystore-backed.
- Pin fingerprint: app private storage.
- Prefer excluding secrets from backups.

### Windows Hub TLS private key

**Not locked to Credential Manager in this revision.**  
T02D-B1A must compare (mature libraries only):

1. Windows Certificate Store / CNG  
2. DPAPI-protected file under LocalAppData + current-user ACL  
3. Credential Manager **if and only if** Python/Uvicorn can load non-interactively  

Requirements for the chosen option: key never in repo/SQLite/logs; non-interactive start; backup/rotate/delete; least privilege; documented fallback.  
B1B implements storage only after B1A locks the choice.

### Windows client device secret (if any)

OS secure storage analogous to Android; out of B1A scope beyond noting parity.

## 15. LAN listen mode

```text
disabled -> loopback-only -> (authorized gate) pairing-only -> authenticated-service
```

Default remains loopback-only. Never bind `0.0.0.0`/LAN by default. No automatic firewall changes (B4 docs only).

B4 locks the implementation contract as follows:

- `disabled` and `loopback-only` accept literal `127.0.0.1` only;
- `pairing-only` and `authenticated-service` require a concrete RFC1918 IPv4
  literal plus explicit per-launch operator acknowledgement;
- pairing-only exposes health and pairing routes only; business, WebSocket,
  operator, and documentation routes are absent;
- authenticated-service retains mandatory B3 device authentication;
- operator transition routes remain loopback-only in every mode;
- policy rejection occurs before identity, database, or socket work;
- firewall configuration is a manual, reviewed operator action only.

B4 does not authorize a real LAN bind by itself. The supervised Huawei trial
and its redacted network evidence belong to C2.

## 16. Reconnect

`OFFLINE -> WAIT_STABLE -> CATCH_UP -> ONLINE` after successful auth.  
Permanent auth errors: no auto-retry. One reconnect flow per device. Reduce meaningless retries.

## 17. Compatibility

- Unknown `protocol_version` → reject.
- Unauthenticated LAN compatibility: **none**.
- Existing loopback `SHARED_SESSION_TRANSPORT_V1` must not be LAN-exposed as-is.

## 18. Out of scope

Public relay, PAKE/Noise E2EE, BLE, iOS Keychain, generating real certs in this design task, LAN bind implementation.

## 19. B3A authenticated business REST addendum

The authenticated business service uses an explicit mode; it must never infer
authentication from the presence of a PairingStore or silently fall back.

| Business route | Required granted capability |
|---|---|
| `POST /v1/conversations` | `session.sync` |
| `POST /v1/conversations/{conversation_id}/messages` | `session.sync` |
| `GET /v1/conversations/{conversation_id}/events` | `session.sync` |

For message append, the body `actor_device_id` MUST equal the authenticated
header device id. Mismatch is `400 policy_violation` and performs no business
write. All REST paths in the conversation namespace are authenticated before
normal routing so a future endpoint cannot be accidentally exposed.

In the MVP authenticated-service boundary, a paired device may append only a
`user` message. `assistant`, `system`, and `tool` are trusted Hub-internal
roles and MUST return `400 policy_violation` with no write. A future remote
Agent role requires a separately reviewed capability; `session.sync` alone
must not grant it.

Malformed/unknown/wrong-secret/PENDING/EXPIRED credentials are externally
collapsed to `401 auth_invalid`. Bounded authentication executor timeout,
saturation, shutdown, or persistence failure is `503 auth_unavailable`; the
client must not tight-loop retry. `auth_unavailable` bodies follow the same
flat redacted error shape.

B3B integrates the reviewed first-frame core into the authenticated route and
proves it through a pin-first real-process loopback WSS harness.
The route now performs bounded handshake admission, possession-first
verification, registry insertion, and `auth_ok` before conversation lookup,
subscription, replay, or event delivery. It observes authorization-change as
a priority terminal signal across conversation lookup, not-found/cursor
handling, subscription registration, replay, and live delivery. If the
registry already owns the authorization close, the route suppresses duplicate
business error frames and closes. It cleans subscription state before
unregistering the device lease. B3B-B2 real pin-first WSS process evidence
is complete with restart replay convergence. B3C adds feature-gated operator
credential endpoints, exact epoch CAS, completion-certain mutations, bounded
REST operation leases, and WSS send gates. Real-process evidence covers two
live sockets on epoch change, connected revoke, stale/revoked permanent errors,
restart persistence, and zero post-transition business frames.

## 20. B3D Dart/Android secure-client addendum

B3D implements strict Dart QR/response/error codecs, the three normative
Human32 vectors, OS-CSPRNG attempt and secret semantics, independently verified
short codes, idempotent hello, claim-authenticated confirm/status recovery, and
a single caller-driven `WAIT_STABLE` retry that reuses the same attempt and
Keystore material.

Android stores pending and active records with a non-exportable Keystore
AES-256-GCM key. App-private Preferences contain only ciphertext and IV;
backups are disabled. Pending encrypted state includes the claim and the pinned
Hub context required to resume confirmation after process restart. Active state
removes the claim and retains the device credential, Hub id, HTTPS endpoint,
certificate fingerprint, granted capabilities, and exact epoch. Unknown,
partial, corrupt, or non-canonical records fail closed.

Dart HTTPS/WSS creates an empty-root `SecurityContext`, uses direct networking,
and admits the self-signed Hub certificate only when SHA-256 over peer DER
matches the expected lowercase pin in constant time. A pin rejection is a
permanent `tls_pin_mismatch`, never a transient reconnect. WSS sends the raw
device credential only in the first application auth frame after pin success;
REST uses the locked Bearer/device-id/epoch headers.

The B3D real-process contract remains loopback-only. The installed Huawei APK
and cold-start evidence do not claim phone-to-PC pairing. Non-loopback listen,
firewall guidance, mDNS, on-device pairing UI/vault invocation, and real Huawei
authenticated convergence remain B4/C1-C4 gates.

## 21. C1 trusted-local pairing UI addendum

C1 adds a loopback-only operator surface for the Windows UI. It does not weaken
the private-LAN route projection defined by B4: every `/v1/operator/*` route is
still rejected at app construction time for non-loopback transport scopes.

| Method | Loopback-only route | Purpose |
|---|---|---|
| `POST` | `/v1/operator/pairing/sessions` | Create a five-minute session from an OTT SHA-256 digest |
| `GET` | `/v1/operator/pairing/sessions/{session_id}` | Return redacted state, short code and requested/granted capabilities |
| `POST` | `/v1/operator/pairing/sessions/{session_id}/attempts/{attempt_id}/confirm` | Record PC-local confirmation and a canonical subset of requested capabilities |
| `POST` | `/v1/operator/pairing/sessions/{session_id}/cancel` | Abort the local session |

All four routes require the per-process `DataSteward-Operator` bearer and the
locked protocol header. The bearer is supplied to the Windows UI for the
current process only; it is neither returned by the API nor placed in the QR,
SQLite, settings, screenshots, or logs. The create body contains only the OTT
digest. The QR is the sole in-memory carrier of the raw OTT and is cleared when
a client attempt appears, the session completes, fails, or is cancelled.

The phone scans or pastes the strict QR descriptor, pins the TLS certificate
before sending HTTP, generates client secrets in the Android Keystore-backed
vault, and independently recomputes Human32. Both screens show the same eight
characters. The Windows user may reduce requested capabilities but cannot add
one. Activation still requires both confirmations in either order.

C1 intentionally performs no automatic polling: refresh and confirm are
explicit user actions. A transient phone-side failure retains exactly the same
in-memory attempt and offers one caller-driven retry only after the network is
stable. Process restart restores a completed pending hello or active Keystore
record without showing credential material. Real Huawei-to-PC private-LAN
transport, firewall and discovery evidence remain C2 work.
