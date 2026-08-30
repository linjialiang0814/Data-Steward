# Trusted LAN Discovery v1

## Identity versus locator

The durable identity tuple is `(hub_id, cert_fingerprint, device_id, device_credential, capability_epoch)`. An IPv4 address and port are mutable locators and are never identity evidence.

## DNS-SD advertisement

- The Windows launcher selects an address only when exactly one preferred, non-skip-source RFC1918 IPv4 belongs to an active Private network profile. Ambiguity is terminal and a manual private IPv4 override remains available.
- Service type: `_datasteward._tcp.local`.
- Instance name: `DataSteward-<12 lowercase hex derived from hub_id>`.
- SRV address/port: the currently gated private IPv4 HTTPS listener.
- TXT allow-list: `hub_id`, `protocol_version`, `cert_fingerprint`, `pairing_available`.
- Forbidden: pairing token/OTT, claim secret, device credential or digest, Authorization, short code, operator token, database/path/URI, user/device serial and source content.

The advertisement is public LAN metadata and is not authenticated. It is only a candidate locator.

## Client migration

1. Load the existing active credential.
2. Try its stored endpoint once.
3. On transport or `auth_unavailable` failure only, wait for network stability and run one bounded DNS-SD discovery.
4. Keep only a unique private IPv4 candidate whose TXT `hub_id`, `protocol_version`, and `cert_fingerprint` exactly match the credential.
5. Connect to the candidate with the existing certificate pin and authenticate `/v1/device/self` using the existing device credential.
6. Require matching `device_id` and `hub_id`; then atomically update endpoint and authorization epoch/capabilities in the platform vault.
7. Stop discovery on success, failure, timeout or lifecycle cancellation. Never automatically retry the same failure.

`auth_revoked`, `auth_invalid`, pin mismatch, protocol mismatch and ambiguous candidates are permanent for the current attempt and do not update storage.

## Privacy and logging

Product UI may display only a friendly state such as “已找到已配对电脑的新地址”. Logs and evidence store stage/error codes and counts only. They do not store discovered addresses, full fingerprints, Hub/device IDs, credentials or request headers.
