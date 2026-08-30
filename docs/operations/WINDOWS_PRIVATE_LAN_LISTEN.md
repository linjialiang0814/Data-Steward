# Windows private-LAN listener operator guide

> B4 boundary: manual operator procedure only. Data Steward does not create,
> edit, enable, disable, or delete Windows Firewall rules.

## When this guide may be used

Use it only for a supervised PC-and-phone trial on a trusted private network,
after the B4 checkpoint. Do not use a public/campus/guest network whose peers
are not controlled. Confirm Windows reports the active network profile as
**Private**, and disconnect VPN/proxy software that changes local routing.

The first trial must use `pairing-only`. Change to `authenticated-service`
only after the phone is paired, its granted capability is reviewed, and the
pairing-only process has stopped. Never use the legacy unauthenticated
`steward_hub.server` process for a LAN trial.

## Preflight checklist

1. Record the PC adapter's concrete RFC1918 IPv4 address. Accepted ranges are
   `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` only.
2. Confirm the address belongs to the intended active adapter. Do not enter a
   hostname, `localhost`, `0.0.0.0`, IPv6 address, public address, or hotspot
   address that is not part of this trial.
3. Choose one high, unused TCP port and record it in the trial notes. Do not
   create a broad port range.
4. Confirm the permanent TLS identity is healthy and the expected certificate
   fingerprint is available through the approved pairing UI/evidence flow.
5. Confirm no previous Data Steward Hub process is running.

## Manual Windows Security UI boundary

If Windows blocks the supervised trial, an administrator may use **Windows
Security > Firewall & network protection > Advanced settings > Inbound Rules**
to create one temporary inbound rule with all of these constraints:

- TCP only and the single selected local port only;
- Private profile only; Public and Domain profiles remain unchecked;
- remote address scope limited to Local subnet (or the phone's single private
  address when stable);
- an unmistakable temporary name containing `Data Steward supervised trial`;
- no edge traversal, no broad application family, and no all-port rule.

Do not accept a generic runtime popup that enables both Private and Public
networks. Do not disable Windows Firewall. Do not add an outbound allow rule.
The repository intentionally contains no firewall mutation script or
copy-paste mutation command.

## Start sequence

1. Start `pairing-only` with the concrete private IPv4, one port, one worker,
   and the explicit `--acknowledge-private-lan-risk` flag.
2. Verify the Hub reports `private_lan_pairing_only` and that conversation
   REST/WS plus operator routes are absent.
3. Complete short-code confirmation on both devices. A mismatch, timeout, pin
   error, or protocol error ends the attempt; do not loop retries while the
   network is unstable.
4. Stop the pairing-only process.
5. If the trial requires shared-session traffic, start a new
   `authenticated-service` process using the same concrete address/port and
   explicit acknowledgement. Unauthenticated REST and WS must fail closed;
   operator routes remain loopback-only and are not mounted on this listener.

The reviewed product entry point is `python -m steward_hub.https_runtime`.
Its required listener arguments are `--host <PRIVATE_IPV4> --port <PORT>
--workers 1 --listen-mode pairing-only --acknowledge-private-lan-risk` for the
first trial. Replace only the mode with `authenticated-service` after pairing.
Database and identity paths must come from the approved Hub bootstrap; do not
put credentials, OTT, claim material, or certificate passwords in arguments or
environment variables.

## Rollback and evidence

1. Stop the exact Hub PID and verify the port is no longer listening.
2. In Windows Firewall Advanced settings, disable and then delete only the
   temporary rule whose name and constraints match the trial record.
3. Confirm Public/Domain profiles and unrelated rules were never changed.
4. Preserve only redacted evidence: mode, port class (not full user path),
   device model/API, truncated fingerprint, result, process exit, and absence
   of fatal/ANR. Never record OTT, claim, credential, full URI, serial, SID,
   user path, or full local network inventory.

The permanent TLS identity and paired credential are separate resources. A
Git rollback does not remove them. Any credential revoke or identity deletion
requires its own reviewed operation.
