# Data Steward Hermes Adapter Boundary

This directory contains repository-safe manifests and gate tooling for the
replaceable Hermes Agent adapter. The installed runtime lives only in the
ignored `.venv/`; provider credentials and the effective user profile never
belong in this repository.

Hermes may propose plans and call explicitly allow-listed Data Steward MCP
tools. It never owns device identity, directory authorization, policy,
approval, file mutation, receipts, undo, audit or long-term memory.

S3-A is a framework gate only. Intelligent archive execution starts only after
an accepted gate and a separate S3-B plan.

## Locked S3-A runtime

- `hermes-agent[mcp]==0.18.2`
- `aiohttp==3.14.1` for the loopback API Server only; the broad `messaging`
  extra is intentionally not installed
- 81 exact installed packages in `requirements.lock`
- exact API profile in `restricted-profile.template.yaml`

The committed profile selects only the `data_steward` MCP server for the API
Server. Its four tools are metadata/search/proposal/preference-read contracts;
the S3-A gate implementation is synthetic and cannot touch real user files.

Validation uses an ignored isolated home and an owned foreground process:

```powershell
agents/hermes_runtime/.venv/Scripts/python.exe `
  agents/hermes_runtime/tool/validate_restricted_profile.py `
  agents/hermes_runtime/restricted-profile.template.yaml
```

`probe_hermes_gateway.py` is the executable process gate. It generates a
runtime-only bearer, chooses a random loopback port, strips provider secrets
from the child environment, verifies health/capabilities/toolsets through the
product adapter, and stops only the process tree it created. It must be run
with explicit OS-process permission on Windows.

## S3-B provider checkpoint

S3-B adds a strict read-only plan client, but live inference remains opt-in.
Supply the provider and model through the current process environment only;
never put an API key in this directory or a command-line argument. Run
`tool/validate_provider_environment.py` to obtain a redacted readiness result.
Until the live provider gate passes, the S2 deterministic query parser remains
the active Showcase fallback.

Volcengine Ark is supported as the locked named custom provider
`custom:volcengine`. Its endpoint is fixed in the gate to
`https://ark.cn-beijing.volces.com/api/v3`, its transport is fixed to OpenAI
Chat Completions, and its only credential source is the process variable
`ARK_API_KEY`. The gate ignores Base URL override variables and never writes
the key into Hermes YAML. Use an Ark API key rather than a Volcengine cloud
Access Key/Secret Key pair.

`tool/probe_readonly_planner_provider.py` is the live acceptance gate. It uses
three synthetic messages, passes only the selected provider credential to an
owned Hermes child process, exposes one random loopback listener, and removes
its isolated run home on exit. Its redacted JSON is the only output that should
be copied into project evidence.

The accepted S3-B Volcengine run completed three live requests with zero
enabled built-in toolsets, one IPv4 loopback listener, both supported intents
validated and the unsupported intent rejected. The committed evidence contains
only provider/model/plan hashes and bounded metrics; it contains no API key,
model ID, prompt, response body or real file metadata.
