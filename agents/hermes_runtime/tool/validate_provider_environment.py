"""Redacted human gate for the S3-B Hermes inference provider.

The tool never writes configuration and never prints a credential or model id.
Credentials must be supplied through the current process environment, not CLI.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderSpec:
    credential_env: str
    hermes_provider: str
    base_url: str | None = None


VOLCENGINE_ARK_BASE_URL = "https://ark.cn-beijing.volces.com/api/v3"
PROVIDER_SPECS = {
    "openrouter": ProviderSpec("OPENROUTER_API_KEY", "openrouter"),
    "openai": ProviderSpec("OPENAI_API_KEY", "openai"),
    "deepseek": ProviderSpec("DEEPSEEK_API_KEY", "deepseek"),
    "dashscope": ProviderSpec("DASHSCOPE_API_KEY", "dashscope"),
    "volcengine": ProviderSpec(
        "ARK_API_KEY",
        "custom:volcengine",
        VOLCENGINE_ARK_BASE_URL,
    ),
}
PROVIDERS = {
    name: spec.credential_env for name, spec in PROVIDER_SPECS.items()
}
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")


def main() -> int:
    provider = os.environ.get("DATA_STEWARD_HERMES_PROVIDER", "").strip().lower()
    model = os.environ.get("DATA_STEWARD_HERMES_MODEL", "").strip()
    provider_spec = PROVIDER_SPECS.get(provider)
    if provider_spec is None:
        print(json.dumps({
            "allowed_providers": sorted(PROVIDER_SPECS),
            "credential_echoed": False,
            "status": "PROVIDER_REQUIRED",
        }, separators=(",", ":"), sort_keys=True))
        return 2
    key_env = provider_spec.credential_env
    secret = os.environ.get(key_env, "")
    if (
        not 16 <= len(secret) <= 512
        or any(ord(char) < 33 or ord(char) > 126 for char in secret)
        or not _MODEL_RE.fullmatch(model)
    ):
        print(json.dumps({
            "credential_echoed": False,
            "credential_source": key_env,
            "provider": provider,
            "status": "PROVIDER_REQUIRED",
        }, separators=(",", ":"), sort_keys=True))
        return 2
    print(json.dumps({
        "credential_echoed": False,
        "credential_source": key_env,
        "endpoint_locked": provider_spec.base_url is not None,
        "model_sha256": hashlib.sha256(model.encode("utf-8")).hexdigest(),
        "provider": provider,
        "status": "READY_FOR_LIVE_PROVIDER_GATE",
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
