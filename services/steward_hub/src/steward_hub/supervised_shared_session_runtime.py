"""C3 supervised loopback UI plus authenticated private-LAN session runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from .api import create_app
from .agent_supervisor import AgentPlannerSupervisor, find_repo_root
from .action_projection import ActionProjectionService
from .android_ocr_store import AndroidOcrStore
from .artifact_export import (
    ArtifactExportService,
    ArtifactExportStore,
    KnowledgeArtifactCoordinator,
)
from .archive_memory import ArchiveMemoryService
from .autonomy_job import AutonomyJobStore
from .catalog_store import CatalogStore
from .cluster_organization import ClusterOrganizationService
from .content_api import ContentInsightCoordinator
from .content_understanding import (
    ContentUnderstandingService,
    ContentUnderstandingStore,
)
from .device_auth import AUTH_MODE_REQUIRED
from .device_connection_registry import DeviceConnectionRegistry
from .https_runtime import build_https_config, validate_port
from .knowledge_pack import KnowledgeContextBuilder
from .listen_policy import (
    LISTEN_AUTHENTICATED_SERVICE,
    LOOPBACK_HOST,
    resolve_listen_policy,
)
from .models import PROTOCOL_VERSION
from .pairing_store import PairingStore
from .pairing_store_executor import PairingStoreExecutor
from .pc_file_scope import PcFileScopeService
from .pc_file_scope_persistence import permanent_pc_file_scope_persistence
from .proactive_suggestion import (
    ProactiveSuggestionService,
    ProactiveSuggestionStore,
)
from .readonly_tool_bridge import ReadonlyToolBridge, ReadonlyToolBridgeServer
from .pc_file_organizer_journal import permanent_organizer_journal_store
from .store import EventStore
from .subscriptions import SubscriptionManager
from .supervised_pairing_runtime import (
    READY_MAX_BYTES,
    _serve_one,
    _start_control_reader,
)
from .tls_identity import build_ssl_context_factory, load_tls_identity, redacted_error
from .windows_dns_sd import DnsSdAdvertisementError, WindowsDnsSdAdvertiser

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_PRE_LISTEN = 2


async def _serve_dual(
    *,
    local_server: uvicorn.Server,
    lan_server: uvicorn.Server,
    ready_payload: dict[str, object],
    advertiser: WindowsDnsSdAdvertiser | None = None,
) -> bool:
    local_task = asyncio.create_task(_serve_one(local_server))
    lan_task = asyncio.create_task(_serve_one(lan_server))
    try:
        while not (local_server.started and lan_server.started):
            if local_task.done() or lan_task.done():
                return False
            await asyncio.sleep(0.01)
        discovery_available = False
        if advertiser is not None:
            try:
                discovery_available = advertiser.start()
            except Exception:  # noqa: BLE001 - discovery is an optional capability
                discovery_available = False
        ready_payload["lan_discovery_available"] = discovery_available
        encoded = json.dumps(ready_payload, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > READY_MAX_BYTES:
            raise RuntimeError("readiness_too_large")
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()
        stdin_task = _start_control_reader(asyncio.get_running_loop())
        done, _ = await asyncio.wait(
            {local_task, lan_task, stdin_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stdin_task in done:
            line = stdin_task.result()
            if line not in {"shutdown\n", "shutdown\r\n", ""}:
                raise RuntimeError("control_input_invalid")
        return local_task not in done and lan_task not in done
    finally:
        local_server.should_exit = True
        lan_server.should_exit = True
        if advertiser is not None:
            try:
                advertiser.close()
            except DnsSdAdvertisementError:
                pass
        await asyncio.gather(local_task, lan_task, return_exceptions=True)


def serve_supervised_shared_session(
    *,
    database_path: str | Path,
    identity_root: str | Path,
    private_host: str,
    private_port: int,
    local_port: int,
    private_lan_authorized: bool,
    operator_token_digest: str,
    agent_provider: str | None = None,
    agent_model: str | None = None,
) -> int:
    pairing: PairingStore | None = None
    events: EventStore | None = None
    executor: PairingStoreExecutor | None = None
    archive_memory: ArchiveMemoryService | None = None
    agent_supervisor: AgentPlannerSupervisor | None = None
    action_projection: ActionProjectionService | None = None
    catalog: CatalogStore | None = None
    content_store: ContentUnderstandingStore | None = None
    android_ocr_store: AndroidOcrStore | None = None
    artifact_export_store: ArtifactExportStore | None = None
    autonomy_store: AutonomyJobStore | None = None
    proactive_store: ProactiveSuggestionStore | None = None
    tool_bridge_server: ReadonlyToolBridgeServer | None = None
    dns_sd_advertiser: WindowsDnsSdAdvertiser | None = None
    try:
        policy = resolve_listen_policy(
            mode=LISTEN_AUTHENTICATED_SERVICE,
            host=private_host,
            private_lan_authorized=private_lan_authorized,
        )
        validate_port(private_port)
        validate_port(local_port)
        if private_port == local_port:
            raise ValueError("listener_ports_must_differ")
        identity = load_tls_identity(Path(identity_root))
        pairing = PairingStore(database_path, auto_start_runtime=False)
        pairing.initialize_hub_identity(
            hub_id=identity.manifest.hub_id,
            cert_fingerprint=identity.cert_fingerprint_sha256,
            tls_storage_kind="dpapi_encrypted_pkcs8",
            tls_key_ref_id="identity-root",
        )
        pairing.start_runtime()
        events = EventStore(database_path)
        catalog = CatalogStore(database_path)
        executor = PairingStoreExecutor()
        subscriptions = SubscriptionManager()
        registry = DeviceConnectionRegistry()
        file_scope = PcFileScopeService(
            permanent_pc_file_scope_persistence(),
            permanent_organizer_journal_store(),
        )
        archive_memory = ArchiveMemoryService(database_path, file_scope)
        action_projection = ActionProjectionService(database_path)
        content_store = ContentUnderstandingStore(database_path)
        android_ocr_store = AndroidOcrStore(database_path, catalog=catalog)
        autonomy_store = AutonomyJobStore(database_path)
        content_service = ContentUnderstandingService(
            store=content_store,
            catalog=catalog,
            file_scope=file_scope,
            windows_device_id=identity.manifest.hub_id,
            android_ocr_store=android_ocr_store,
        )
        tool_bridge = ReadonlyToolBridge(
            catalog=catalog,
            content=content_service,
            memory=archive_memory,
        )
        tool_bridge_server = ReadonlyToolBridgeServer(tool_bridge)
        tool_bridge_server.start()
        agent_environment = _agent_environment(
            provider=agent_provider,
            model=agent_model,
        )
        agent_supervisor = AgentPlannerSupervisor(
            repo_root=find_repo_root(),
            environment=agent_environment,
            tool_bridge=tool_bridge,
            tool_bridge_endpoint=tool_bridge_server.endpoint,
            tool_bridge_token=tool_bridge_server.token,
        )
        planner = agent_supervisor.start_optional()
        content_coordinator = ContentInsightCoordinator(
            content=content_service,
            planner=planner,
            job_store=autonomy_store,
        )
        artifact_export_store = ArtifactExportStore(database_path)
        artifact_export_service = ArtifactExportService(
            store=artifact_export_store,
            file_scope=file_scope,
        )
        knowledge_builder = KnowledgeContextBuilder(
            catalog=catalog,
            content=content_service,
        )
        knowledge_artifact = KnowledgeArtifactCoordinator(
            content_coordinator=content_coordinator,
            builder=knowledge_builder,
            export=artifact_export_service,
        )
        cluster_organization = ClusterOrganizationService(
            catalog=catalog,
            file_scope=file_scope,
            windows_device_id=identity.manifest.hub_id,
        )
        proactive_store = ProactiveSuggestionStore(database_path)
        proactive_suggestions = ProactiveSuggestionService(
            store=proactive_store,
            autonomy=autonomy_store,
            catalog=catalog,
            organization=cluster_organization,
            knowledge=knowledge_builder,
            planner=planner,
        )

        local_app = create_app(
            event_store=events,
            subscription_manager=subscriptions,
            pairing_store=pairing,
            close_pairing_store=False,
            pairing_store_executor=executor,
            device_connection_registry=registry,
            operator_token_digest=operator_token_digest,
            pc_file_scope_service=file_scope,
            archive_memory_service=archive_memory,
            read_only_intent_planner=planner,
            action_projection_service=action_projection,
            catalog_store=catalog,
            cluster_organization_service=cluster_organization,
            content_insight_coordinator=content_coordinator,
            android_ocr_store=android_ocr_store,
            knowledge_artifact_coordinator=knowledge_artifact,
            proactive_suggestion_service=proactive_suggestions,
            pairing_routes_enabled=False,
        )
        lan_app = create_app(
            event_store=events,
            subscription_manager=subscriptions,
            pairing_store=pairing,
            close_pairing_store=False,
            pairing_store_executor=executor,
            device_connection_registry=registry,
            pc_file_scope_service=file_scope,
            archive_memory_service=archive_memory,
            read_only_intent_planner=planner,
            action_projection_service=action_projection,
            catalog_store=catalog,
            cluster_organization_service=cluster_organization,
            content_insight_coordinator=content_coordinator,
            android_ocr_store=android_ocr_store,
            knowledge_artifact_coordinator=knowledge_artifact,
            proactive_suggestion_service=proactive_suggestions,
            business_auth_mode=AUTH_MODE_REQUIRED,
            pairing_routes_enabled=True,
            transport_scope=policy.transport_scope,
        )
        local_server = uvicorn.Server(
            uvicorn.Config(
                local_app,
                host=LOOPBACK_HOST,
                port=local_port,
                workers=1,
                reload=False,
                access_log=False,
                proxy_headers=False,
                log_level="warning",
                server_header=False,
                date_header=False,
            )
        )
        factory, cleanup = build_ssl_context_factory(identity)
        del cleanup
        lan_server = uvicorn.Server(
            build_https_config(
                app=lan_app,
                host=private_host,
                port=private_port,
                identity=identity,
                ssl_context_factory=factory,
                listen_policy=policy,
            )
        )
        try:
            dns_sd_advertiser = WindowsDnsSdAdvertiser(
                hub_id=identity.manifest.hub_id,
                cert_fingerprint=identity.cert_fingerprint_sha256,
                private_host=private_host,
                port=private_port,
            )
        except DnsSdAdvertisementError:
            dns_sd_advertiser = None
        servers = (local_server, lan_server)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(
                signal.SIGBREAK,
                lambda _s, _f: [setattr(server, "should_exit", True) for server in servers],
            )
        ready = {
            "event": "c3_session_ready",
            "protocol_version": PROTOCOL_VERSION,
            "auth_protocol_version": "pairing_auth/1",
            "local_url": f"http://{LOOPBACK_HOST}:{local_port}",
            "service_url": f"https://{private_host}:{private_port}",
            "hub_id": identity.manifest.hub_id,
            "cert_fingerprint": identity.cert_fingerprint_sha256,
            "transport_scope": policy.transport_scope,
            "agent_mode": agent_supervisor.status.mode,
        }
        clean = asyncio.run(
            _serve_dual(
                local_server=local_server,
                lan_server=lan_server,
                ready_payload=ready,
                advertiser=dns_sd_advertiser,
            )
        )
        return EXIT_OK if clean else EXIT_RUNTIME
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(redacted_error("C3_RUNTIME", exc) + "\n")
        return EXIT_PRE_LISTEN
    finally:
        if dns_sd_advertiser is not None:
            try:
                dns_sd_advertiser.close()
            except DnsSdAdvertisementError:
                pass
        if agent_supervisor is not None:
            try:
                agent_supervisor.close()
            except Exception:  # noqa: BLE001
                pass
        if action_projection is not None:
            try:
                action_projection.close()
            except Exception:  # noqa: BLE001
                pass
        if archive_memory is not None:
            try:
                archive_memory.close()
            except Exception:  # noqa: BLE001
                pass
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_queued=True)
            except Exception:  # noqa: BLE001
                pass
        if events is not None:
            try:
                events.close()
            except Exception:  # noqa: BLE001
                pass
        if tool_bridge_server is not None:
            try:
                tool_bridge_server.close()
            except Exception:  # noqa: BLE001
                pass
        if catalog is not None:
            try:
                catalog.close()
            except Exception:  # noqa: BLE001
                pass
        if content_store is not None:
            try:
                content_store.close()
            except Exception:  # noqa: BLE001
                pass
        if android_ocr_store is not None:
            try:
                android_ocr_store.close()
            except Exception:  # noqa: BLE001
                pass
        if autonomy_store is not None:
            try:
                autonomy_store.close()
            except Exception:  # noqa: BLE001
                pass
        if artifact_export_store is not None:
            try:
                artifact_export_store.close()
            except Exception:  # noqa: BLE001
                pass
        if proactive_store is not None:
            try:
                proactive_store.close()
            except Exception:  # noqa: BLE001
                pass
        if pairing is not None:
            try:
                pairing.close()
            except Exception:  # noqa: BLE001
                pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Supervised C3 shared-session runtime")
    parser.add_argument("--database", required=True)
    parser.add_argument("--identity-root", required=True)
    parser.add_argument("--private-host", required=True)
    parser.add_argument("--private-port", type=int, required=True)
    parser.add_argument("--local-port", type=int, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--operator-token-digest", required=True)
    parser.add_argument("--agent-provider")
    parser.add_argument("--agent-model")
    parser.add_argument("--acknowledge-private-lan-risk", action="store_true")
    args = parser.parse_args(argv)
    if args.workers != 1:
        raise SystemExit("exactly one worker is required")
    return serve_supervised_shared_session(
        database_path=args.database,
        identity_root=args.identity_root,
        private_host=args.private_host,
        private_port=args.private_port,
        local_port=args.local_port,
        private_lan_authorized=args.acknowledge_private_lan_risk,
        operator_token_digest=args.operator_token_digest,
        agent_provider=args.agent_provider,
        agent_model=args.agent_model,
    )


def _agent_environment(
    *, provider: str | None, model: str | None
) -> dict[str, str] | None:
    if (provider is None) != (model is None):
        raise ValueError("agent_provider_model_pair_required")
    if provider is None:
        return None
    environment = dict(os.environ)
    environment["DATA_STEWARD_HERMES_PROVIDER"] = provider
    environment["DATA_STEWARD_HERMES_MODEL"] = model
    return environment


if __name__ == "__main__":
    raise SystemExit(main())
