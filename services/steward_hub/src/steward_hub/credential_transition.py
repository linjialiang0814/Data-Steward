"""Completion-certain credential transitions coordinated with live sockets."""

from __future__ import annotations

from collections.abc import Sequence

from .device_connection_registry import (
    AuthorizationTransition,
    DeviceConnectionRegistry,
    TransitionResult,
)
from .pairing_models import (
    ConfirmResult,
    CredentialTransitionResult,
    DeviceCredentialView,
    HubIdentity,
    OperatorPairingView,
    PairingSessionView,
)
from .pairing_store import PairingStore
from .pairing_store_executor import PairingStoreExecutor


class DeviceAuthorizationService:
    """Trusted operator service; never accepts a device credential."""

    def __init__(
        self,
        *,
        pairing_store: PairingStore,
        store_executor: PairingStoreExecutor,
        registry: DeviceConnectionRegistry,
    ) -> None:
        if not isinstance(pairing_store, PairingStore):
            raise ValueError("pairing_store is invalid")
        if not isinstance(store_executor, PairingStoreExecutor):
            raise ValueError("store_executor is invalid")
        if not isinstance(registry, DeviceConnectionRegistry):
            raise ValueError("registry is invalid")
        self._pairing_store = pairing_store
        self._store_executor = store_executor
        self._registry = registry

    async def get(self, *, device_id: str) -> DeviceCredentialView:
        return await self._store_executor.run_completion_certain(
            self._pairing_store.get_device_credential,
            device_id,
        )

    async def list(self, *, limit: int = 32) -> list[DeviceCredentialView]:
        return await self._store_executor.run_completion_certain(
            self._pairing_store.list_device_credentials,
            limit=limit,
        )

    async def revoke(
        self,
        *,
        device_id: str,
        expected_capability_epoch: int,
    ) -> TransitionResult[CredentialTransitionResult]:
        async def transition() -> AuthorizationTransition[
            CredentialTransitionResult
        ]:
            result = await self._store_executor.run_completion_certain(
                self._pairing_store.revoke_device_credential,
                device_id,
                expected_capability_epoch=expected_capability_epoch,
            )
            return AuthorizationTransition(
                value=result,
                authorization_changed=result.changed,
            )

        return await self._registry.transition_and_close(
            device_id=device_id,
            transition=transition,
            close_code=1008,
            close_reason="device authorization changed",
        )

    async def update_capabilities(
        self,
        *,
        device_id: str,
        expected_capability_epoch: int,
        granted_capabilities: Sequence[str],
    ) -> TransitionResult[CredentialTransitionResult]:
        async def transition() -> AuthorizationTransition[
            CredentialTransitionResult
        ]:
            result = await self._store_executor.run_completion_certain(
                self._pairing_store.update_device_capabilities,
                device_id,
                expected_capability_epoch=expected_capability_epoch,
                granted_capabilities=granted_capabilities,
            )
            return AuthorizationTransition(
                value=result,
                authorization_changed=result.changed,
            )

        return await self._registry.transition_and_close(
            device_id=device_id,
            transition=transition,
            close_code=1008,
            close_reason="device authorization changed",
        )


class PairingOperatorService:
    """Trusted loopback session control; accepts OTT digest only."""

    def __init__(
        self,
        *,
        pairing_store: PairingStore,
        store_executor: PairingStoreExecutor,
    ) -> None:
        if not isinstance(pairing_store, PairingStore):
            raise ValueError("pairing_store is invalid")
        if not isinstance(store_executor, PairingStoreExecutor):
            raise ValueError("store_executor is invalid")
        self._pairing_store = pairing_store
        self._store_executor = store_executor

    async def identity(self) -> HubIdentity:
        return await self._store_executor.run_completion_certain(
            self._pairing_store.get_hub_identity
        )

    async def create(
        self,
        *,
        pairing_token_digest: str,
        ttl_seconds: int,
    ) -> tuple[HubIdentity, PairingSessionView]:
        identity = await self.identity()
        session = await self._store_executor.run_completion_certain(
            self._pairing_store.create_pairing_session,
            pairing_token_digest=pairing_token_digest,
            ttl_seconds=ttl_seconds,
        )
        return identity, session

    async def status(self, *, pairing_session_id: str) -> OperatorPairingView:
        return await self._store_executor.run_completion_certain(
            self._pairing_store.get_operator_pairing_view,
            pairing_session_id=pairing_session_id,
        )

    async def confirm(
        self,
        *,
        pairing_session_id: str,
        pairing_attempt_id: str,
        granted_capabilities: Sequence[str],
    ) -> ConfirmResult:
        return await self._store_executor.run_completion_certain(
            self._pairing_store.record_hub_confirmation,
            pairing_session_id=pairing_session_id,
            pairing_attempt_id=pairing_attempt_id,
            granted_capabilities=granted_capabilities,
        )

    async def cancel(self, *, pairing_session_id: str) -> PairingSessionView:
        return await self._store_executor.run_completion_certain(
            self._pairing_store.abort_pairing_session,
            pairing_session_id=pairing_session_id,
            reason="cancel",
        )
