from __future__ import annotations

import asyncio
import unittest

from steward_hub.device_auth import AuthenticatedDevice, DeviceAuthError
from steward_hub.device_connection_registry import (
    LOCK_STRIPE_COUNT,
    DeviceConnectionRegistry,
    DeviceConnectionRegistryCapacityError,
    DeviceConnectionRegistryCloseTimeout,
    DeviceConnectionRegistryClosedError,
    DeviceConnectionRegistryPolicyError,
)

DEVICE_A = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEVICE_B = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


def _device(device_id: str, epoch: int = 1) -> AuthenticatedDevice:
    return AuthenticatedDevice(
        device_id=device_id,
        hub_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
        capability_epoch=epoch,
        granted_capabilities=("session.sync",),
        display_name=None,
        platform="android",
    )


async def _verify(device_id: str, epoch: int = 1) -> AuthenticatedDevice:
    return _device(device_id, epoch)


class DeviceConnectionRegistryTest(unittest.IsolatedAsyncioTestCase):
    async def test_defaults_are_bounded_and_stripes_are_fixed(self) -> None:
        registry = DeviceConnectionRegistry()
        snapshot = await registry.snapshot()
        self.assertTrue(snapshot.accepting)
        self.assertEqual(0, snapshot.handshake_count)
        self.assertEqual(0, snapshot.connection_count)
        self.assertEqual(0, snapshot.closing_connection_count)
        self.assertEqual(LOCK_STRIPE_COUNT, snapshot.stripe_count)

        alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

        async def reject_unknown() -> AuthenticatedDevice:
            raise DeviceAuthError("auth_invalid", 401)

        for index in range(64):
            device_id = (
                DEVICE_A[:-2]
                + alphabet[index // len(alphabet)]
                + alphabet[index % len(alphabet)]
            )
            with self.assertRaises(DeviceAuthError):
                await registry.authenticate_and_register(
                    device_id=device_id,
                    verifier=reject_unknown,
                    close_callback=_noop_close,
                )
        self.assertEqual(LOCK_STRIPE_COUNT, (await registry.snapshot()).stripe_count)

    async def test_handshake_capacity_release_and_stop(self) -> None:
        registry = DeviceConnectionRegistry(max_handshakes=1)
        holder = {}

        async def close(_code: int, _reason: str) -> None:
            await holder["permit"].release()

        permit = await registry.acquire_handshake(close)
        holder["permit"] = permit
        with self.assertRaises(DeviceConnectionRegistryCapacityError):
            await registry.acquire_handshake(_noop_close)
        await permit.release()
        await permit.release()
        self.assertEqual(0, (await registry.snapshot()).handshake_count)

        await registry.stop_accepting_and_close_all()
        with self.assertRaises(DeviceConnectionRegistryClosedError):
            await registry.acquire_handshake(_noop_close)

    async def test_concurrent_shutdown_reuses_handshake_close_task(self) -> None:
        registry = DeviceConnectionRegistry(close_timeout_s=1)
        holder = {}
        close_started = asyncio.Event()
        allow_close = asyncio.Event()
        close_call_count = 0

        async def close(_code: int, _reason: str) -> None:
            nonlocal close_call_count
            close_call_count += 1
            close_started.set()
            await allow_close.wait()
            await holder["permit"].release()

        permit = await registry.acquire_handshake(close)
        holder["permit"] = permit
        first = asyncio.create_task(registry.stop_accepting_and_close_all())
        await close_started.wait()
        second = asyncio.create_task(registry.stop_accepting_and_close_all())
        await asyncio.sleep(0)
        self.assertEqual(1, close_call_count)
        allow_close.set()
        await asyncio.gather(first, second)
        snapshot = await registry.snapshot()
        self.assertFalse(snapshot.accepting)
        self.assertEqual(0, snapshot.handshake_count)

    async def test_close_code_policy_rejects_reserved_wire_values(self) -> None:
        registry = DeviceConnectionRegistry()
        transition_call_count = 0

        async def transition() -> None:
            nonlocal transition_call_count
            transition_call_count += 1

        invalid_codes = (
            True,
            999,
            1004,
            1005,
            1006,
            1015,
            2000,
            2999,
            5000,
        )
        for code in invalid_codes:
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    await registry.transition_and_close(
                        device_id=DEVICE_A,
                        transition=transition,
                        close_code=code,  # type: ignore[arg-type]
                    )
        self.assertEqual(0, transition_call_count)

    async def test_close_code_policy_accepts_standard_and_app_values(self) -> None:
        registry = DeviceConnectionRegistry()
        valid_codes = (
            1000,
            1001,
            1002,
            1003,
            1007,
            1008,
            1009,
            1010,
            1011,
            1012,
            1013,
            1014,
            3000,
            4404,
            4999,
        )
        for code in valid_codes:
            with self.subTest(code=code):
                result = await registry.transition_and_close(
                    device_id=DEVICE_A,
                    transition=_noop_transition,
                    close_code=code,
                )
                self.assertEqual(0, result.closed_connection_count)

    async def test_per_device_and_total_connection_limits(self) -> None:
        registry = DeviceConnectionRegistry(
            max_connections=2,
            max_per_device=1,
        )
        first = await self._register(registry, DEVICE_A)
        with self.assertRaises(DeviceConnectionRegistryCapacityError):
            await registry.authenticate_and_register(
                device_id=DEVICE_A,
                verifier=lambda: _verify(DEVICE_A),
                close_callback=_noop_close,
            )
        second = await self._register(registry, DEVICE_B)
        with self.assertRaises(DeviceConnectionRegistryCapacityError):
            await registry.authenticate_and_register(
                device_id="01ARZ3NDEKTSV4RRFFQ69G5FAY",
                verifier=lambda: _verify("01ARZ3NDEKTSV4RRFFQ69G5FAY"),
                close_callback=_noop_close,
            )
        self.assertEqual(2, (await registry.snapshot()).connection_count)
        await first.unregister()
        await second.unregister()
        self.assertEqual(0, (await registry.snapshot()).connection_count)

    async def test_verifier_identity_mismatch_never_registers(self) -> None:
        registry = DeviceConnectionRegistry()
        with self.assertRaises(DeviceConnectionRegistryPolicyError):
            await registry.authenticate_and_register(
                device_id=DEVICE_A,
                verifier=lambda: _verify(DEVICE_B),
                close_callback=_noop_close,
            )
        self.assertEqual(0, (await registry.snapshot()).connection_count)

    async def test_transition_commits_before_close_and_is_device_scoped(self) -> None:
        registry = DeviceConnectionRegistry()
        committed = False
        a_holder = {}
        b_holder = {}
        close_observations = []

        async def close_a(code: int, reason: str) -> None:
            close_observations.append(
                (
                    committed,
                    lease_a._authorization_changed.is_set(),
                    code,
                    reason,
                )
            )
            await a_holder["lease"].unregister()

        async def close_b(_code: int, _reason: str) -> None:
            await b_holder["lease"].unregister()

        _, lease_a = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=close_a,
        )
        _, lease_b = await registry.authenticate_and_register(
            device_id=DEVICE_B,
            verifier=lambda: _verify(DEVICE_B),
            close_callback=close_b,
        )
        a_holder["lease"] = lease_a
        b_holder["lease"] = lease_b

        async def transition() -> str:
            nonlocal committed
            committed = True
            return "committed"

        result = await registry.transition_and_close(
            device_id=DEVICE_A,
            transition=transition,
        )
        snapshot = await registry.snapshot()
        self.assertEqual("committed", result.value)
        self.assertEqual(1, result.closed_connection_count)
        self.assertEqual(
            [(True, True, 1008, "device authorization changed")],
            close_observations,
        )
        self.assertEqual(1, snapshot.connection_count)
        self.assertEqual(1, snapshot.device_count)
        await lease_b.unregister()

    async def test_failed_transition_does_not_detach_or_close(self) -> None:
        registry = DeviceConnectionRegistry()
        closed = False

        async def close(_code: int, _reason: str) -> None:
            nonlocal closed
            closed = True

        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=close,
        )

        async def transition() -> None:
            raise RuntimeError("synthetic transition failure")

        with self.assertRaisesRegex(RuntimeError, "synthetic transition"):
            await registry.transition_and_close(
                device_id=DEVICE_A,
                transition=transition,
            )
        self.assertFalse(closed)
        self.assertEqual(1, (await registry.snapshot()).connection_count)
        await lease.unregister()

    async def test_late_authentication_cannot_survive_committed_transition(
        self,
    ) -> None:
        registry = DeviceConnectionRegistry()
        holder = {}
        transition_started = asyncio.Event()
        allow_transition = asyncio.Event()
        revoked = False

        async def close(_code: int, _reason: str) -> None:
            await holder["lease"].unregister()

        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=close,
        )
        holder["lease"] = lease

        async def transition() -> None:
            nonlocal revoked
            transition_started.set()
            await allow_transition.wait()
            revoked = True

        transition_task = asyncio.create_task(
            registry.transition_and_close(
                device_id=DEVICE_A,
                transition=transition,
            )
        )
        await transition_started.wait()

        async def late_verifier() -> AuthenticatedDevice:
            if revoked:
                raise DeviceAuthError("auth_revoked", 401)
            return _device(DEVICE_A)

        late_task = asyncio.create_task(
            registry.authenticate_and_register(
                device_id=DEVICE_A,
                verifier=late_verifier,
                close_callback=_noop_close,
            )
        )
        allow_transition.set()
        await transition_task
        with self.assertRaises(DeviceAuthError):
            await late_task
        self.assertEqual(0, (await registry.snapshot()).connection_count)

    async def test_shutdown_closes_handshakes_and_connections(self) -> None:
        registry = DeviceConnectionRegistry()
        holder = {}
        closes = []

        async def close_handshake(code: int, reason: str) -> None:
            closes.append(("handshake", code, reason))
            await holder["permit"].release()

        async def close_connection(code: int, reason: str) -> None:
            closes.append(("connection", code, reason))
            await holder["lease"].unregister()

        permit = await registry.acquire_handshake(close_handshake)
        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=close_connection,
        )
        holder.update(permit=permit, lease=lease)
        await registry.stop_accepting_and_close_all()
        snapshot = await registry.snapshot()
        self.assertFalse(snapshot.accepting)
        self.assertEqual(0, snapshot.handshake_count)
        self.assertEqual(0, snapshot.connection_count)
        self.assertEqual(
            {
                ("handshake", 1012, "service restart"),
                ("connection", 1012, "service restart"),
            },
            set(closes),
        )

    async def test_close_timeout_owns_and_drains_callback_task(self) -> None:
        registry = DeviceConnectionRegistry(
            max_connections=1,
            max_per_device=1,
            close_timeout_s=0.02,
        )
        callback_cancelled = asyncio.Event()
        close_call_count = 0

        async def blocking_close(_code: int, _reason: str) -> None:
            nonlocal close_call_count
            close_call_count += 1
            try:
                await asyncio.Event().wait()
            finally:
                callback_cancelled.set()

        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=blocking_close,
        )
        with self.assertRaises(DeviceConnectionRegistryCloseTimeout):
            await registry.transition_and_close(
                device_id=DEVICE_A,
                transition=_noop_transition,
            )
        self.assertTrue(callback_cancelled.is_set())
        snapshot = await registry.snapshot()
        self.assertEqual(1, snapshot.connection_count)
        self.assertEqual(1, snapshot.closing_connection_count)
        self.assertEqual(1, snapshot.device_count)
        self.assertTrue(lease._authorization_changed.is_set())
        with self.assertRaises(DeviceConnectionRegistryCapacityError):
            await registry.authenticate_and_register(
                device_id=DEVICE_B,
                verifier=lambda: _verify(DEVICE_B),
                close_callback=_noop_close,
            )
        with self.assertRaises(DeviceConnectionRegistryCloseTimeout):
            await registry.transition_and_close(
                device_id=DEVICE_A,
                transition=_noop_transition,
            )
        self.assertTrue(callback_cancelled.is_set())
        self.assertEqual(1, close_call_count)
        await lease.unregister()
        self.assertEqual(0, (await registry.snapshot()).connection_count)

    async def test_parent_cancellation_during_transition_still_closes(self) -> None:
        registry = DeviceConnectionRegistry(close_timeout_s=1)
        holder = {}
        transition_started = asyncio.Event()
        allow_transition_return = asyncio.Event()
        close_called = asyncio.Event()
        committed = False

        async def close(_code: int, _reason: str) -> None:
            close_called.set()
            await holder["lease"].unregister()

        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=close,
        )
        holder["lease"] = lease

        async def transition() -> None:
            nonlocal committed
            committed = True
            transition_started.set()
            await allow_transition_return.wait()

        task = asyncio.create_task(
            registry.transition_and_close(
                device_id=DEVICE_A,
                transition=transition,
            )
        )
        await transition_started.wait()
        task.cancel()
        task.cancel()
        await asyncio.sleep(0)
        self.assertTrue(committed)
        self.assertFalse(close_called.is_set())
        allow_transition_return.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(close_called.is_set())
        self.assertTrue(lease._authorization_changed.is_set())
        self.assertEqual(0, (await registry.snapshot()).connection_count)

    async def test_concurrent_transitions_share_one_close_task(self) -> None:
        registry = DeviceConnectionRegistry(close_timeout_s=1)
        holder = {}
        close_started = asyncio.Event()
        second_transition_ran = asyncio.Event()
        allow_close = asyncio.Event()
        close_call_count = 0
        concurrent_close_count = 0
        peak_concurrent_close_count = 0

        async def close(_code: int, _reason: str) -> None:
            nonlocal close_call_count
            nonlocal concurrent_close_count
            nonlocal peak_concurrent_close_count
            close_call_count += 1
            concurrent_close_count += 1
            peak_concurrent_close_count = max(
                peak_concurrent_close_count,
                concurrent_close_count,
            )
            close_started.set()
            try:
                await allow_close.wait()
            finally:
                concurrent_close_count -= 1
            await holder["lease"].unregister()

        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=close,
        )
        holder["lease"] = lease

        first = asyncio.create_task(
            registry.transition_and_close(
                device_id=DEVICE_A,
                transition=_noop_transition,
            )
        )
        await close_started.wait()

        async def second_transition() -> None:
            second_transition_ran.set()

        second = asyncio.create_task(
            registry.transition_and_close(
                device_id=DEVICE_A,
                transition=second_transition,
            )
        )
        await second_transition_ran.wait()
        await asyncio.sleep(0)
        self.assertEqual(1, close_call_count)
        self.assertEqual(1, peak_concurrent_close_count)
        allow_close.set()
        first_result, second_result = await asyncio.gather(first, second)
        self.assertEqual(1, first_result.closed_connection_count)
        self.assertEqual(0, second_result.closed_connection_count)
        self.assertEqual(0, (await registry.snapshot()).connection_count)

    async def test_shutdown_reuses_in_flight_transition_close(self) -> None:
        registry = DeviceConnectionRegistry(close_timeout_s=1)
        holder = {}
        close_started = asyncio.Event()
        allow_close = asyncio.Event()
        close_call_count = 0

        async def close(_code: int, _reason: str) -> None:
            nonlocal close_call_count
            close_call_count += 1
            close_started.set()
            await allow_close.wait()
            await holder["lease"].unregister()

        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=close,
        )
        holder["lease"] = lease
        transition_task = asyncio.create_task(
            registry.transition_and_close(
                device_id=DEVICE_A,
                transition=_noop_transition,
            )
        )
        await close_started.wait()
        shutdown_task = asyncio.create_task(
            registry.stop_accepting_and_close_all()
        )
        await asyncio.sleep(0)
        self.assertEqual(1, close_call_count)
        allow_close.set()
        await asyncio.gather(transition_task, shutdown_task)
        snapshot = await registry.snapshot()
        self.assertFalse(snapshot.accepting)
        self.assertEqual(0, snapshot.connection_count)

    async def test_parent_cancellation_waits_for_committed_close(self) -> None:
        registry = DeviceConnectionRegistry(close_timeout_s=1)
        holder = {}
        callback_started = asyncio.Event()
        allow_close = asyncio.Event()
        callback_completed = asyncio.Event()

        async def blocking_close(_code: int, _reason: str) -> None:
            callback_started.set()
            await allow_close.wait()
            await holder["lease"].unregister()
            callback_completed.set()

        _, lease = await registry.authenticate_and_register(
            device_id=DEVICE_A,
            verifier=lambda: _verify(DEVICE_A),
            close_callback=blocking_close,
        )
        holder["lease"] = lease
        task = asyncio.create_task(
            registry.transition_and_close(
                device_id=DEVICE_A,
                transition=_noop_transition,
            )
        )
        await callback_started.wait()
        task.cancel()
        allow_close.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(callback_completed.is_set())
        self.assertEqual(0, (await registry.snapshot()).connection_count)

    async def _register(
        self,
        registry: DeviceConnectionRegistry,
        device_id: str,
    ):
        _, lease = await registry.authenticate_and_register(
            device_id=device_id,
            verifier=lambda: _verify(device_id),
            close_callback=_noop_close,
        )
        return lease


async def _noop_close(_code: int, _reason: str) -> None:
    return None


async def _noop_transition() -> None:
    return None


if __name__ == "__main__":
    unittest.main()
