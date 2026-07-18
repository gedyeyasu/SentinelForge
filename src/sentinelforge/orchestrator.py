from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sentinelforge.control.models import PentestPhase
from sentinelforge.control.storage import SQLiteRunStore, utc_now
from sentinelforge.event_bus import EventBus, LiveEvent
from sentinelforge.pentest_modes import ModeConfig, PentestMode, get_mode_config

logger = logging.getLogger(__name__)


class Phase(StrEnum):
    INIT = "init"
    OWNERSHIP_VERIFICATION = "ownership_verification"
    ENVIRONMENT_CHECK = "environment_check"
    SCOPING = "scoping"
    CVE_INGESTION = "cve_ingestion"
    MAPPING = "mapping"
    DEPENDENCY_SCAN = "dependency_scan"
    PATTERN_SCAN = "pattern_scan"
    THREAT_LEARNING = "threat_learning"
    AUTH_ATTACK = "auth_attack"
    INJECTION_ATTACK = "injection_attack"
    ZERO_DAY_HUNTING = "zero_day_hunting"
    CUSTOM_EXPLOIT = "custom_exploit"
    HIDDENLAYER_SCAN = "hiddenlayer_scan"
    OPENSHELL_AUDIT = "openshell_audit"
    NIM_ANALYSIS = "nim_analysis"
    ATTESTATION = "attestation"
    COMPLETE = "complete"


PHASE_ORDER: list[Phase] = [
    Phase.INIT,
    Phase.OWNERSHIP_VERIFICATION,
    Phase.ENVIRONMENT_CHECK,
    Phase.SCOPING,
    Phase.CVE_INGESTION,
    Phase.MAPPING,
    Phase.DEPENDENCY_SCAN,
    Phase.PATTERN_SCAN,
    Phase.THREAT_LEARNING,
    Phase.AUTH_ATTACK,
    Phase.INJECTION_ATTACK,
    Phase.ZERO_DAY_HUNTING,
    Phase.CUSTOM_EXPLOIT,
    Phase.HIDDENLAYER_SCAN,
    Phase.OPENSHELL_AUDIT,
    Phase.NIM_ANALYSIS,
    Phase.ATTESTATION,
    Phase.COMPLETE,
]

PHASE_TO_PENTEST_PHASE: dict[Phase, PentestPhase] = {
    Phase.INIT: PentestPhase.SCOPING,
    Phase.OWNERSHIP_VERIFICATION: PentestPhase.SCOPING,
    Phase.ENVIRONMENT_CHECK: PentestPhase.SCOPING,
    Phase.SCOPING: PentestPhase.SCOPING,
    Phase.CVE_INGESTION: PentestPhase.SCOPING,
    Phase.MAPPING: PentestPhase.MAPPING,
    Phase.DEPENDENCY_SCAN: PentestPhase.MAPPING,
    Phase.PATTERN_SCAN: PentestPhase.MAPPING,
    Phase.THREAT_LEARNING: PentestPhase.MAPPING,
    Phase.AUTH_ATTACK: PentestPhase.ATTACKING,
    Phase.INJECTION_ATTACK: PentestPhase.ATTACKING,
    Phase.ZERO_DAY_HUNTING: PentestPhase.ATTACKING,
    Phase.CUSTOM_EXPLOIT: PentestPhase.ATTACKING,
    Phase.HIDDENLAYER_SCAN: PentestPhase.ATTACKING,
    Phase.OPENSHELL_AUDIT: PentestPhase.ATTACKING,
    Phase.NIM_ANALYSIS: PentestPhase.ATTACKING,
    Phase.ATTESTATION: PentestPhase.ATTESTED,
    Phase.COMPLETE: PentestPhase.ATTESTED,
}

_PHASE_NAMES: dict[Phase, str] = {
    Phase.INIT: "Initializing",
    Phase.OWNERSHIP_VERIFICATION: "Verifying Ownership",
    Phase.ENVIRONMENT_CHECK: "Checking Environment",
    Phase.SCOPING: "Validating Scope",
    Phase.CVE_INGESTION: "Ingesting CVE Intelligence (NVD/KEV/EPSS)",
    Phase.MAPPING: "Mapping Attack Surface",
    Phase.DEPENDENCY_SCAN: "Scanning Dependencies",
    Phase.PATTERN_SCAN: "Scanning for Exploit Patterns",
    Phase.THREAT_LEARNING: "Learning Threat Patterns",
    Phase.AUTH_ATTACK: "Running Auth Attacks (7 techniques)",
    Phase.INJECTION_ATTACK: "Running Injection Attacks (Adaptive Payloads)",
    Phase.ZERO_DAY_HUNTING: "Hunting Zero-Day Vulnerabilities",
    Phase.CUSTOM_EXPLOIT: "Writing Custom Exploit (Agent-written Python)",
    Phase.HIDDENLAYER_SCAN: "HiddenLayer AI Scan",
    Phase.OPENSHELL_AUDIT: "OpenShell Audit",
    Phase.NIM_ANALYSIS: "NIM Threat Analysis",
    Phase.ATTESTATION: "Generating Attestation",
    Phase.COMPLETE: "Complete",
}


@dataclass
class PhaseResult:
    phase: Phase
    success: bool
    duration_ms: int
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class OrchestratorState:
    run_id: str
    mode: PentestMode
    current_phase: Phase
    phases_completed: list[Phase] = field(default_factory=list)
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)
    results: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    cancelled: bool = False


PhaseHandler = Callable[
    [str, ModeConfig, OrchestratorState],
    Any,
]


class AgentOrchestrator:
    def __init__(
        self,
        store: SQLiteRunStore,
        *,
        mode: PentestMode = PentestMode.STANDARD,
    ) -> None:
        self._store = store
        self._mode = mode
        self._config = get_mode_config(mode)
        self._handlers: dict[Phase, PhaseHandler] = {}
        self._running: dict[str, asyncio.Task[None]] = {}
        self._bus = EventBus.instance()

    @property
    def config(self) -> ModeConfig:
        return self._config

    def register_handler(self, phase: Phase, handler: PhaseHandler) -> None:
        self._handlers[phase] = handler

    def plan_phases(self) -> list[Phase]:
        config = self._config
        phases: list[Phase] = [Phase.INIT]

        if config.require_ownership_verification:
            phases.append(Phase.OWNERSHIP_VERIFICATION)
        if config.detect_target_environment:
            phases.append(Phase.ENVIRONMENT_CHECK)

        phases.append(Phase.SCOPING)

        if config.run_cve_ingestion:
            phases.append(Phase.CVE_INGESTION)

        phases.append(Phase.MAPPING)

        if config.run_dependency_scan:
            phases.append(Phase.DEPENDENCY_SCAN)
        if config.run_pattern_scan:
            phases.append(Phase.PATTERN_SCAN)
        if config.run_threat_learning:
            phases.append(Phase.THREAT_LEARNING)
        if config.run_auth_attacks:
            phases.append(Phase.AUTH_ATTACK)
        if config.run_injection_attacks:
            phases.append(Phase.INJECTION_ATTACK)
        if config.run_zero_day_hunting:
            phases.append(Phase.ZERO_DAY_HUNTING)
        if config.run_custom_exploit:
            phases.append(Phase.CUSTOM_EXPLOIT)
        if config.run_hiddenlayer_scan:
            phases.append(Phase.HIDDENLAYER_SCAN)
        if config.run_openshell_audit:
            phases.append(Phase.OPENSHELL_AUDIT)

        if config.run_nim_analysis:
            phases.append(Phase.NIM_ANALYSIS)

        phases.append(Phase.ATTESTATION)
        phases.append(Phase.COMPLETE)
        return phases

    async def execute(
        self,
        run_id: str,
        context: dict[str, Any],
    ) -> OrchestratorState:
        state = OrchestratorState(
            run_id=run_id,
            mode=self._mode,
            current_phase=Phase.INIT,
            started_at=utc_now(),
            results=context,
        )

        phases = self.plan_phases()
        self._store.append_event(
            run_id,
            phase="orchestrator",
            kind="orchestration_started",
            payload={
                "mode": self._mode.value,
                "phases": [p.value for p in phases],
                "config": self._config.to_dict(),
            },
        )

        for phase in phases:
            if state.cancelled:
                break

            state.current_phase = phase
            pentest_phase = PHASE_TO_PENTEST_PHASE.get(
                phase, PentestPhase.SCOPING
            )
            self._store.update_pentest_run(
                run_id, phase=pentest_phase
            )
            self._bus.publish(LiveEvent(
                run_id=run_id,
                phase=phase.value,
                kind="phase_started",
                timestamp=time.time(),
                payload={"phase": phase.value, "phase_name": _PHASE_NAMES.get(phase, phase.value)},
            ))

            handler = self._handlers.get(phase)
            if handler is None:
                result = PhaseResult(
                    phase=phase,
                    success=True,
                    duration_ms=0,
                    data={"skipped": True, "reason": "no handler"},
                )
            else:
                start = time.monotonic()
                try:
                    data = await asyncio.wait_for(
                        asyncio.to_thread(
                            handler, run_id, self._config, state
                        ),
                        timeout=float(self._config.timeout_seconds),
                    )
                    duration = int(
                        (time.monotonic() - start) * 1000
                    )
                    result = PhaseResult(
                        phase=phase,
                        success=True,
                        duration_ms=duration,
                        data=data if isinstance(data, dict) else {},
                    )
                except TimeoutError:
                    duration = int(
                        (time.monotonic() - start) * 1000
                    )
                    result = PhaseResult(
                        phase=phase,
                        success=False,
                        duration_ms=duration,
                        error="Phase timed out",
                    )
                except Exception as exc:
                    duration = int(
                        (time.monotonic() - start) * 1000
                    )
                    result = PhaseResult(
                        phase=phase,
                        success=False,
                        duration_ms=duration,
                        error=str(exc),
                    )
                    logger.exception(
                        "Phase %s failed in run %s", phase, run_id
                    )

            state.phase_results[phase.value] = result
            state.phases_completed.append(phase)

            self._store.append_event(
                run_id,
                phase=phase.value,
                kind="phase_completed",
                payload={
                    "phase": phase.value,
                    "success": result.success,
                    "duration_ms": result.duration_ms,
                    "error": result.error,
                },
            )
            self._bus.publish(LiveEvent(
                run_id=run_id,
                phase=phase.value,
                kind="phase_completed",
                timestamp=time.time(),
                payload={
                    "phase": phase.value,
                    "phase_name": _PHASE_NAMES.get(phase, phase.value),
                    "success": result.success,
                    "duration_ms": result.duration_ms,
                    "error": result.error,
                },
            ))

            if (
                not result.success
                and self._config.gate_on_block
            ):
                self._store.append_event(
                    run_id,
                    phase=phase.value,
                    kind="orchestration_aborted",
                    payload={
                        "reason": "phase_failed",
                        "phase": phase.value,
                        "error": result.error,
                    },
                )
                break

        self._store.append_event(
            run_id,
            phase="orchestrator",
            kind="orchestration_completed",
            payload={
                "phases_completed": [
                    p.value for p in state.phases_completed
                ],
                "cancelled": state.cancelled,
            },
        )
        return state

    def cancel(self, run_id: str) -> None:
        task = self._running.get(run_id)
        if task and not task.done():
            task.cancel()

    def submit(
        self,
        run_id: str,
        context: dict[str, Any],
    ) -> asyncio.Task[OrchestratorState]:
        task = asyncio.create_task(
            self.execute(run_id, context)
        )
        self._running[run_id] = task
        task.add_done_callback(
            lambda _t: self._running.pop(run_id, None)
        )
        return task
