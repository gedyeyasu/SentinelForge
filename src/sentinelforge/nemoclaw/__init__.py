"""
NemoClaw - Persistent orchestrator for SentinelForge

Per PLAN.md §6 and Track 1 (NemoClaw + OpenShell bounty):
- Persistent orchestrator that maintains run state + memory across heartbeat ticks
- Fixed multi-agent roster (11 agents) in config/agents.yaml
- Heartbeat file HEARTBEAT.md with last_cursor, advisories_seen, learning delta
- Live run via orchestrator that survives restarts (event-sourced)

This module implements NemoClaw-specific extensions on top of generic AgentOrchestrator.
"""

from sentinelforge.nemoclaw.heartbeat import NemoClawHeartbeat
from sentinelforge.nemoclaw.orchestrator import NemoClawOrchestrator

__all__ = ["NemoClawOrchestrator", "NemoClawHeartbeat"]
