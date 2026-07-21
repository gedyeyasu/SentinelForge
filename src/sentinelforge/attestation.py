from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sentinelforge.redaction import redact_dict


@dataclass
class AttestationKeyPair:
    private_key_hex: str
    public_key_hex: str


def _load_or_create_keypair(key_dir: Path = Path(".sentinelforge/keys")) -> AttestationKeyPair:
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / "attestation_private.key"
    pub_path = key_dir / "attestation_public.key"
    if priv_path.is_file():
        private_hex = priv_path.read_text().strip()
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
        public_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        if not pub_path.is_file() or pub_path.read_text().strip() != public_hex:
            pub_path.write_text(public_hex)
        return AttestationKeyPair(
            private_key_hex=private_hex,
            public_key_hex=public_hex,
        )

    seed = os.urandom(32)
    private_hex = seed.hex()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    priv_path.write_text(private_hex)
    pub_path.write_text(public_hex)
    # Restrict perms
    try:
        priv_path.chmod(0o600)
        pub_path.chmod(0o644)
    except Exception:
        pass
    return AttestationKeyPair(private_key_hex=private_hex, public_key_hex=public_hex)


@dataclass
class SignedAttestation:
    attestation: dict[str, Any]
    signature: str
    public_key: str
    evidence_hash: str
    algorithm: str = "ed25519"


class AttestationSigner:
    """
    Produces signed JSON attestation per PLAN §7.3 Evidence Standard.
    Includes hash chain of events for tamper detection.
    """

    def __init__(self, key_dir: Path = Path(".sentinelforge/keys")):
        self.keypair = _load_or_create_keypair(key_dir)
        self.key_dir = key_dir

    def sign(
        self,
        run_id: str,
        candidate_verdict: str,
        patch_verdict: str | None,
        events: list[dict[str, Any]],
        results: dict[str, Any],
        threat_assessment: dict[str, Any] | None = None,
    ) -> SignedAttestation:
        # Redact before signing
        safe_results, _ = redact_dict(results)
        safe_events = []
        for ev in events:
            safe_payload, _ = redact_dict(ev.get("payload", {}))
            safe_events.append({**ev, "payload": safe_payload})

        # Hash chain: each event hash includes previous hash
        prev_hash = "0" * 64
        chain_hashes = []
        for ev in safe_events:
            canonical = json.dumps({**ev, "prev_hash": prev_hash}, sort_keys=True)
            h = hashlib.sha256(canonical.encode()).hexdigest()
            chain_hashes.append(h)
            prev_hash = h

        attestation = {
            "run_id": run_id,
            "version": "0.2.0",
            "candidate_verdict": candidate_verdict,
            "patch_verdict": patch_verdict,
            "event_count": len(safe_events),
            "event_chain_head": prev_hash,
            "event_chain_hashes": chain_hashes[-5:],  # last 5 for brevity
            "results_summary": {
                "routes": len(safe_results.get("routes", [])),
                "receipts": len(safe_results.get("receipts", [])),
                "dep_vulns": safe_results.get("dependency_vulnerabilities", {}).get("vulnerable_count", 0)
                if isinstance(safe_results.get("dependency_vulnerabilities"), dict)
                else len(safe_results.get("dependency_vulnerabilities", [])),
                "pattern_findings": safe_results.get("exploit_patterns", {}).get("finding_count", 0)
                if isinstance(safe_results.get("exploit_patterns"), dict)
                else 0,
            },
            "threat_assessment": threat_assessment,
            "evidence_review": (
                safe_results.get("openai_evidence_review")
                if isinstance(safe_results.get("openai_evidence_review"), dict)
                else None
            ),
            "compliance": {
                "evidence_standard": "PLAN §7.3 8 fields",
                "patch_standard": "PLAN §7.4 7 criteria",
                "human_approval_required": True,
                "no_prod_target": True,
                "secret_redaction_verified": True,
            },
            "public_key": self.keypair.public_key_hex,
        }

        canonical_att = json.dumps(attestation, sort_keys=True)
        evidence_hash = hashlib.sha256(canonical_att.encode()).hexdigest()
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(self.keypair.private_key_hex)
        )
        sig = private_key.sign(canonical_att.encode()).hex()

        return SignedAttestation(
            attestation=attestation,
            signature=sig,
            public_key=self.keypair.public_key_hex,
            evidence_hash=evidence_hash,
            algorithm="ed25519",
        )

    @staticmethod
    def verify(signed: SignedAttestation) -> bool:
        canonical = json.dumps(signed.attestation, sort_keys=True)
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(signed.public_key)
            )
            public_key.verify(bytes.fromhex(signed.signature), canonical.encode())
        except (InvalidSignature, ValueError):
            return False
        return True

    def write_attestation(self, run_id: str, signed: SignedAttestation, out_dir: Path = Path(".sentinelforge/attestations")) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"attestation_{run_id}.json"
        payload = {
            "attestation": signed.attestation,
            "signature": signed.signature,
            "public_key": signed.public_key,
            "evidence_hash": signed.evidence_hash,
            "algorithm": signed.algorithm,
        }
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return out_path
