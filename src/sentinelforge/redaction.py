from __future__ import annotations

import hashlib
import re
from typing import Any


# Patterns that must never appear in persisted events, PR bodies, or attestations
SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+[A-Za-z0-9\-_\.=]+)"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?)"),
    re.compile(r"(?i)(x-api-key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?)"),
    re.compile(r"(?i)(GITHUB_TOKEN|NVIDIA_API_KEY|HIDDENLAYER_API_KEY)\s*=\s*.+"),
    re.compile(r"x-access-token:[^@\s]+@"),
    re.compile(r"(?i)(password|secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
]

REDACTED_PLACEHOLDER = "[REDACTED_SECRET]"


def redact_text(text: str) -> tuple[str, bool]:
    """Redact secrets from text. Returns (redacted_text, did_redact)."""
    original = text
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED_PLACEHOLDER, redacted)
    # Also redact long bearer-like tokens in headers
    redacted = re.sub(r"(?i)(authorization:\s*bearer\s+)\S+", r"\1" + REDACTED_PLACEHOLDER, redacted)
    redacted = re.sub(r"(?i)(x-user-id:\s*)\S+@\S+", r"\1[REDACTED_USER]", redacted)
    return redacted, redacted != original


def redact_dict(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Recursively redact dict values. Returns (redacted_dict, did_redact)."""
    redacted_any = False
    result: dict[str, Any] = {}
    sensitive_keys = {"authorization", "x-api-key", "api_key", "token", "password", "secret", "github_token", "nvidia_api_key"}
    for k, v in data.items():
        if k.lower() in sensitive_keys:
            result[k] = REDACTED_PLACEHOLDER
            redacted_any = True
        elif isinstance(v, str):
            rv, did = redact_text(v)
            result[k] = rv
            redacted_any = redacted_any or did
        elif isinstance(v, dict):
            rv, did = redact_dict(v)
            result[k] = rv
            redacted_any = redacted_any or did
        elif isinstance(v, list):
            new_list = []
            for item in v:
                if isinstance(item, str):
                    rv, did = redact_text(item)
                    new_list.append(rv)
                    redacted_any = redacted_any or did
                elif isinstance(item, dict):
                    rv, did = redact_dict(item)
                    new_list.append(rv)
                    redacted_any = redacted_any or did
                else:
                    new_list.append(item)
            result[k] = new_list
        else:
            result[k] = v
    return result, redacted_any


def redact_receipt_dict(receipt: dict[str, Any]) -> dict[str, Any]:
    """Redact ExploitReceipt dict for safe persistence/PR per PLAN §13 critical #9."""
    # Never persist raw Authorization headers, only hash
    headers = receipt.get("request_headers", {})
    if isinstance(headers, dict):
        # Keep only non-sensitive header names, redact values for auth-like
        safe_headers = {}
        for hk, hv in headers.items():
            if hk.lower() in ("authorization", "x-api-key", "cookie"):
                safe_headers[hk] = REDACTED_PLACEHOLDER
            else:
                # Redact if value looks like token
                if isinstance(hv, str) and len(hv) > 20 and ("Bearer" in hv or hv.count(".") == 2):
                    safe_headers[hk] = REDACTED_PLACEHOLDER
                else:
                    safe_headers[hk] = hv
        receipt = {**receipt, "request_headers": safe_headers}

    # Redact body if contains secret patterns
    body = receipt.get("response_body", "")
    if isinstance(body, str) and body:
        rb, _ = redact_text(body)
        receipt = {**receipt, "response_body": rb[:4096]}

    return receipt


def compute_evidence_hash(payload: dict[str, Any]) -> str:
    """Compute SHA256 evidence hash after redaction."""
    import json

    safe, _ = redact_dict(payload)
    canonical = json.dumps(safe, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def assert_no_secrets(payload: dict[str, Any]) -> None:
    """Raise if secrets still present (for PR creation gate)."""
    text = str(payload)
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            raise ValueError(f"Secret pattern detected in payload: {pattern.pattern[:50]} - blocked per security policy")
