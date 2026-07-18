from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

PRODUCTION_SIGNALS = [
    "production",
    "prod",
    "live",
    "release",
    "stable",
    "main",
    "master",
]

STAGING_SIGNALS = [
    "staging",
    "stage",
    "preprod",
    "pre-prod",
    "qa",
    "uat",
    "acceptance",
    "canary",
    "beta",
]

DEVELOPMENT_SIGNALS = [
    "development",
    "dev",
    "local",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "test",
    "testing",
    "experimental",
    "feature",
    "debug",
    "sandbox",
]

PRODUCTION_HEADERS = {
    "x-deployment-environment": "production",
    "x-env": "production",
    "x-app-env": "production",
    "x-deploy-env": "prod",
    "x-release": "true",
}

PRODUCTION_CONTENT_SIGNALS = [
    "robots.txt",
    "sitemap.xml",
    "google-analytics",
    "gtag",
    "hotjar",
    "segment.com",
    "mixpanel",
    "amplitude",
    "datadoghq",
    "sentry.io",
    "newrelic",
    "stripe.com",
    "paypal.com",
]


class EnvironmentTier(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EnvironmentClassification:
    tier: EnvironmentTier
    confidence: float
    signals: list[str]
    url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "confidence": self.confidence,
            "signals": self.signals,
            "url": self.url,
        }


class EnvironmentDetector:
    """Detects deployment tier of a target URL.

    Uses multiple signals:
    - URL path/host analysis
    - Response headers
    - Page content patterns
    """

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._client = client or httpx.Client(
            timeout=10,
            follow_redirects=True,
        )

    def detect(self, url: str) -> EnvironmentClassification:
        signals: list[str] = []
        score = 0.0

        url_score, url_signals = self._analyze_url(url)
        score += url_score
        signals.extend(url_signals)

        header_score, header_signals = self._analyze_headers(url)
        score += header_score
        signals.extend(header_signals)

        content_score, content_signals = self._analyze_content(url)
        score += content_score
        signals.extend(content_signals)

        tier = self._score_to_tier(score)

        return EnvironmentClassification(
            tier=tier,
            confidence=min(abs(score), 1.0),
            signals=signals,
            url=url,
        )

    def is_production(self, url: str) -> bool:
        result = self.detect(url)
        return result.tier == EnvironmentTier.PRODUCTION

    def _analyze_url(self, url: str) -> tuple[float, list[str]]:
        score = 0.0
        signals: list[str] = []
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path.lower()

        host_lower = host.lower()

        for signal in DEVELOPMENT_SIGNALS:
            if signal in host_lower:
                score -= 0.4
                signals.append(f"dev_host:{signal}")
                break

        for signal in STAGING_SIGNALS:
            if signal in host_lower:
                score -= 0.2
                signals.append(f"staging_host:{signal}")
                break

        for signal in PRODUCTION_SIGNALS:
            if signal in host_lower and signal not in DEVELOPMENT_SIGNALS:
                score += 0.3
                signals.append(f"prod_host:{signal}")
                break

        if host_lower in ("localhost", "127.0.0.1", "0.0.0.0"):
            score = -1.0
            signals.append("localhost")

        if "localhost" in url or "127.0.0.1" in url:
            score = -1.0
            signals.append("loopback")

        if any(ext in path for ext in ("/staging", "/dev/", "/test/", "/sandbox")):
            score -= 0.3
            signals.append("dev_path")

        if any(ext in path for ext in ("/prod", "/live", "/release")):
            score += 0.2
            signals.append("prod_path")

        return score, signals

    def _analyze_headers(self, url: str) -> tuple[float, list[str]]:
        score = 0.0
        signals: list[str] = []
        try:
            response = self._client.get(url, timeout=5)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            for header, expected in PRODUCTION_HEADERS.items():
                if header in headers and expected in headers[header]:
                    score += 0.3
                    signals.append(f"prod_header:{header}")

            server = headers.get("server", "")
            if any(s in server for s in ["cloudflare", "aws", "fastly", "akamai"]):
                score += 0.1
                signals.append(f"cdn_server:{server[:20]}")

            if "x-debug" in headers or "x-debug-mode" in headers:
                score -= 0.3
                signals.append("debug_header")

        except Exception as exc:
            logger.debug("Header analysis failed for %s: %s", url, exc)
            signals.append("header_fetch_failed")

        return score, signals

    def _analyze_content(self, url: str) -> tuple[float, list[str]]:
        score = 0.0
        signals: list[str] = []
        try:
            response = self._client.get(url, timeout=5)
            content = response.text[:50_000].lower()

            prod_count = sum(
                1 for s in PRODUCTION_CONTENT_SIGNALS if s.lower() in content
            )
            if prod_count >= 3:
                score += 0.3
                signals.append(f"prod_content_signals:{prod_count}")
            elif prod_count >= 1:
                score += 0.1
                signals.append(f"some_prod_signals:{prod_count}")

            dev_indicators = ["webpack-dev", "hot reload", "vite dev", "debug mode", "console.log"]
            dev_count = sum(1 for s in dev_indicators if s in content)
            if dev_count >= 2:
                score -= 0.3
                signals.append(f"dev_content_signals:{dev_count}")

        except Exception as exc:
            logger.debug("Content analysis failed for %s: %s", url, exc)
            signals.append("content_fetch_failed")

        return score, signals

    def _score_to_tier(self, score: float) -> EnvironmentTier:
        if score >= 0.4:
            return EnvironmentTier.PRODUCTION
        elif score >= 0.0:
            return EnvironmentTier.STAGING
        elif score >= -0.4:
            return EnvironmentTier.DEVELOPMENT
        else:
            return EnvironmentTier.DEVELOPMENT

    def scan_codebase_for_env_hints(
        self, repository_root: str
    ) -> dict[str, Any]:
        import pathlib

        root = pathlib.Path(repository_root)
        hints: list[str] = []

        env_files = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.staging",
            ".env.development",
        ]
        for env_file in env_files:
            path = root / env_file
            if path.exists():
                hints.append(f"env_file:{env_file}")

        docker_files = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]
        for docker_file in docker_files:
            path = root / docker_file
            if path.exists():
                try:
                    content = path.read_text(encoding="utf-8")[:5_000]
                    for signal in PRODUCTION_SIGNALS:
                        if signal in content.lower():
                            hints.append(f"docker_prod_signal:{signal}")
                            break
                except OSError:
                    pass

        config_patterns = [
            (r"(?:DEBUG|debug)\s*[=:]\s*(?:True|true|1|False|false|0)", "debug_flag"),
            (r"(?:ENVIRONMENT|environment)\s*[=:]\s*[\"']?(\w+)", "env_var"),
            (r"(?:NODE_ENV|node_env)\s*[=:]\s*[\"']?(\w+)", "node_env"),
        ]
        for py_file in list(root.rglob("*.py"))[:20]:
            if any(part.startswith(".") for part in py_file.relative_to(root).parts):
                continue
            try:
                content = py_file.read_text(encoding="utf-8")[:10_000]
            except OSError:
                continue
            for pattern, label in config_patterns:
                match = re.search(pattern, content)
                if match:
                    hints.append(f"{label}:{match.group()[:50]}")

        return {
            "hints": hints,
            "env_files_found": [h for h in hints if h.startswith("env_file:")],
            "config_signals": [h for h in hints if not h.startswith("env_file:")],
        }
