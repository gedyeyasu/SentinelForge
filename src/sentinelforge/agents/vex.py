from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class VEXStatus(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


@dataclass
class VEXStatement:
    vulnerability: str  # CVE id
    status: VEXStatus
    product: str  # purl or component name
    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None


@dataclass
class VEXDocument:
    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    version: int = 1
    statements: list[VEXStatement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "version": self.version,
            "vulnerabilities": [
                {
                    "id": s.vulnerability,
                    "analysis": {
                        "state": s.status.value,
                        "justification": s.justification,
                        "detail": s.impact_statement,
                        "response": [s.action_statement] if s.action_statement else [],
                    },
                    "affects": [{"ref": s.product}],
                }
                for s in self.statements
            ],
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


@dataclass
class ReachabilityResult:
    component: str
    version: str | None
    cve: str
    reachable: bool
    call_path: list[str] | None = None
    confidence: float = 0.0
    vex_status: VEXStatus = VEXStatus.AFFECTED
    justification: str | None = None


class VEXEvaluator:
    """
    Evaluates SBOM components against Red Hat CSAF + call-graph reachability.
    Generates VEX statements with no-impact evidence per PLAN P2 requirement.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def evaluate(
        self,
        sbom_components: list[Any],
        advisories: list[Any],
        call_graph: dict[str, list[str]] | None = None,
    ) -> list[ReachabilityResult]:
        results: list[ReachabilityResult] = []
        call_graph = call_graph or self._build_call_graph()

        for advisory in advisories:
            for pkg in advisory.released_packages:
                # pkg format like "python3-cryptography-3.4.8-..."
                pkg_name = self._extract_pkg_name(pkg)
                for comp in sbom_components:
                    if not self._name_matches(comp, pkg_name):
                        continue
                    cve = advisory.cves[0] if advisory.cves else advisory.advisory_id
                    reachable, call_path, conf = self._check_reachability(comp, cve, call_graph)
                    status = VEXStatus.AFFECTED if reachable else VEXStatus.NOT_AFFECTED
                    justification = (
                        "vulnerable_code_not_in_execute_path"
                        if not reachable
                        else "vulnerable_function_called"
                    )
                    results.append(
                        ReachabilityResult(
                            component=comp.name if hasattr(comp, "name") else str(comp),
                            version=getattr(comp, "version", None),
                            cve=cve,
                            reachable=reachable,
                            call_path=call_path,
                            confidence=conf,
                            vex_status=status,
                            justification=justification,
                        )
                    )
        return results

    def generate_vex_doc(self, results: list[ReachabilityResult]) -> VEXDocument:
        statements = []
        for r in results:
            statements.append(
                VEXStatement(
                    vulnerability=r.cve,
                    status=r.vex_status,
                    product=r.component,
                    justification=r.justification,
                    impact_statement=f"Reachability: {r.reachable}, call_path: {r.call_path}, confidence: {r.confidence}",
                    action_statement="Update to fixed version" if r.vex_status == VEXStatus.AFFECTED else "No action needed",
                )
            )
        return VEXDocument(statements=statements)

    def _build_call_graph(self) -> dict[str, list[str]]:
        # Simple AST import + function call graph
        import ast

        graph: dict[str, list[str]] = {}
        for py_file in self.root.rglob("*.py"):
            if any(part.startswith(".") for part in py_file.relative_to(self.root).parts):
                continue
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            imports = set()
            calls = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split(".")[0])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        calls.append(node.func.attr)
                    elif isinstance(node.func, ast.Name):
                        calls.append(node.func.id)
            for imp in imports:
                graph.setdefault(imp, []).extend(calls)
        return graph

    def _check_reachability(
        self, component: Any, cve: str, call_graph: dict[str, list[str]]
    ) -> tuple[bool, list[str] | None, float]:
        name = getattr(component, "normalized_name", "") or getattr(component, "name", "").lower()
        # Check if component name appears in call_graph keys
        if name in call_graph or any(name in k for k in call_graph.keys()):
            calls = call_graph.get(name, []) or next((v for k, v in call_graph.items() if name in k), [])
            # Heuristic: if any risky functions called
            risky = ["load", "loads", "eval", "exec", "verify", "decrypt", "encrypt"]
            matched_calls = [c for c in calls if any(r in c.lower() for r in risky)]
            if matched_calls:
                return True, [name, matched_calls[0]], 0.85
            return True, [name], 0.60
        # Not directly imported => low reachability
        return False, None, 0.90

    def _extract_pkg_name(self, released_pkg: str) -> str:
        # python3-cryptography-3.4.8-2.el8 -> cryptography
        # Try to extract after prefix
        if "python" in released_pkg:
            parts = released_pkg.split("-")
            # Heuristic: find component before version (version is like 3.4.8)
            for i, p in enumerate(parts):
                if p and p[0].isdigit() and "." in p:
                    # previous part is likely name
                    if i > 0:
                        return parts[i - 1]
            return parts[1] if len(parts) > 1 else released_pkg
        return released_pkg.split("-")[0]

    def _name_matches(self, component: Any, pkg_name: str) -> bool:
        comp_name = getattr(component, "normalized_name", "") or getattr(component, "name", "").lower()
        pkg_norm = pkg_name.lower().replace("_", "-")
        return comp_name == pkg_norm or pkg_norm in comp_name or comp_name in pkg_norm
