from pathlib import Path

from sentinelforge.detectors import FastAPIBOLADetector

FIXTURE = Path(__file__).parents[1] / "examples" / "vulnerable_shop"


def test_detector_finds_missing_tenant_authorization() -> None:
    findings = FastAPIBOLADetector().scan(FIXTURE)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "SF-PY-FASTAPI-BOLA-001"
    assert finding.endpoint == "/orders/{order_id}"
    assert finding.evidence["resource_variable"] == "order"
    assert finding.evidence["identity_variable"] == "current_user"
    assert finding.invariant.startswith("A principal may access")


def test_detector_accepts_explicit_tenant_authorization(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text(
        """from fastapi import FastAPI
app = FastAPI()

@app.get("/orders/{order_id}")
def read_order(order_id: int, current_user):
    order = get_order(order_id)
    if order.tenant_id != current_user.tenant_id:
        raise PermissionError
    return order
""",
        encoding="utf-8",
    )

    assert FastAPIBOLADetector().scan(tmp_path) == []
