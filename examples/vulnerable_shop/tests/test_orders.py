from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_owner_can_read_order() -> None:
    response = client.get("/orders/1", headers={"x-user-id": "tenant-a-user"})
    assert response.status_code == 200
    assert response.json()["item"] == "GPU workstation"


def test_missing_order_is_not_found() -> None:
    response = client.get("/orders/999", headers={"x-user-id": "tenant-a-user"})
    assert response.status_code == 404
