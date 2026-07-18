from dataclasses import dataclass

from fastapi import Depends, FastAPI, Header, HTTPException


@dataclass(frozen=True)
class User:
    id: str
    tenant_id: str


@dataclass(frozen=True)
class Order:
    id: int
    tenant_id: str
    item: str


USERS = {
    "tenant-a-user": User(id="tenant-a-user", tenant_id="tenant-a"),
    "tenant-b-user": User(id="tenant-b-user", tenant_id="tenant-b"),
}

ORDERS = {
    1: Order(id=1, tenant_id="tenant-a", item="GPU workstation"),
    2: Order(id=2, tenant_id="tenant-b", item="Inference credits"),
}

app = FastAPI(title="SentinelForge Vulnerable Shop")


def current_user(x_user_id: str = Header()) -> User:
    user = USERS.get(x_user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Unknown test identity")
    return user


def get_order(order_id: int) -> Order | None:
    return ORDERS.get(order_id)


@app.get("/orders/{order_id}")
def read_order(order_id: int, current_user: User = Depends(current_user)) -> Order:
    order = get_order(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Not found")
    return order
