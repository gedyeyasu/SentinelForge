# Controlled Vulnerable Shop

This fixture contains a deliberate broken-object-level authorization defect for authorized local testing. `GET /orders/{order_id}` authenticates the caller but does not verify that the requested order belongs to the caller's tenant.

Never deploy this fixture to a public environment.
