import httpx

from sentinelforge.integrations import RedHatSecurityDataClient


def test_red_hat_client_parses_public_csaf_index() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/csaf.json")
        assert request.url.params["package"] == "compat-openssl11"
        assert request.url.params["isCompressed"] == "false"
        return httpx.Response(
            200,
            json=[
                {
                    "RHSA": "RHSA-2026:39012",
                    "severity": "important",
                    "released_on": "2026-07-13T17:34:24Z",
                    "CVEs": ["CVE-2026-28390", "CVE-2026-45447"],
                    "released_packages": ["compat-openssl11-1:1.1.1k-4.el9_2.2.x86_64"],
                    "resource_url": (
                        "https://access.redhat.com/hydra/rest/securitydata/"
                        "csaf/RHSA-2026:39012.json"
                    ),
                }
            ],
        )

    client = RedHatSecurityDataClient(client=httpx.Client(transport=httpx.MockTransport(handler)))

    advisories = client.list_advisories(package="compat-openssl11", created_days_ago=90, per_page=2)

    assert len(advisories) == 1
    assert advisories[0].advisory_id == "RHSA-2026:39012"
    assert advisories[0].severity == "important"
    assert advisories[0].cves == ["CVE-2026-28390", "CVE-2026-45447"]


def test_red_hat_client_rejects_unbounded_package_filter() -> None:
    client = RedHatSecurityDataClient(
        client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[])))
    )

    try:
        client.list_advisories(package="openssl&severity=critical")
    except ValueError as error:
        assert "unsupported characters" in str(error)
    else:
        raise AssertionError("Unsafe package filter was accepted")
