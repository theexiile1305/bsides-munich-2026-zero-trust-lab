# BSides Munich 2026: Zero Trust lab

A local-only shop demonstrates one service-to-service call: `order` obtains an X.509 SVID from SPIRE, authenticates to Keycloak with a custom SPIFFE URI-SAN client authenticator, requests a five-minute JWT, and calls `inventory` over SPIFFE mTLS. Inventory validates the JWT locally from cached JWKS and asks its OPA sidecar whether this peer, client, scope, method and path are allowed.

This is a teaching system shaped around review findings, not a production deployment or a customer incident. The SPIFFE-to-Keycloak bridge is intentionally explicit; Keycloak's built-in X.509 client authenticator does not perform this URI-SAN mapping.

## Prerequisites

- Docker with about 8 GiB free memory and network access for image and chart downloads;
- `kind`, `kubectl`, `helm`, `openssl`, `jq`, `make`;
- free local cluster name `bsides-zt`.

```sh
make up
make demo
make test
make policy-test
```

Expected `make test` output:

```text
200  order → inventory (GET, inventory-read)
401  token audience = billing
403  inventory-read cannot authorize POST
403  peer = spiffe://prod.demo/ns/shop/sa/other
401  staging issuer at prod inventory
```

`make demo CASE=allow` and `make demo CASE=deny` isolate the two stage fallback sections. The main `make demo` runs four checks. A failed expectation exits nonzero. `make down` deletes the local `bsides-zt` kind cluster.

## What the denial cases prove

| Case | Checks reached | Response |
| --- | --- | --- |
| `order` GET with inventory token | TLS peer, JWT signature/issuer/audience/expiry, OPA method and scope | 200 |
| Billing-audience token at inventory | JWT audience | 401 |
| `order` POST with inventory-read token | OPA action policy | 403 |
| `other` reuses order's token | Verified SPIFFE peer to authorized client mapping | 403 |
| Staging token at production inventory | JWT issuer | 401 |

The lab rotates workload SVIDs through the SPIRE Workload API and refreshes its JWKS cache on a new `kid` or cache expiry. It does not simulate a signing-key rotation under load. A five-minute bearer token remains replayable within its lifetime by a process with the authorized workload identity. The demo intentionally omits user delegation, NetworkPolicy, external ingress, persistent Keycloak storage, HA, monitoring, and production-grade secret management. Keycloak's bootstrap admin credential and TLS server certificate are disposable local development material; the `order` workload has no static client secret.

## Source map

- `extension/`: Keycloak 26.7.4 client authenticator requiring a trusted TLS client certificate, exactly one SPIFFE URI SAN, and an exact client-ID mapping.
- `realm/`: separate `prod` and `staging` issuers with narrow scopes and audience mappers.
- `helm/`, `k8s/`: SPIRE and shop workload definitions.
- `app/`: token client, SPIFFE mTLS inventory, and local RS256 JWT validation.
- `policy/`: OPA Rego policy and tests.
- `scripts/`: repeatable cluster setup, Keycloak flow configuration, and demonstration.

The implementation uses [SPIFFE/SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/), [Keycloak client authentication](https://www.keycloak.org/docs/latest/server_development/), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html), and [OPA's REST API](https://www.openpolicyagent.org/docs/rest-api). The parent talk repository has a slide-by-slide source register.
