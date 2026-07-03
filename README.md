# ms-sec-gateway

Security gateway for the **RIntellix** platform — the single public entry point
that sits in front of the microservices, authenticates callers against
**Keycloak**, authorises only the **`ANALISTA`** role to execute REST methods,
and filters out **MongoDB (NoSQL) injection** and other common web attacks
before routing the surviving traffic downstream.

> Built for the TFG local setup: `ms-risk-engine`, `ms-core-data` and
> `ms-reporting` run locally, `ms-model` runs in Docker, and Keycloak runs in
> Docker. Everything is designed to move into a single Docker network later.

## Tech stack

- Java 17, Spring Boot **4.0.7**, Maven
- Spring Cloud Gateway **2025.1.x** (reactive / WebFlux server)
- Spring Security **OAuth2 Resource Server** (JWT validation against Keycloak)

## Responsibilities

| Concern | How |
|---|---|
| **Authentication** | Validates the Keycloak JWT (signature/issuer/expiry via the realm JWKS) on every request. Stateless bearer tokens. |
| **Authorization** | Every routed REST method requires `hasRole('ANALISTA')`. Realm roles are read from the JWT `realm_access.roles` claim and mapped to `ROLE_*`. No/invalid token → `401`; authenticated but not `ANALISTA` → `403`. |
| **NoSQL injection filter** | Scans query params, path and JSON body; rejects Mongo operator injection (`$where`, `$ne`, `$gt`, `$regex`, …), `$`-prefixed / dotted JSON keys, and embedded JS. |
| **Input hardening** | Max body size, max URL length, header-count cap, path-traversal and reflected-XSS rejection. |
| **Rate limiting** | In-memory token bucket, keyed by JWT subject (falls back to client IP). |
| **Transport hardening** | Restricted CORS, security response headers (CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS), and stripping of spoofable inbound identity headers. |

## Routes

| Path | Downstream |
|---|---|
| `/api/simulations/**`, `/api/requests/**` | `ms-core-data` (`:8081`) |
| `/api/v1/simulations/**` | `ms-risk-engine` (`:8082`) |

`ms-model` (`:8000`) is **internal** (called only by `ms-risk-engine`) and is
deliberately not routed through the gateway.

## Ports

| Component | Port |
|---|---|
| ms-sec-gateway | `8080` |
| Keycloak | `8180` |
| ms-core-data | `8081` |
| ms-risk-engine | `8082` |
| ms-model (Docker) | `8000` |

## Getting started

### 1. Start Keycloak (Docker)

```bash
cp .env.example .env          # optional: adjust admin creds / ports
docker compose up -d keycloak
```

This imports the `rintellix` realm from `keycloak/rintellix-realm.json`:
- realm role **`ANALISTA`**,
- public client **`rintellix-frontend`** (Standard Flow + Direct Access Grants),
- test users **`analista`** / `analista` (has `ANALISTA`) and **`viewer`** /
  `viewer` (no role).

Admin console: <http://localhost:8180> (default `admin` / `admin`).

### 2. Run the gateway

```bash
mvn spring-boot:run
```

> Keycloak must be reachable at startup — the gateway resolves the realm's JWKS
> from `KEYCLOAK_ISSUER_URI` (default `http://localhost:8180/realms/rintellix`).

### 3. Get a token and call through the gateway

```bash
# Obtain an access token for the analyst user (password grant)
TOKEN=$(curl -s \
  -d "client_id=rintellix-frontend" \
  -d "grant_type=password" \
  -d "username=analista" -d "password=analista" \
  http://localhost:8180/realms/rintellix/protocol/openid-connect/token \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

# Authorised call (ANALISTA) → forwarded to ms-core-data
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/requests

# No token → 401 ; token for `viewer` → 403
curl -i http://localhost:8080/api/requests

# Blocked NoSQL injection → 400
curl -i -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST -d '{"partyName": {"$ne": null}}' \
  http://localhost:8080/api/simulations
```

## Configuration

All values have safe defaults. Common overrides (env var → property):

| Env var | Property | Default |
|---|---|---|
| `GATEWAY_PORT` | `server.port` | `8080` |
| `KEYCLOAK_ISSUER_URI` | `spring.security.oauth2.resourceserver.jwt.issuer-uri` | `http://localhost:8180/realms/rintellix` |
| `MS_CORE_DATA_URI` | route uri | `http://localhost:8081` |
| `MS_RISK_ENGINE_URI` | route uri | `http://localhost:8082` |

Attack-filter tuning lives under the `gateway.security.*` prefix (see
`application.yaml` / `GatewaySecurityProperties`): `cors`, `limits`,
`injection`, `rate-limit`, `stripped-headers`.

## Build & test

```bash
mvn clean test      # unit tests (attack detector + role converter)
mvn clean package   # build the executable jar
```

## Notes / future work

- **Gateway bypass:** the backends currently have no auth and listen on
  localhost, so they can be reached directly. For the future all-Docker setup,
  publish only the gateway's port and keep backends on an internal network.
  Adding JWT validation on each backend would be additional defence-in-depth.
- `ms-reporting` exposes no REST endpoints today (Kafka-driven); routes will be
  added here when it does.
- Rate limiting is per-instance in-memory; switch to a Redis-backed
  `RequestRateLimiter` when running multiple gateway instances.
- TLS/HSTS is meaningful only once the gateway is served over HTTPS.
