# ms-sec-gateway

**API gateway and security perimeter for the RIntellix credit-risk platform.**

`Java 17` · `Spring Cloud Gateway` · `Spring WebFlux` · `Keycloak / OAuth2`

---

## 1. Overview

`ms-sec-gateway` is the single entry point for all external traffic into RIntellix. It is a
reactive API gateway built on Spring Cloud Gateway that:

- Routes incoming requests to the appropriate downstream microservice
  (`ms-core-data`, `ms-risk-engine`, …).
- Validates OAuth2/JWT access tokens issued by **Keycloak** before a request is allowed through.
- Centralises cross-cutting concerns (CORS, error format, request filtering) so downstream
  services don't have to re-implement them.

No business logic lives here — its only responsibility is *authenticate, route, protect*.

## 2. Key aspects of the system

- **Reactive, non-blocking gateway.** Built with `spring-cloud-starter-gateway-server-webflux`
  on Project Reactor, suited to proxy many concurrent downstream calls efficiently.
- **OAuth2 resource-server validation.** `spring-boot-starter-oauth2-resource-server` validates
  incoming bearer tokens against the Keycloak issuer configured in `KEYCLOAK_ISSUER_URI`.
  Token/role logic lives in `security/`.
- **Custom gateway filters.** `filters/` contains pre/post filters applied to routed requests
  (e.g. propagating auth context, logging).
- **Centralised reactive error handling.** `error/` implements a global handler so that gateway-
  level failures (auth failures, routing errors, downstream timeouts) return a consistent error
  payload instead of leaking framework-specific stack traces.

### Repository structure

The following schematic illustrates the source code layout and how the key architectural pieces described above map to the main project folders:

![Directory structure](./estructura_directorios_ms_sec_gateway.svg)

## 3. Tech stack

- **Language / runtime:** Java 17
- **Framework:** Spring Cloud Gateway (reactive, WebFlux-based)
- **Security:** Spring Security + OAuth2 Resource Server, Keycloak 26.4 as Identity Provider
- **Utilities:** Lombok

## 4. Prerequisites

- JDK 17+
- Maven 3.9+
- Docker & Docker Compose (to run Keycloak locally)
- The downstream services this gateway routes to (`ms-core-data`, `ms-risk-engine`) reachable
  at the URLs configured below

## 5. Getting started

> `**IMPORTANT**`
>
> **Global platform deployment**:
> This repository contains only the gateway code. To spin up the entire RIntellix platform (including this service, Keycloak, and the rest of the microservices), clone the main infrastructure repository **[TFG-RIntellix/rintellix-deployment]** and follow its instructions.

The following commands are provided for local development, code review, and building:

```bash
# 1. Clone the repository
git clone https://github.com/TFG-RIntellix/ms-sec-gateway.git
cd ms-sec-gateway

# 2. Prepare your environment file
cp .env.example .env
# edit .env if you need different ports/credentials

# 3. Build the project
mvn clean package -DskipTests
```

The gateway listens on **port 8080** by default, configured via `GATEWAY_PORT`.

## 6. Configuration

Environment variables (see `.env.example`):

| Variable | Description | Default |
|---|---|---|
| `KEYCLOAK_ADMIN` | Keycloak admin console username (local dev only) | `admin` |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin console password (local dev only) | `admin` |
| `GATEWAY_PORT` | Port the gateway listens on | `8080` |
| `KEYCLOAK_ISSUER_URI` | OAuth2 issuer URI used to validate tokens | `http://localhost:8180/realms/rintellix` |
| `MS_CORE_DATA_URI` | Base URL of `ms-core-data` | `http://localhost:8081` |
| `MS_RISK_ENGINE_URI` | Base URL of `ms-risk-engine` | `http://localhost:8082` |

> `application.yaml*` / `application.properties*` are gitignored — route definitions and
> resource-server settings should reference the variables above.

## 7. Related services

- **ms-core-data**, **ms-risk-engine** — downstream services this gateway routes to.
- **Keycloak** — identity provider for OAuth2 token validation.

## 8. Author

Lucía Fernández Mancebo — TFG *RIntellix*, Universidad de Cantabria.



