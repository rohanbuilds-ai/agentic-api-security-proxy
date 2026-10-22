# Agentic API Security Proxy

[![Continuous Integration](https://github.com/rohanbuilds-ai/agentic-api-security-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/rohanbuilds-ai/agentic-api-security-proxy/actions/workflows/ci.yml)

An inline, fail-closed runtime API security gateway positioned between autonomous AI agents and protected backend services/databases.

### Project Summary for Reviewers & Recruiters
This repository implements a lightweight, deterministic application security proxy engineered for AI-agent tool-calling and autonomous API interactions:
- **Runtime Security Proxy for AI-Agent API Actions**: Intercepts, validates, and authorizes action requests before forwarding to upstream services.
- **Deterministic RBAC and Tenant Isolation**: Resolves trusted server-side agent identity, enforces strict role-based access control, and prevents Broken Object Level Authorization (BOLA/IDOR) via tenant scoping.
- **Request Inspection and Response DLP**: Detects adversarial input indicators and exfiltration attempts, recursively redacting sensitive egress data (SSNs, credit cards, credentials) with fail-closed semantics.
- **Tamper-Evident Audit Logging**: Cryptographically hash-chains all security decisions in an append-only store with SQLite tamper-prevention triggers.
- **Reproducible Security Evaluation**: Runs an automated 16-scenario adversarial evaluation battery measuring block rates, false rejection rates, and chain integrity.
- **Local-Only Mock Backend and Synthetic Demonstration Data**: Fully runnable without paid APIs, cloud services, external credentials, or model downloads.

> **Status:** Phase 5 Complete — Docker Containerization, CI/CD, Terminal Dashboard & Release Readiness
> **Cost & Dependencies:** 100% Free, local-only, zero cloud subscriptions, zero external model calls.

---

## 1. Project Overview & Multi-Stage Pipeline

Autonomous AI agents with tool-calling capabilities often propose actions (API calls, data mutations, queries) that standard backends execute uncritically. The **Agentic API Security Proxy** mediates every action request, enforcing deterministic application security controls before forwarding requests to protected upstream services.

```
[ AI Agent / Client ]
         │
         ▼  (1) POST /proxy/v1/action (Header: 'Authorization: Bearer <token>')
[ Proxy Gateway (:8000) ]
   ├── Stage 1: Payload Size & Schema Limits (Max 64KB, strict Pydantic V2)
   ├── Stage 2: Identity Resolver (Server-Side Registry -> AgentIdentity: role, tenant_id)
   ├── Stage 3: Identity Isolation (Client body cannot override role/tenant)
   ├── Stage 4: Deterministic Policy Engine (RBAC via config/policies.yaml -> Fail Closed)
   ├── Stage 5: Ingress Request Inspection & Adversarial Heuristics (Regex patterns -> 403 BLOCKED)
   ├── Stage 6: Tenant Injection & Service Key Wrapping
         │
         ▼  (2) HTTP Forward with 'X-Tenant-ID' & 'X-Internal-Service-Key'
[ Mock Upstream Backend (:8001) ]
   ├── Step 1: Internal Service Key Verification (Direct caller bypass blocked: 401)
   ├── Step 2: Tenant Context Scoping (Parameterized SQL: WHERE order_id = ? AND tenant_id = ?)
   ├── Step 3: BOLA Prevention (Cross-tenant access blocked: 403 Forbidden)
         │
         ▼
[ Multi-Tenant SQLite Database (synthetic_upstream.db) ]
         │
         ▼  (3) Upstream Response Data
[ Outbound DLP Engine (Egress) ]
   ├── Step 1: Recursive Traversal (Dicts, lists, strings)
   ├── Step 2: Pattern Redaction (SSN, Luhn-valid Credit Cards, API Keys, Secrets)
   ├── Step 3: Fail-Closed Protection (Withholds response on inspection failure -> 502)
   └── Step 4: Metadata Emission (Count & categories reported without leaking secrets)
         │
         ▼  (4) Tamper-Evident Decision Logging
[ Append-Only Audit Store (audit_log.db) ]
   ├── Cryptographic SHA-256 Hash Chaining (previous_hash -> event_hash)
   ├── SQL Triggers Preventing UPDATE and DELETE operations
   └── Strict redaction of credentials, raw payloads, and original secrets
```

---

## 2. Quickstart & Demonstration

### A. One-Command Interactive Security Demo
Run the self-contained demonstration workflow that exercises all 8 security controls in sequence:
```powershell
python scripts/demo.py
```
*(Optionally run against live services using `python scripts/demo.py --live`)*

**The 8 Demonstration Steps:**
1. **Permitted Request (Happy Path)**: Authorized agent reads order within its assigned tenant (`tenant-alpha`).
2. **Perimeter Authentication**: Unauthenticated request is rejected immediately (`401 Unauthorized`).
3. **Deterministic RBAC**: Read-only analyst agent is blocked from creating orders (`403 Forbidden`).
4. **BOLA/Tenant Isolation**: Agent from `tenant-alpha` is blocked from accessing order belonging to `tenant-beta` (`403 Forbidden`).
5. **Ingress Adversarial Heuristics**: Prompt injection / instruction override attempt is blocked before reaching backend (`403 Forbidden`).
6. **Outbound DLP Redaction**: Backend returns synthetic SSN and credit card; proxy redacts them before client response (`200 OK [REDACTED]`).
7. **Structured Audit Trail**: Real-time display of structured security events recorded for each action.
8. **Tamper-Evident Hash Chain**: Standalone verification that all sequential SHA-256 hashes are mathematically intact.

### B. Live Terminal Developer Dashboard
Monitor proxy status, decision totals, reason codes, recent mediation events, evaluation metrics, and audit integrity:
```powershell
# Snapshot view:
python scripts/dashboard.py

# Live auto-refreshing monitor (every 3 seconds):
python scripts/dashboard.py --watch 3
```

### C. Reproducible Security Evaluation
Run the deterministic 16-scenario test battery and generate structured JSON evaluation metrics:
```powershell
python scripts/evaluate_security.py --output evaluation_report.json
```

### D. Audit Chain Verification
Recalculate SHA-256 hashes across the entire audit database to verify tamper-evidence:
```powershell
python scripts/verify_audit.py
```

### E. Run Full Pytest Suite (61 Tests)
```powershell
pytest -v
```

All 61 tests execute with zero warnings (including strict resource leak and deprecation checks).

---

## 3. Containerization with Docker & Docker Compose

The repository includes enterprise-grade containerization configuration ensuring zero-trust network boundaries and minimal privilege.

### A. Network Isolation Architecture
In Docker Compose, the backend service is completely private:
- `upstream` is placed exclusively on an internal bridge network (`proxy-net`). Its port (`8001`) is **not published to the host machine**.
- `proxy` is the sole entry point and is bound exclusively to the host loopback interface (`127.0.0.1:8000`), preventing external exposure.
- Even if an attacker scans host ports, the upstream backend is unreachable except through proxy mediation.

### B. Container Hardening
- **Python 3.13-slim Base**: Minimal attack surface without unnecessary build tools.
- **Unprivileged User**: Runs as `appuser:1001` with `no-new-privileges:true`.
- **Persistent Named Volumes**: `agentic_proxy_audit_data` and `agentic_proxy_upstream_data` persist SQLite databases safely in `/data`.
- **Health Checks**: Standalone healthchecks verify service readiness via standard Python `urllib` without external dependencies like `curl`.

### C. Docker Commands
```powershell
# Build and start services in the background:
docker compose up --build -d

# Check service status and health:
docker compose ps

# View live proxy and upstream logs:
docker compose logs -f

# Shut down and remove containers:
docker compose down
```

---

## 4. Environment Configuration

Copy `.env.example` to `.env` to customize settings:
```powershell
cp .env.example .env
```

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PROXY_HOST` | `127.0.0.1` | Loopback binding for the proxy gateway (`0.0.0.0` inside Docker). |
| `PROXY_PORT` | `8000` | Port for the proxy service. |
| `UPSTREAM_BASE_URL` | `http://127.0.0.1:8001` | Upstream mock backend URL (`http://upstream:8001` in Docker). |
| `UPSTREAM_CONNECT_TIMEOUT_SEC` | `2.0` | Connection timeout in seconds. |
| `UPSTREAM_READ_TIMEOUT_SEC` | `5.0` | Read timeout in seconds. |
| `INTERNAL_SERVICE_KEY` | `dev-proxy-internal-service-key-998877` | Shared secret authenticating proxy to upstream. |
| `AUDIT_DB_PATH` | `audit_log.db` | Path to append-only SQLite audit database (`/data/audit_log.db` in Docker). |
| `UPSTREAM_DB_PATH` | `synthetic_upstream.db` | Path to upstream database (`/data/synthetic_upstream.db` in Docker). |

---

## 5. Tamper-Evident Audit Trail

### A. Audit Event Schema
Every mediation decision is atomically committed to an append-only SQLite database (`audit_log.db`):

| Field | Type | Description |
| :--- | :--- | :--- |
| `event_id` | `TEXT` | Unique event identifier (e.g. `evt-4377af293206`). |
| `timestamp_utc` | `TEXT` | Timezone-aware UTC timestamp in ISO-8601 format. |
| `request_id` | `TEXT` | Ingress request ID or correlated error identifier. |
| `agent_id` | `TEXT` | Server-resolved identity (`None` if unauthenticated). |
| `role` | `TEXT` | Server-resolved role (`None` if unauthenticated). |
| `tenant_id` | `TEXT` | Server-resolved tenant boundary (`None` if unauthenticated). |
| `action` | `TEXT` | Constrained action name (`get_order_details`, `create_order`). |
| `decision` | `TEXT` | Categorical decision: `ALLOWED`, `DENIED`, `BLOCKED`, `SANITIZED`, `ERROR`. |
| `reason_code` | `TEXT` | Machine-readable reason (e.g. `ACTION_SUCCESS`, `ERR_RBAC_FORBIDDEN`, `ERR_BOLA_VIOLATION`, `ERR_INPUT_POLICY`, `DLP_REDACTED`). |
| `rule_id` | `TEXT` | Ingress detector rule ID (e.g. `INPUT_INSTRUCTION_OVERRIDE`). |
| `http_status` | `INTEGER` | HTTP status code returned to the calling client. |
| `upstream_status` | `INTEGER` | HTTP status code received from upstream backend. |
| `latency_ms` | `REAL` | Elapsed processing latency in milliseconds. |
| `redaction_count` | `INTEGER` | Number of sensitive elements redacted by egress DLP. |
| `redaction_categories`| `TEXT` | Comma-separated list of redacted types (`SSN`, `CREDIT_CARD`, etc.). |
| `previous_hash` | `TEXT` | SHA-256 hash of the preceding event (`0000...0000` for genesis). |
| `event_hash` | `TEXT` | Canonical SHA-256 hash of this event's attributes and `previous_hash`. |

### B. What is Deliberately Excluded
To prevent the audit log from becoming a data leakage vector:
- **No Bearer Tokens or Passwords**: Caller tokens are verified in memory and never logged to disk.
- **No Internal Service Credentials**: Backend service keys are strictly excluded.
- **No Raw Payloads or SQL Text**: Blocked request bodies and injected prompts are never stored.
- **No Unredacted Secrets**: Upstream responses containing PII or keys are sanitized before metadata emission.

### C. Immutability & Hash Chain Verification
- **Database Triggers**: SQLite triggers actively reject `UPDATE` and `DELETE` operations on the `audit_events` table (`RAISE(FAIL, 'Audit records are append-only...')`).
- **Cryptographic Hash Chain**: Every event incorporates the hash of the preceding event. A verification script iterates through the entire log, recomputing canonical hashes to detect any modified, inserted, or deleted records.

---

## 6. Continuous Integration (GitHub Actions)

The repository includes a strict CI pipeline in `.github/workflows/ci.yml`:
- **Least Privilege**: Restricted token permissions (`permissions: contents: read`).
- **Multi-Version Matrix**: Tests against Python 3.11, 3.12, and 3.13 on `ubuntu-latest`.
- **Automated Verification**:
  1. Executes full pytest suite (61 tests) under strict warning controls.
  2. Runs reproducible security evaluation runner and publishes evaluation report as CI artifact (`--audit-db ci_audit.db`).
  3. Verifies cryptographic audit chain integrity (`--db ci_audit.db --min-events 14`).
  4. Validates Docker Compose configuration (`docker compose config`) and tests image builds (`docker compose build`).

---

## 7. Security Evaluation Metrics

The evaluation runner executes a deterministic battery of **16 benign and adversarial scenarios**:

```
================================================================================
AGENTIC API SECURITY PROXY — SECURITY EVALUATION REPORT
================================================================================
Timestamp:       2026-10-21T15:00:45Z
Total Scenarios: 16 | Passed: 16 | Failed: 0
Outcome Match Rate:           100.0%
Attack-Case Block Rate:       100.0% (Defined test battery)
Benign False-Rejection Rate:  0.0%
Audit Hash-Chain Verified:    True (14 events)
Evaluation Latency:           mean=8.32ms, median=5.5ms (N=16)
--------------------------------------------------------------------------------
Case ID    | Category           | Status | Latency  | Description
--------------------------------------------------------------------------------
BENIGN-01  | Authorization      | PASS   | 29.0ms   | Authorized support rep reads order in own tenant
BENIGN-02  | Operation          | PASS   | 7.8ms    | Authorized agent creates order within bounds
BENIGN-03  | Heuristic Accuracy | PASS   | 8.3ms    | Ordinary business text containing 'system', 'secret'
BENIGN-04  | RBAC               | PASS   | 6.3ms    | Admin agent successfully accesses tenant resource
ADV-01     | Authentication     | PASS   | 4.6ms    | Unauthenticated request rejected with HTTP 401
ADV-02     | Authentication     | PASS   | 4.6ms    | Invalid token rejected with HTTP 401
ADV-03     | RBAC               | PASS   | 4.8ms    | Readonly analyst blocked from creating orders
ADV-04     | Authorization      | PASS   | 5.8ms    | Cross-tenant access attempt (BOLA/IDOR) blocked
ADV-05     | Identity Isolation | PASS   | 4.6ms    | Client body claims cannot elevate privileges
ADV-06     | Input Safety       | PASS   | 4.8ms    | Adversarial instruction override pattern blocked
ADV-07     | Input Safety       | PASS   | 5.6ms    | Explicit security bypass request blocked
ADV-08     | Input Safety       | PASS   | 5.5ms    | Data exfiltration instruction blocked
ADV-09     | Perimeter Prot.    | PASS   | 0.9ms    | Direct upstream access without service key rejected
ADV-10     | Response DLP       | PASS   | 5.5ms    | Synthetic SSN and credit card in response redacted
ADV-11     | Fail-Closed Safety | PASS   | 5.4ms    | DLP engine fault withholds response (HTTP 502)
ADV-12     | Audit Integrity    | PASS   | 29.8ms   | Tamper-evident hash chain detects modified event
================================================================================
```

### Precise Metric Definitions
- **Outcome Match Rate**: $\frac{\text{Scenarios with Expected Outcome}}{\text{Total Scenarios Executed}} \times 100\%$
- **Attack-Case Block Rate**: $\frac{\text{Correctly Blocked Applicable Attack Cases}}{\text{Total Applicable Attack Cases Evaluated}} \times 100\%$ (Measured against this finite test set)
- **Benign False-Rejection Rate**: $\frac{\text{Benign Cases Incorrectly Blocked}}{\text{Total Benign Cases Evaluated}} \times 100\%$
- **Audit Chain Verified**: Cryptographic verification that all evaluation events form an unbroken sequential hash chain.

---

## 8. Security Disclosures & Known Limitations

> [!WARNING]
> **Limitations & Security Disclosures:**
> 1. **Unkeyed Hash Chain**: The hash chain relies on SHA-256 without a private cryptographic key (HMAC/Asymmetric signature). An attacker with write access to the filesystem could modify past records and recompute the unkeyed hash chain. In production, audit events must be forwarded in real time to an append-only remote SIEM (e.g., AWS CloudWatch, Datadog) or cryptographically anchored using a Hardware Security Module (HSM) or public key signature.
> 2. **Finite Test Set Disclosure**: A 100% block rate on the evaluation suite indicates that the proxy blocks all attacks in the defined test set. It does **not** prove universal immunity against all prompt injection attacks, multi-turn conversational jailbreaks, or novel exfiltration techniques.
> 3. **Heuristic vs. Semantic Inspection**: Regular expression pattern matching on ingress notes catches known override indicators and delimiter injections with zero latency overhead, but can be bypassed by creative semantic paraphrasing. In enterprise architectures, regex heuristic filters should be paired with specialized semantic classifier microservices and fine-grained parameter schema constraints.
> 4. **Demonstration Credentials**: The Bearer tokens in `src/security/identity.py` and the internal service key in `.env.example` are synthetic demonstration secrets for local testing. They must never be used in production.
> 5. **Docker Verification Disclosure**: Container configurations (`Dockerfile`, `docker-compose.yml`) are verified syntactically and built in GitHub Actions CI (`ubuntu-24.04` with Docker Buildx). Host image building was marked `NOT RUN` during local audits on machines lacking a local Docker engine.

---

## 9. Directory Structure

```
Agentic API Security Proxy/
├── .dockerignore                # Container build exclusions
├── .env.example                 # Documented template for local/container environment variables
├── .gitignore                   # Version control ignore rules
├── Dockerfile                   # Multi-service unprivileged container specification
├── docker-compose.yml           # Zero-trust isolated network service orchestration
├── requirements.txt             # Pinned project dependencies
├── README.md                    # Architecture, verification & deployment documentation
├── evaluation_report.example.json # Sanitized reference evaluation output (committed)
├── synthetic_upstream.db        # Multi-tenant SQLite database (local; gitignored)
├── audit_log.db                 # Tamper-evident append-only audit trail (local; gitignored)
├── evaluation_report.json       # Security evaluation runner output (local; gitignored)
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions multi-python test & build workflow
├── config/
│   └── policies.yaml            # Deterministic RBAC role permissions
├── src/
│   ├── __init__.py
│   ├── proxy/
│   │   ├── __init__.py
│   │   ├── app.py               # Proxy FastAPI service (:8000)
│   │   ├── client.py            # Async HTTPX client with timeouts & service key
│   │   └── config.py            # Configuration (environment variables & defaults)
│   ├── security/
│   │   ├── __init__.py
│   │   ├── identity.py          # Demonstration credential registry & Bearer token resolver
│   │   ├── policy.py            # Deterministic PolicyEngine loading policies.yaml
│   │   ├── authorizer.py        # SecurityAuthorizer for RBAC & BOLA enforcement
│   │   ├── sanitizer.py         # Ingress request inspection & adversarial heuristics
│   │   ├── dlp.py               # Egress DLP engine & sensitive data redaction
│   │   └── audit.py             # Tamper-evident append-only audit logger & verifier
│   ├── upstream/
│   │   ├── __init__.py
│   │   ├── app.py               # Mock Upstream FastAPI service (:8001)
│   │   └── store.py             # Parameterized SQLite multi-tenant synthetic data store
│   └── schemas/
│       ├── __init__.py
│       ├── action.py            # AgentActionRequest, ProxyActionResponse, ActionType
│       └── order.py             # OrderCreate, OrderRecord (tenant-bound)
├── tests/
│   ├── conftest.py              # Shared async test fixtures & ASGI transports
│   ├── test_audit_and_evaluation.py # Audit logging, hash-chain & evaluation tests
│   ├── test_input_inspection.py # Ingress safety & adversarial prompt tests
│   ├── test_response_dlp.py     # Outbound DLP & recursive redaction tests
│   ├── test_auth_and_rbac.py    # Authentication & RBAC test battery
│   ├── test_tenant_isolation.py # BOLA & cross-tenant isolation tests
│   ├── test_upstream_boundary.py# Proxy-to-upstream credential & short-circuit tests
│   ├── test_forwarding.py       # End-to-end forwarding tests
│   ├── test_validation.py       # Schema enforcement, SSRF & traversal rejections
│   ├── test_health.py           # Service health endpoint checks
│   └── test_error_handling.py   # Network faults, connection drops, and timeouts
└── scripts/
    ├── demo.py                  # One-command interactive 8-step security demonstration
    ├── dashboard.py             # Terminal security & audit monitoring dashboard
    ├── evaluate_security.py     # Reproducible adversarial security evaluation runner
    ├── verify_audit.py          # Cryptographic hash chain verification tool
    ├── view_audit.py            # Audit log viewer and filter CLI
    ├── smoke_test.py            # Live end-to-end smoke test script across ports 8000 and 8001
    └── reset_db.py              # Database reset and seed utility
```
