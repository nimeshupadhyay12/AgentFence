# AgentFence v2 – what changed and why

This document lists every change made in the v2 hardening pass, grouped by theme, with the
weakness it addresses. Numbers in brackets refer to the review findings of the v1 code.

Before → after: **20 → 110 tests**, **10 → 18 attack simulations** (each now asserts the control
it targets), CI added, management API authenticated.

## 1. Test isolation and self-seeding simulations [9]

* `backend/tests/conftest.py` points `AGENTFENCE_DATA_DIR`/`DATABASE_URL` at a throwaway directory
  *before* any app module is imported, so `pytest` no longer wipes the demo database.
* `scripts/run_simulations.py` seeds an empty database itself (v1 crashed at attack 7 on a fresh
  checkout) and exits non-zero on any failure, so CI can use it.

## 2. Authentication and secrets [3]

| Before | After | Where |
|---|---|---|
| `POST /auth/login` issued a token for any existing username or agent id, no credential | Users log in with a password, agents with a client secret; both stored as **Argon2id** hashes; unknown users cost the same time (dummy verify); login is rate-limited and audited | `core/auth.py`, `core/security.py`, `api/routes.py` |
| JWT secret hard-coded in the public repo | No default: `AGENTFENCE_ENV=prod` refuses to start without `AGENTFENCE_SECRET_KEY`/`AGENTFENCE_SIGNING_KEYS`; keys < 32 bytes and the old public value are rejected; dev generates a random key in the gitignored data dir | `core/config.py` |
| Demo passwords | Randomly generated per principal (or `AGENTFENCE_DEMO_PASSWORD`) and written to the gitignored `backend/data/demo_credentials.json` | `database/seed.py` |
| 60-minute tokens, no `kid`, any claim set accepted | 15-minute tokens; `kid` header with key-ring rotation; algorithm pinned (alg=none / alg switching rejected before verification); required claims `iss sub aud exp nbf iat jti tid token_use`; 30 s leeway | `core/security.py` |
| Delegation credentials could be presented as identity tokens | `token_use` claim separates the two | `core/security.py` |
| Role and tenant trusted from the token | Principal re-loaded from the DB on each request (must exist, be active, same tenant; role from DB) | `core/auth.py` |
| No logout | `POST /auth/logout` puts the token's `jti` on a denylist (`revoked_tokens`) until it expires | `core/auth.py` |

## 3. Management API authorization [1]

* Every `/api/v1` endpoint except `health` and `auth/login` requires a token, enforced by one
  `@endpoint(admin=..., platform_admin=...)` decorator **before** the handler runs; every 401/403
  raised by the decorator is written to the audit chain (`api.access_denied`). Refusals raised
  inside handlers are audited under their own event types, and some object-level 404s (e.g.
  toggling a foreign policy) are not audited yet.
* Function-level roles: tenant admin (policies, audit, metrics, approvals decisions), platform
  admin (tool registration, simulations, audit export). Object-level scoping inside handlers:
  tenant admins only see/modify their own tenant; non-admins only see delegations they issued,
  received or originated. Missing and foreign objects both return 404 (no probing).
* Delegation lists never contain the bearer credential. Only a SHA-256 fingerprint is stored; the
  credential is returned once, in the creation response.
* CORS is an explicit origin list (was `*` with credentials), security headers added
  (`nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store`).
* The OpenAPI document is generated from the same route table and shows the auth level per route.

## 4. Delegation authority [2]

* The delegator is the authenticated caller and the tenant is the caller's tenant;
  `delegating_agent_id`, `tenant_id`, `permitted_actions` and `audience` in the body are ignored
  and reported back as `ignored_fields` (v1 accepted `"delegating_agent_id": "nobody_checked"`).
* Root delegations: only users, and only for tool/resource pairs the policy engine would allow the
  user directly ("you cannot delegate what you do not hold"). Agents can only re-delegate a grant
  issued to them; attenuation covers tools, resources ("unrestricted" counts as wider), expiry,
  depth and single-use parents.
* `MAX_DELEGATION_DEPTH` and `MAX_DELEGATION_TTL` are now enforced (they were defined but unused).
* Revocation is permitted to the tenant admin, platform admin, original user or delegator, is audited and
  cascades (descendants fail chain verification). Chain verification also checks that each link
  was issued by the recipient of its parent.

## 5. Server-derived authorization context [4]

* `MCPTool.action` and `MCPTool.resource_param` define the action and the protected resource; the
  gateway no longer reads `arguments["action"]` or a client-supplied audience.
* Arguments are validated against the tool's JSON schema (types, enums, ranges, patterns, length,
  **no undeclared parameters**, 16 KiB cap) before any authorization decision
  (`gateway/tool_guard.py`).

## 6. Replay protection [5]

* Durable and atomic: a single-use credential is burned by inserting its `jti` into
  `replay_identifiers` (UNIQUE) **and** a conditional `UPDATE ... WHERE is_consumed = 0`, in one
  transaction. It works across threads, worker processes and restarts (v1 used an unlocked
  in-memory dict). Consumption happens only after the delegation, policy and chain-wide checks
  passed, so a call denied by those checks does not burn the credential. Known edge case: for a
  delegated call that also needs human approval, the single-use grant is consumed just before the
  approval is marked USED, so losing a race on the approval burns the grant.
* Identity tokens: 15-minute lifetime + `jti` revocation instead of reusable 60-minute tokens.
* `UPSTREAM_ALLOWLIST` is now used (see 9).

## 7. Audit trail [6]

* `record_hash = SHA-256(canonical JSON of every stored data field incl. details and previous hash)`
  (21 of 22 columns; only the auto-increment `seq` key is excluded, and order is still protected by
  the previous-hash pointer);
  v1 hashed only 11 fields, so editing `attack_classification` or `execution_outcome` went unnoticed.
* `previous_record_hash` is UNIQUE, so two concurrent writers cannot fork the chain (the loser
  retries on the new head).
* New event types: `auth.login`, `auth.logout`, `delegation.create` (allow and reject),
  `delegation.revoke`, `policy.toggle`, `approval.decision`, `tool.register`, `api.access_denied`,
  plus `reason_code` on every event. v1 attacks 3 and 8 left no record; now they do.
* Tests tamper with each of 20 hashed fields in turn (the chain pointer is covered by the
  delete-record test), and delete a record, and require verification to fail.
* Existing chains: a pre-v2 database is moved aside on first start in dev mode
  (`agentfence.db.v1-<timestamp>.bak`) rather than re-chained, so the original evidence is
  untouched; `scripts/audit_cli.py verify-legacy <file>` still verifies it with the v1 algorithm.
  Outside dev mode the gateway refuses to start on an old schema instead of guessing.

## 8. Simulations and the confused deputy [7, 8]

* Each scenario asserts the **specific** reason code of the control it targets and links the audit
  event returned by the decisive request (v1 picked a random event: it sorted by a random id).
* Attack 9 now reaches the delegation tool-scope check (`UNAUTHORIZED_TOOL_EXECUTION`) instead of
  being stopped by default deny.
* Real confused deputy (attack 1): the low-privilege plugin holds a grant for a SECRET document it
  is not allowed to read, re-delegates it to the privileged coordinator, and the coordinator makes
  the call. New **chain-wide authorization** (pipeline step 7) evaluates the policy for every
  delegator in the chain and blocks it (`AUTHZ_CONFUSED_DEPUTY_BLOCKED`); a control call by the
  coordinator on its own grant is allowed. The hard-coded `admin_override` role rule was removed.
* `admin_override` allow path: tenant admins are allowed by policy; the tool is critical so it
  requires approval by a different administrator (attack 18 and `test_admin_override_allow_path...`).
* New scenarios 11–18: identity-token replay after logout, forged identity tokens (alg=none and
  the old public secret), tool poisoning, argument smuggling, rate-limit abuse, management-API
  abuse, delegating authority you don't hold, approval bypass. All mapped to OWASP Top 10 for LLM
  Applications 2025 / OWASP API Security Top 10 2023.
* Dashboard bug: results were matched with `key.includes('attack_1')`, so attack 10's result was
  shown in attack 1's row. The lab now loads the catalog from the API and keys results exactly.

## 9. MCP gateway and upstreams [10]

* `tools/list` requires authentication and is **filtered per caller** (policy discovery check,
  quarantine, and the presented delegation's tool scope).
* JSON-RPC fixes: notifications get no response (HTTP 202), invalid envelopes return `-32600`,
  `ping` supported, unauthenticated `tools/list` returns `-32001` with HTTP 401; gateway decision,
  reason code and audit id are returned in `result._meta.agentfence`.
* Optional real upstream: tools whose `upstream_endpoint` is `http(s)://` are forwarded as JSON-RPC
  `tools/call` if the origin is in `AGENTFENCE_UPSTREAM_ALLOWLIST` (checked at registration and at
  call time); caller tokens are never forwarded. `scripts/sample_upstream_mcp.py` is a minimal
  real MCP server used by an end-to-end test (the test runs it in-process through Starlette's test
  transport, not over a network socket). The in-process mock remains the default.
* Tool registration (`POST /api/v1/tools`) scans names, descriptions and schema descriptions for
  tool-poisoning markers (instruction overrides, hidden tags, concealment, credential
  exfiltration, cross-tool hijacking, invisible Unicode) and stores matches **quarantined**.

## 10. Richer ABAC and runtime controls [11]

* New/used conditions: `resource_owner`, `max_sensitivity`, `max_risk_level`, `min_risk_level`,
  `time_window`, `delegation_max_depth`, `args` (min/max/in/not_in/pattern/max_length/path_prefix),
  `role_in`/`role_not_in`. Unknown or malformed conditions fail closed (an ALLOW never matches, a
  DENY always does). Deny-overrides semantics.
* Seed policies demonstrate them: plugin agents can never use high/critical tools (DENY,
  `min_risk_level`), analysts read up to `confidential`, Beta researchers read only documents
  they own, search limits capped through `args`.
* Human-in-the-loop approvals (`gateway/approvals.py`): bound to requester, tenant, tool and
  SHA-256 of the exact arguments; expire; single use; requester cannot approve.
* Per-principal, per-tool sliding-window rate limits (`core/ratelimit.py`).

## 11. Dashboard

Login screen, bearer token on every call, automatic return to login on 401, server-side logout,
role-aware tabs, delegation creation as the signed-in principal with one-time credential display,
Approvals page, event-type filter and reason codes in the audit view, quarantine/approval badges
in the registry, catalog-driven attack lab.

## 12. CI and tooling

* `.github/workflows/ci.yml`: pytest, attack simulations on a fresh DB, prod-without-key refusal
  check, `npm ci && npm run build` (TypeScript type-check + Vite build).
* `scripts/audit_cli.py` (verify / verify-legacy / export), `scripts/sample_upstream_mcp.py`, the
  screenshot script now signs in.

## Known limitations (not done)

* stdio / SSE upstream transports; HS256 instead of asymmetric keys or an external IdP.
* SQLite and per-process rate limiting (fine for a demo, not for a cluster).
* External anchoring of the audit-chain head (needed to resist a full-database rewrite).
* README screenshots still show the v1 UI (`scripts/capture_readme_screenshots.py` can refresh them).
