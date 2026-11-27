# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

RiskView (repository name: DeepSec) is a security monitoring SaaS for small businesses: it watches customers' websites, public assets, known vulnerabilities and signs of data leaks, notifies on findings, and sends monthly reports. The user writes in Japanese; documents and UI text are Japanese.

`docs/DESIGN.md` is the approved design and the source of truth for architecture, adopted/rejected OSS, external data sources and constraints. Read the relevant section before implementing a feature, and update it when a decision changes.

Status: only implementation step 1 (database) of the 16 steps in DESIGN.md §15 is done. `web-mock/admin-mock.html` is a standalone UI mock with fake data, not the real admin console. `docs/proposal/` holds a business proposal deck (not code).

## Commands

Requires Node.js 22.18+ (TypeScript files run directly via Node's type stripping; there is no build step) and PostgreSQL 16+ server binaries (`initdb`, `pg_ctl`) for the DB tests.

```bash
npm run test:db                                      # start a throwaway PostgreSQL, migrate, run test/db
npm run test:db -- --test-name-pattern="scanner"     # run a single DB test (args are forwarded to node --test)
MIGRATION_DATABASE_URL=postgres://owner@host/db npm run migrate   # apply migrations with the owner role
```

`npm test` alone fails until non-DB tests exist: the DB tests throw without `TEST_DATABASE_URL`, which `scripts/test-db.sh` sets. There is no linter configured.

## Architecture

Planned (DESIGN.md §1, §5): a lightweight browser admin console, an API server (Hono), PostgreSQL, and queue workers, on two free-tier VMs. The **core VM** holds the DB, API, light checks, notifications and reports. The **scan VM** runs Nuclei/ZAP/subfinder/Gitleaks and the Tor fetcher, and must never hold customer data or secrets. Client PCs only run a browser; all monitoring, PDF and CSV generation happen server-side.

### Database (`db/migrations/`)

- Migrations are plain SQL applied in filename order by `scripts/migrate.ts`, each in a transaction, tracked by checksum in `schema_migrations`. **Never edit an applied migration** (the runner refuses a changed checksum); add a new numbered file.
- Tenant isolation is enforced by RLS in `0002_rls.sql`, per database role:
  - `app_api`: API. Each request runs in a transaction that sets `app.user_id`, `app.tenant_id` and `app.role` via `set_config(..., true)`. `app.can_access_tenant()` always re-checks `tenant_members`, so a claimed tenant or role without membership yields no rows.
  - `app_worker`: core-VM workers (`app.role = 'worker'`). Queues are cross-tenant, but tenant data may only be written for the tenant the job is bound to (`app.tenant_id`).
  - `app_scanner`: scan-VM workers. Can only claim medium/heavy jobs and insert `scan_results` for a job it is running. It cannot read tenants, users, findings or settings; scan targets come only from `app.scan_target(job_id)`.
  - The owner/migration role bypasses RLS and must never be used by application code.
- Every new table needs RLS enabled (a test asserts this), `tenant_id` if it holds customer data, and explicit grants and policies for each role that touches it.
- `scan_results.outcome` is `ok` / `finding` / `error`. A failed check is `error` with an `error_category` and must never be treated as "nothing found" (DESIGN.md §6-3).
- `security_events` are de-duplicated by `(tenant_id, fingerprint)`. `state` (new/ongoing/resolved) is set by the system; `status` is the human handling status.
- `audit_logs` is append-only (triggers reject UPDATE/DELETE/TRUNCATE, even by the owner) and hash-chained; `app.audit_logs_first_broken()` verifies the chain.

### Tests (`test/db/rls.test.ts`)

Tests run against a real PostgreSQL. The `as(dbRole, ctx, fn)` helper switches to an app role with a request context inside a transaction that is rolled back. Add an isolation test for every new tenant-scoped table or policy.

## Rules from the spec that constrain implementation

- Only OSS under MIT, Apache-2.0, BSD-2/3-Clause, ISC or the PostgreSQL License may be built in. No GPL/AGPL code (Wazuh, Greenbone, RansomLook's code and TorBot were rejected), and no service that needs a paid contract or written approval (HIBP, ransomware.live, SNS APIs). Noto Sans JP (OFL) is approved for PDFs.
- Scan only domains that are `verified` and whose customer consented; check again right before each scan. Nuclei templates are allowlisted (informational and low-impact only).
- Never store leaked credentials, passwords or raw leak data; store masked values, source, time and summary only.
- Never claim complete coverage ("ダークウェブ全体を監視", "すべての漏洩を検知", "完全リアルタイム", "安全"/"問題なし") in UI, reports or notifications.
- No prices, fees or billing anywhere in the system; plans (BASIC/STANDARD/PREMIUM) control features only, via `plan_features`.
- All outbound requests from workers go through an SSRF guard (DESIGN.md §11): resolve and validate IPs, pin the connection to the checked IP, re-check every redirect.
- The admin console must stay light enough for a PC with 4GB RAM or less: plain HTML/CSS/JS, paginated queries, no heavy client libraries.
