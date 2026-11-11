-- DeepSec schema. Run by the migration (owner) role only.
-- Application code connects as app_api / app_worker / app_scanner, never as the owner.

CREATE SCHEMA app;

-- Application roles (group roles; deployment creates LOGIN roles that inherit from these).
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['app_api', 'app_worker', 'app_scanner'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOBYPASSRLS', r);
    END IF;
  END LOOP;
END $$;

----------------------------------------------------------------------
-- Tenants, users, membership
----------------------------------------------------------------------

CREATE TABLE tenants (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  contact_name  text,
  email         text,
  phone         text,
  status        text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'terminated')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
  code         text PRIMARY KEY,
  description  text NOT NULL
);

CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           text NOT NULL CHECK (email = lower(email) AND length(email) <= 254),
  display_name    text NOT NULL DEFAULT '',
  password_hash   text NOT NULL,
  mfa_secret_enc  text,
  mfa_enabled     boolean NOT NULL DEFAULT false,
  -- Operator-side role. NULL for customer users (their role lives in tenant_members).
  system_role     text CHECK (system_role IN ('system_admin', 'operator')),
  status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  failed_logins   integer NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  last_login_at   timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (email)
);

-- Customer users: role_code is tenant_admin / tenant_user.
-- Operators: role_code is operator, meaning "assigned to this customer".
CREATE TABLE tenant_members (
  tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role_code   text NOT NULL REFERENCES roles (code)
              CHECK (role_code IN ('operator', 'tenant_admin', 'tenant_user')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX tenant_members_user_idx ON tenant_members (user_id);

CREATE TABLE sessions (
  id_hash       bytea PRIMARY KEY,          -- SHA-256 of the session token; the token itself is never stored
  user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  mfa_verified  boolean NOT NULL DEFAULT false,
  csrf_token    text NOT NULL,
  ip            inet,
  user_agent    text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

----------------------------------------------------------------------
-- Plans (no monetary columns by design)
----------------------------------------------------------------------

CREATE TABLE subscriptions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  plan        text NOT NULL CHECK (plan IN ('BASIC', 'STANDARD', 'PREMIUM')),
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled')),
  started_at  timestamptz NOT NULL DEFAULT now(),
  ended_at    timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX subscriptions_one_active_idx ON subscriptions (tenant_id) WHERE status = 'active';

CREATE TABLE plan_features (
  plan         text NOT NULL CHECK (plan IN ('BASIC', 'STANDARD', 'PREMIUM')),
  feature_key  text NOT NULL,
  enabled      boolean NOT NULL DEFAULT false,
  limits       jsonb NOT NULL DEFAULT '{}',
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (plan, feature_key)
);

----------------------------------------------------------------------
-- Monitoring targets
----------------------------------------------------------------------

CREATE TABLE domains (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  hostname             text NOT NULL
                       CHECK (hostname = lower(hostname)
                              AND hostname ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
                              AND length(hostname) <= 253),
  verification_status  text NOT NULL DEFAULT 'pending'
                       CHECK (verification_status IN ('pending', 'verified', 'failed', 'revoked')),
  -- none: no scanning. standard: information-gathering and low-impact checks.
  -- extended: checks that perform attack-like actions, only with recorded customer approval.
  scan_consent_level   text NOT NULL DEFAULT 'none'
                       CHECK (scan_consent_level IN ('none', 'standard', 'extended')),
  active               boolean NOT NULL DEFAULT true,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, hostname),
  UNIQUE (tenant_id, id)
);

CREATE TABLE domain_verifications (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL,
  domain_id    uuid NOT NULL,
  method       text NOT NULL CHECK (method IN ('dns_txt', 'html_file', 'email', 'manual')),
  token        text,                          -- public challenge value the customer publishes; not a secret
  status       text NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'verified', 'failed', 'expired')),
  verified_at  timestamptz,
  verified_by  uuid REFERENCES users (id),
  expires_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, domain_id) REFERENCES domains (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX domain_verifications_domain_idx ON domain_verifications (tenant_id, domain_id);

-- tenant_id NULL = system-wide default; a tenant row overrides it.
CREATE TABLE monitoring_settings (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid REFERENCES tenants (id) ON DELETE CASCADE,
  key         text NOT NULL,
  value       jsonb NOT NULL,
  updated_by  uuid REFERENCES users (id),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (tenant_id, key)
);

----------------------------------------------------------------------
-- Job queue and execution records
----------------------------------------------------------------------

-- tenant_id NULL = system job (feed sync, backup, housekeeping).
CREATE TABLE monitoring_jobs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid REFERENCES tenants (id) ON DELETE CASCADE,
  domain_id        uuid,
  queue            text NOT NULL CHECK (queue IN ('light', 'medium', 'heavy', 'notify', 'report')),
  job_type         text NOT NULL,
  payload          jsonb NOT NULL DEFAULT '{}',
  status           text NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'timed_out', 'cancelled', 'deferred')),
  priority         integer NOT NULL DEFAULT 0,
  run_at           timestamptz NOT NULL DEFAULT now(),
  attempts         integer NOT NULL DEFAULT 0,
  max_attempts     integer NOT NULL DEFAULT 3 CHECK (max_attempts >= 1),
  timeout_seconds  integer NOT NULL DEFAULT 300 CHECK (timeout_seconds > 0),
  locked_by        text,
  locked_at        timestamptz,
  heartbeat_at     timestamptz,
  started_at       timestamptz,
  finished_at      timestamptz,
  error_category   text,
  idempotency_key  text UNIQUE,
  created_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, domain_id) REFERENCES domains (tenant_id, id) ON DELETE CASCADE,
  CHECK (domain_id IS NULL OR tenant_id IS NOT NULL)
);
CREATE INDEX monitoring_jobs_claim_idx ON monitoring_jobs (queue, priority DESC, run_at)
  WHERE status IN ('queued', 'deferred');
CREATE INDEX monitoring_jobs_running_idx ON monitoring_jobs (heartbeat_at) WHERE status = 'running';
CREATE INDEX monitoring_jobs_tenant_idx ON monitoring_jobs (tenant_id, created_at DESC);

CREATE TABLE monitoring_job_logs (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id       uuid REFERENCES tenants (id) ON DELETE CASCADE,
  job_id          uuid NOT NULL REFERENCES monitoring_jobs (id) ON DELETE CASCADE,
  level           text NOT NULL CHECK (level IN ('info', 'warn', 'error')),
  error_category  text,
  message         text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX monitoring_job_logs_job_idx ON monitoring_job_logs (job_id, id);

-- One row per check per run. "error" means the check could not be performed
-- and must never be read as "nothing found".
CREATE TABLE scan_results (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  job_id          uuid REFERENCES monitoring_jobs (id) ON DELETE SET NULL,
  domain_id       uuid,
  check_type      text NOT NULL,
  outcome         text NOT NULL CHECK (outcome IN ('ok', 'finding', 'error')),
  error_category  text CHECK (error_category IN
                    ('dns', 'connect', 'tls', 'timeout', 'external_api', 'tool', 'blocked', 'internal')),
  summary         jsonb NOT NULL DEFAULT '{}',
  processed_at    timestamptz,               -- set when findings were turned into security_events
  observed_at     timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, domain_id) REFERENCES domains (tenant_id, id) ON DELETE CASCADE,
  CHECK ((outcome = 'error') = (error_category IS NOT NULL))
);
CREATE INDEX scan_results_tenant_idx ON scan_results (tenant_id, observed_at DESC);
CREATE INDEX scan_results_unprocessed_idx ON scan_results (observed_at) WHERE processed_at IS NULL;

----------------------------------------------------------------------
-- Findings
----------------------------------------------------------------------

CREATE TABLE event_sources (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code              text NOT NULL UNIQUE,
  name              text NOT NULL,
  kind              text NOT NULL CHECK (kind IN ('builtin', 'scanner', 'vuln_feed', 'public_web', 'leak_feed', 'tor')),
  min_plan          text NOT NULL DEFAULT 'BASIC' CHECK (min_plan IN ('BASIC', 'STANDARD', 'PREMIUM')),
  attribution_text  text,                    -- notice we are required to display for this source
  coverage_note     text,                    -- scope, update frequency and delay, shown to customers
  active            boolean NOT NULL DEFAULT true
);

CREATE TABLE security_events (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  domain_id         uuid,
  event_type        text NOT NULL,
  severity          text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  source_id         uuid NOT NULL REFERENCES event_sources (id),
  title             text NOT NULL,
  detail            text NOT NULL DEFAULT '',  -- summary only; never raw leaked data or credentials
  url               text,
  confidence        text NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
  recommendation    text NOT NULL DEFAULT '',
  -- Handling status set by people: 未対応 / 対応中 / 対応済み / 誤検知 / 保留
  status            text NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'in_progress', 'resolved', 'false_positive', 'on_hold')),
  -- Detection state set by the system: 新規 / 継続 / 解消
  state             text NOT NULL DEFAULT 'new' CHECK (state IN ('new', 'ongoing', 'resolved')),
  assignee_id       uuid REFERENCES users (id),
  fingerprint       bytea NOT NULL,           -- hash of (type, target, normalized key) for de-duplication
  occurrence_count  integer NOT NULL DEFAULT 1,
  first_seen_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at      timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz,
  FOREIGN KEY (tenant_id, domain_id) REFERENCES domains (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, fingerprint),
  UNIQUE (tenant_id, id)
);
CREATE INDEX security_events_list_idx ON security_events (tenant_id, last_seen_at DESC);
CREATE INDEX security_events_open_idx ON security_events (severity, last_seen_at DESC)
  WHERE status IN ('open', 'in_progress');

CREATE TABLE event_status_histories (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    uuid NOT NULL,
  event_id     uuid NOT NULL,
  from_status  text,
  to_status    text NOT NULL,
  changed_by   uuid REFERENCES users (id),
  note         text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, event_id) REFERENCES security_events (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX event_status_histories_event_idx ON event_status_histories (tenant_id, event_id, id);

----------------------------------------------------------------------
-- Notifications
----------------------------------------------------------------------

-- tenant_id NULL = operator-only system alert that concerns no single customer.
CREATE TABLE notifications (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid REFERENCES tenants (id) ON DELETE CASCADE,
  event_id         uuid,
  audience         text NOT NULL CHECK (audience IN ('operator', 'customer')),
  recipient        text NOT NULL,
  template         text NOT NULL,
  payload          jsonb NOT NULL DEFAULT '{}',
  status           text NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'sending', 'sent', 'failed', 'dead', 'suppressed')),
  attempts         integer NOT NULL DEFAULT 0,
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  dedupe_key       text NOT NULL UNIQUE,
  created_at       timestamptz NOT NULL DEFAULT now(),
  sent_at          timestamptz,
  FOREIGN KEY (tenant_id, event_id) REFERENCES security_events (tenant_id, id) ON DELETE CASCADE,
  CHECK (audience = 'operator' OR tenant_id IS NOT NULL)
);
CREATE INDEX notifications_due_idx ON notifications (next_attempt_at) WHERE status IN ('queued', 'failed');

CREATE TABLE notification_logs (
  id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id            uuid REFERENCES tenants (id) ON DELETE CASCADE,
  notification_id      uuid NOT NULL REFERENCES notifications (id) ON DELETE CASCADE,
  attempt              integer NOT NULL,
  result               text NOT NULL CHECK (result IN ('accepted', 'failed')),
  provider_message_id  text,
  -- Acceptance by the mail provider is not delivery; this is updated from bounce/complaint webhooks.
  delivery_status      text NOT NULL DEFAULT 'unknown'
                       CHECK (delivery_status IN ('unknown', 'delivered', 'bounced', 'complained')),
  error                text,
  created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notification_logs_notification_idx ON notification_logs (notification_id, id);
CREATE INDEX notification_logs_provider_idx ON notification_logs (provider_message_id);

CREATE TABLE email_suppressions (
  email       text PRIMARY KEY CHECK (email = lower(email)),
  reason      text NOT NULL CHECK (reason IN ('bounce', 'complaint', 'manual')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

----------------------------------------------------------------------
-- Reports
----------------------------------------------------------------------

CREATE TABLE report_settings (
  tenant_id           uuid PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
  auto_send           boolean NOT NULL DEFAULT false,
  recipients          text[] NOT NULL DEFAULT '{}',
  cc                  text[] NOT NULL DEFAULT '{}',
  send_day            integer NOT NULL DEFAULT 1 CHECK (send_day BETWEEN 1 AND 28),
  send_time           time NOT NULL DEFAULT '09:00',
  timezone            text NOT NULL DEFAULT 'Asia/Tokyo',
  attach_pdf          boolean NOT NULL DEFAULT true,
  -- Recipient changes stay here until confirmed.
  pending_recipients  text[],
  pending_cc          text[],
  confirm_token_hash  bytea,
  confirm_expires_at  timestamptz,
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE monthly_reports (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  period_start  date NOT NULL,
  period_end    date NOT NULL,
  status        text NOT NULL DEFAULT 'generating'
                CHECK (status IN ('generating', 'generated', 'sent', 'failed')),
  summary       jsonb NOT NULL DEFAULT '{}',
  storage_key   text,
  generated_at  timestamptz,
  sent_at       timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, period_start),
  CHECK (period_end >= period_start)
);

----------------------------------------------------------------------
-- System
----------------------------------------------------------------------

CREATE TABLE external_api_settings (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id               uuid NOT NULL UNIQUE REFERENCES event_sources (id) ON DELETE CASCADE,
  enabled                 boolean NOT NULL DEFAULT false,
  secret_ref              text,              -- name of an environment variable / secret; never the secret itself
  limits                  jsonb NOT NULL DEFAULT '{}',
  usage_terms_checked_at  timestamptz,
  last_ok_at              timestamptz,
  last_error_at           timestamptz,
  last_error              text,
  updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    uuid,                         -- no FK: audit rows must outlive the tenant
  actor_id     uuid,
  actor_role   text,
  action       text NOT NULL,
  target_type  text,
  target_id    text,
  ip           inet,
  meta         jsonb NOT NULL DEFAULT '{}',
  prev_hash    bytea,
  hash         bytea,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_tenant_idx ON audit_logs (tenant_id, id DESC);

CREATE TABLE system_logs (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  level       text NOT NULL CHECK (level IN ('info', 'warn', 'error')),
  component   text NOT NULL,
  message     text NOT NULL,
  meta        jsonb NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX system_logs_created_idx ON system_logs (created_at DESC);

----------------------------------------------------------------------
-- Audit log: append-only and hash-chained
----------------------------------------------------------------------

CREATE FUNCTION app.audit_logs_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  prev bytea;
BEGIN
  -- Serialize inserts so every row links to the true predecessor.
  PERFORM pg_advisory_xact_lock(hashtext('audit_logs_chain'));
  SELECT hash INTO prev FROM audit_logs ORDER BY id DESC LIMIT 1;
  NEW.created_at := clock_timestamp();
  NEW.prev_hash := prev;
  NEW.hash := sha256(
    coalesce(prev, ''::bytea) ||
    convert_to(
      concat_ws('|', NEW.id, NEW.tenant_id, NEW.actor_id, NEW.actor_role, NEW.action,
                NEW.target_type, NEW.target_id, host(NEW.ip), NEW.meta::text,
                to_char(NEW.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')),
      'UTF8'));
  RETURN NEW;
END $$;

CREATE TRIGGER audit_logs_chain BEFORE INSERT ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION app.audit_logs_chain();

CREATE FUNCTION app.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION app.reject_change();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION app.reject_change();

-- Returns the id of the first row whose hash does not match, or NULL when the chain is intact.
CREATE FUNCTION app.audit_logs_first_broken() RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  r audit_logs%ROWTYPE;
  prev bytea := NULL;
  expected bytea;
BEGIN
  FOR r IN SELECT * FROM audit_logs ORDER BY id LOOP
    expected := sha256(
      coalesce(prev, ''::bytea) ||
      convert_to(
        concat_ws('|', r.id, r.tenant_id, r.actor_id, r.actor_role, r.action,
                  r.target_type, r.target_id, host(r.ip), r.meta::text,
                  to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')),
        'UTF8'));
    IF r.prev_hash IS DISTINCT FROM prev OR r.hash IS DISTINCT FROM expected THEN
      RETURN r.id;
    END IF;
    prev := r.hash;
  END LOOP;
  RETURN NULL;
END $$;
