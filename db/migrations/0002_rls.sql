-- Tenant isolation.
--
-- Every request/job runs in a transaction that sets:
--   app.user_id   - authenticated user (API only)
--   app.tenant_id - tenant the request/job acts on, chosen by server code after verifying membership
--   app.role      - system_admin | operator | tenant_admin | tenant_user | service | worker
-- "service" is used by the API for its own work before a user context exists (login, session lookup, webhooks).
--
-- The table owner (migration role) is not subject to RLS and is never used by application code.

CREATE FUNCTION app.ctx_user() RETURNS uuid LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;
CREATE FUNCTION app.ctx_tenant() RETURNS uuid LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;
CREATE FUNCTION app.ctx_role() RETURNS text LANGUAGE sql STABLE AS
  $$ SELECT coalesce(nullif(current_setting('app.role', true), ''), 'none') $$;

-- SECURITY DEFINER so the membership lookup is not itself filtered by the tenant_members policy.
CREATE FUNCTION app.can_access_tenant(t uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT CASE app.ctx_role()
    WHEN 'system_admin' THEN true
    WHEN 'operator' THEN t IS NOT NULL AND EXISTS (
      SELECT 1 FROM tenant_members m
      WHERE m.tenant_id = t AND m.user_id = app.ctx_user() AND m.role_code = 'operator')
    WHEN 'tenant_admin' THEN t IS NOT NULL AND t = app.ctx_tenant() AND EXISTS (
      SELECT 1 FROM tenant_members m
      WHERE m.tenant_id = t AND m.user_id = app.ctx_user() AND m.role_code = 'tenant_admin')
    WHEN 'tenant_user' THEN t IS NOT NULL AND t = app.ctx_tenant() AND EXISTS (
      SELECT 1 FROM tenant_members m
      WHERE m.tenant_id = t AND m.user_id = app.ctx_user() AND m.role_code IN ('tenant_admin', 'tenant_user'))
    ELSE false
  END
$$;

CREATE FUNCTION app.can_write_tenant(t uuid) RETURNS boolean LANGUAGE sql STABLE AS
  $$ SELECT app.ctx_role() <> 'tenant_user' AND app.can_access_tenant(t) $$;

CREATE FUNCTION app.is_admin() RETURNS boolean LANGUAGE sql STABLE AS
  $$ SELECT app.ctx_role() = 'system_admin' $$;
CREATE FUNCTION app.is_worker() RETURNS boolean LANGUAGE sql STABLE AS
  $$ SELECT app.ctx_role() = 'worker' $$;

GRANT USAGE ON SCHEMA app TO app_api, app_worker, app_scanner;

----------------------------------------------------------------------
-- Enable RLS on every table
----------------------------------------------------------------------

DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'schema_migrations' LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;

----------------------------------------------------------------------
-- app_api
----------------------------------------------------------------------

-- Tenant-owned tables: read if the caller may access the tenant, write unless read-only customer user.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'domains', 'domain_verifications', 'monitoring_jobs', 'monitoring_job_logs', 'scan_results',
    'security_events', 'event_status_histories', 'notifications', 'notification_logs',
    'report_settings', 'monthly_reports'
  ] LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO app_api', t);
    EXECUTE format('CREATE POLICY api_read ON %I FOR SELECT TO app_api USING (app.can_access_tenant(tenant_id))', t);
    EXECUTE format('CREATE POLICY api_insert ON %I FOR INSERT TO app_api WITH CHECK (app.can_write_tenant(tenant_id))', t);
    EXECUTE format('CREATE POLICY api_update ON %I FOR UPDATE TO app_api USING (app.can_write_tenant(tenant_id)) WITH CHECK (app.can_write_tenant(tenant_id))', t);
    EXECUTE format('CREATE POLICY api_delete ON %I FOR DELETE TO app_api USING (app.can_write_tenant(tenant_id))', t);
  END LOOP;
END $$;

-- Tenant-owned tables only a system administrator may change.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, subscriptions, tenant_members TO app_api;
CREATE POLICY api_read ON tenants FOR SELECT TO app_api USING (app.can_access_tenant(id));
CREATE POLICY api_admin_write ON tenants FOR ALL TO app_api USING (app.is_admin()) WITH CHECK (app.is_admin());
CREATE POLICY api_read ON subscriptions FOR SELECT TO app_api USING (app.can_access_tenant(tenant_id));
CREATE POLICY api_admin_write ON subscriptions FOR ALL TO app_api USING (app.is_admin()) WITH CHECK (app.is_admin());
-- Membership: visible to those who can access the tenant; also to "service" so the API can resolve a user's tenants at login.
CREATE POLICY api_read ON tenant_members FOR SELECT TO app_api
  USING (app.can_access_tenant(tenant_id) OR app.ctx_role() = 'service' OR user_id = app.ctx_user());
CREATE POLICY api_admin_write ON tenant_members FOR ALL TO app_api USING (app.is_admin()) WITH CHECK (app.is_admin());

-- Settings: system defaults (tenant_id NULL) are readable by any signed-in role, writable by admins.
GRANT SELECT, INSERT, UPDATE, DELETE ON monitoring_settings TO app_api;
CREATE POLICY api_read ON monitoring_settings FOR SELECT TO app_api
  USING ((tenant_id IS NULL AND app.ctx_role() <> 'none') OR app.can_access_tenant(tenant_id));
CREATE POLICY api_write ON monitoring_settings FOR ALL TO app_api
  USING (app.is_admin() OR (tenant_id IS NOT NULL AND app.ctx_role() = 'operator' AND app.can_access_tenant(tenant_id)))
  WITH CHECK (app.is_admin() OR (tenant_id IS NOT NULL AND app.ctx_role() = 'operator' AND app.can_access_tenant(tenant_id)));

-- Users and sessions.
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions TO app_api;
CREATE POLICY api_read ON users FOR SELECT TO app_api USING (
  app.ctx_role() IN ('system_admin', 'service')
  OR id = app.ctx_user()
  OR (app.ctx_role() IN ('operator', 'tenant_admin') AND EXISTS (
        SELECT 1 FROM tenant_members m
        WHERE m.user_id = users.id AND m.role_code <> 'operator' AND app.can_access_tenant(m.tenant_id))));
CREATE POLICY api_write ON users FOR ALL TO app_api
  USING (app.ctx_role() IN ('system_admin', 'service'))
  WITH CHECK (app.ctx_role() IN ('system_admin', 'service'));
CREATE POLICY api_service ON sessions FOR ALL TO app_api
  USING (app.ctx_role() = 'service') WITH CHECK (app.ctx_role() = 'service');

-- Reference data.
GRANT SELECT, INSERT, UPDATE, DELETE ON roles, plan_features, event_sources, external_api_settings, email_suppressions TO app_api;
CREATE POLICY api_read ON roles FOR SELECT TO app_api USING (app.ctx_role() <> 'none');
CREATE POLICY api_read ON plan_features FOR SELECT TO app_api USING (app.ctx_role() <> 'none');
CREATE POLICY api_read ON event_sources FOR SELECT TO app_api USING (app.ctx_role() <> 'none');
CREATE POLICY api_admin_write ON roles FOR ALL TO app_api USING (app.is_admin()) WITH CHECK (app.is_admin());
CREATE POLICY api_admin_write ON plan_features FOR ALL TO app_api USING (app.is_admin()) WITH CHECK (app.is_admin());
CREATE POLICY api_admin_write ON event_sources FOR ALL TO app_api USING (app.is_admin()) WITH CHECK (app.is_admin());
CREATE POLICY api_admin ON external_api_settings FOR ALL TO app_api USING (app.is_admin()) WITH CHECK (app.is_admin());
CREATE POLICY api_admin ON email_suppressions FOR ALL TO app_api
  USING (app.ctx_role() IN ('system_admin', 'service')) WITH CHECK (app.ctx_role() IN ('system_admin', 'service'));

-- Logs: insert-only for the application; no UPDATE/DELETE privilege is granted to anyone.
GRANT SELECT, INSERT ON audit_logs, system_logs TO app_api;
CREATE POLICY api_insert ON audit_logs FOR INSERT TO app_api WITH CHECK (app.ctx_role() <> 'none');
CREATE POLICY api_read ON audit_logs FOR SELECT TO app_api
  USING (app.is_admin() OR (app.ctx_role() = 'operator' AND tenant_id IS NOT NULL AND app.can_access_tenant(tenant_id)));
CREATE POLICY api_insert ON system_logs FOR INSERT TO app_api WITH CHECK (true);
CREATE POLICY api_read ON system_logs FOR SELECT TO app_api USING (app.is_admin());

----------------------------------------------------------------------
-- app_worker (scheduler, light checks, ingest, notify, report) on the core server
----------------------------------------------------------------------

-- Queues are cross-tenant by nature.
GRANT SELECT, INSERT, UPDATE ON monitoring_jobs, notifications TO app_worker;
GRANT SELECT, INSERT ON monitoring_job_logs TO app_worker;
GRANT SELECT, INSERT, UPDATE ON notification_logs TO app_worker;
CREATE POLICY worker_all ON monitoring_jobs FOR ALL TO app_worker USING (app.is_worker()) WITH CHECK (app.is_worker());
CREATE POLICY worker_all ON monitoring_job_logs FOR ALL TO app_worker USING (app.is_worker()) WITH CHECK (app.is_worker());
CREATE POLICY worker_all ON notifications FOR ALL TO app_worker USING (app.is_worker()) WITH CHECK (app.is_worker());
CREATE POLICY worker_all ON notification_logs FOR ALL TO app_worker USING (app.is_worker()) WITH CHECK (app.is_worker());

-- Read-only inputs needed to schedule work across tenants.
GRANT SELECT ON tenants, subscriptions, domains, monitoring_settings, report_settings, plan_features,
  event_sources, roles TO app_worker;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenants', 'subscriptions', 'domains', 'monitoring_settings', 'report_settings',
                           'plan_features', 'event_sources', 'roles'] LOOP
    EXECUTE format('CREATE POLICY worker_read ON %I FOR SELECT TO app_worker USING (app.is_worker())', t);
  END LOOP;
END $$;

-- Tenant data may only be written for the tenant the job is bound to.
GRANT SELECT, INSERT, UPDATE ON scan_results, security_events, monthly_reports, domain_verifications TO app_worker;
GRANT SELECT, INSERT ON event_status_histories TO app_worker;
GRANT UPDATE (verification_status, updated_at) ON domains TO app_worker;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['scan_results', 'security_events', 'monthly_reports', 'domain_verifications',
                           'event_status_histories'] LOOP
    EXECUTE format(
      'CREATE POLICY worker_tenant ON %I FOR ALL TO app_worker
         USING (app.is_worker() AND tenant_id = app.ctx_tenant())
         WITH CHECK (app.is_worker() AND tenant_id = app.ctx_tenant())', t);
  END LOOP;
END $$;
CREATE POLICY worker_update ON domains FOR UPDATE TO app_worker
  USING (app.is_worker() AND tenant_id = app.ctx_tenant())
  WITH CHECK (app.is_worker() AND tenant_id = app.ctx_tenant());
-- Ingest needs to discover which tenants have unprocessed results.
CREATE POLICY worker_unprocessed ON scan_results FOR SELECT TO app_worker
  USING (app.is_worker() AND processed_at IS NULL);

-- Notification recipients: operators, and members of the bound tenant.
GRANT SELECT ON tenant_members TO app_worker;
GRANT SELECT (id, email, display_name, system_role, status) ON users TO app_worker;
CREATE POLICY worker_read ON tenant_members FOR SELECT TO app_worker
  USING (app.is_worker() AND tenant_id = app.ctx_tenant());
CREATE POLICY worker_read ON users FOR SELECT TO app_worker USING (
  app.is_worker() AND (
    system_role IS NOT NULL
    OR EXISTS (SELECT 1 FROM tenant_members m WHERE m.user_id = users.id AND m.tenant_id = app.ctx_tenant())));

GRANT SELECT, UPDATE ON external_api_settings TO app_worker;
CREATE POLICY worker_all ON external_api_settings FOR ALL TO app_worker USING (app.is_worker()) WITH CHECK (app.is_worker());
GRANT SELECT, INSERT ON email_suppressions TO app_worker;
CREATE POLICY worker_all ON email_suppressions FOR ALL TO app_worker USING (app.is_worker()) WITH CHECK (app.is_worker());
GRANT INSERT ON audit_logs, system_logs TO app_worker;
CREATE POLICY worker_insert ON audit_logs FOR INSERT TO app_worker WITH CHECK (app.is_worker());
CREATE POLICY worker_insert ON system_logs FOR INSERT TO app_worker WITH CHECK (true);

----------------------------------------------------------------------
-- app_scanner (scan / dark web workers on the isolated server)
--
-- May only: take jobs from the medium/heavy queues, report their outcome, and write scan results
-- for a job it is running. It cannot read tenants, users, sessions, findings or settings.
----------------------------------------------------------------------

GRANT SELECT ON monitoring_jobs TO app_scanner;
GRANT UPDATE (status, attempts, run_at, locked_by, locked_at, heartbeat_at, started_at, finished_at, error_category)
  ON monitoring_jobs TO app_scanner;
CREATE POLICY scanner_read ON monitoring_jobs FOR SELECT TO app_scanner USING (queue IN ('medium', 'heavy'));
CREATE POLICY scanner_update ON monitoring_jobs FOR UPDATE TO app_scanner
  USING (queue IN ('medium', 'heavy')) WITH CHECK (queue IN ('medium', 'heavy'));

GRANT INSERT ON monitoring_job_logs, scan_results, system_logs TO app_scanner;
CREATE POLICY scanner_insert ON monitoring_job_logs FOR INSERT TO app_scanner WITH CHECK (
  EXISTS (SELECT 1 FROM monitoring_jobs j
          WHERE j.id = job_id AND j.tenant_id IS NOT DISTINCT FROM monitoring_job_logs.tenant_id));
CREATE POLICY scanner_insert ON scan_results FOR INSERT TO app_scanner WITH CHECK (
  processed_at IS NULL AND EXISTS (
    SELECT 1 FROM monitoring_jobs j
    WHERE j.id = job_id AND j.status = 'running' AND j.tenant_id = scan_results.tenant_id
      AND j.domain_id IS NOT DISTINCT FROM scan_results.domain_id));
CREATE POLICY scanner_insert ON system_logs FOR INSERT TO app_scanner WITH CHECK (true);
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_api, app_worker, app_scanner;

-- The only tenant facts a scanner may learn: what it is allowed to scan for a job it holds.
-- Re-checked immediately before every scan so revoked consent takes effect at once.
CREATE FUNCTION app.scan_target(p_job_id uuid)
RETURNS TABLE (hostname text, verified boolean, scan_consent_level text, tenant_active boolean, plan text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT d.hostname,
         d.verification_status = 'verified' AND d.active,
         d.scan_consent_level,
         t.status = 'active',
         s.plan
  FROM monitoring_jobs j
  JOIN domains d ON d.tenant_id = j.tenant_id AND d.id = j.domain_id
  JOIN tenants t ON t.id = j.tenant_id
  LEFT JOIN subscriptions s ON s.tenant_id = j.tenant_id AND s.status = 'active'
  WHERE j.id = p_job_id AND j.status = 'running' AND j.queue IN ('medium', 'heavy')
$$;

-- Functions are executable by PUBLIC by default; restrict the privileged ones.
REVOKE ALL ON FUNCTION app.scan_target(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.scan_target(uuid) TO app_scanner, app_worker;
REVOKE ALL ON FUNCTION app.audit_logs_first_broken() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.audit_logs_first_broken() TO app_api;
REVOKE ALL ON FUNCTION app.audit_logs_chain() FROM PUBLIC;
