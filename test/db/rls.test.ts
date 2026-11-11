// Tenant isolation and privilege tests against a real PostgreSQL. Run with: npm run test:db
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { migrate } from '../../scripts/migrate.ts';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set (use npm run test:db)');

const pool = new pg.Pool({ connectionString: url, max: 4 });

type Ctx = { role?: string; user?: string; tenant?: string };
type Q = (sql: string, params?: unknown[]) => Promise<pg.QueryResult>;

/** Runs fn inside a transaction as the given DB role with the given request context, then rolls back. */
async function as<T>(dbRole: string, ctx: Ctx, fn: (q: Q) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query(`SET LOCAL ROLE ${dbRole}`);
    await c.query(
      `SELECT set_config('app.role', $1, true), set_config('app.user_id', $2, true), set_config('app.tenant_id', $3, true)`,
      [ctx.role ?? '', ctx.user ?? '', ctx.tenant ?? ''],
    );
    return await fn((sql, params) => c.query(sql, params));
  } finally {
    await c.query('ROLLBACK');
    c.release();
  }
}

const denied = (p: Promise<unknown>) => assert.rejects(p, (e: { code?: string }) => e.code === '42501');

const id = {} as Record<string, string>;

before(async () => {
  await migrate(url, () => {});
  const q = (sql: string, params?: unknown[]) => pool.query(sql, params);
  const one = async (sql: string, params?: unknown[]) => (await q(sql, params)).rows[0].id as string;

  id.tA = await one(`INSERT INTO tenants (name, email) VALUES ('Tenant A', 'a@example.test') RETURNING id`);
  id.tB = await one(`INSERT INTO tenants (name, email) VALUES ('Tenant B', 'b@example.test') RETURNING id`);
  const user = (email: string, sys: string | null) =>
    one(`INSERT INTO users (email, password_hash, system_role) VALUES ($1, 'x', $2) RETURNING id`, [email, sys]);
  id.admin = await user('admin@example.test', 'system_admin');
  id.op = await user('op@example.test', 'operator');
  id.aAdmin = await user('a-admin@example.test', null);
  id.aUser = await user('a-user@example.test', null);
  id.bAdmin = await user('b-admin@example.test', null);
  await q(
    `INSERT INTO tenant_members (tenant_id, user_id, role_code) VALUES
       ($1, $3, 'operator'), ($1, $4, 'tenant_admin'), ($1, $5, 'tenant_user'), ($2, $6, 'tenant_admin')`,
    [id.tA, id.tB, id.op, id.aAdmin, id.aUser, id.bAdmin],
  );
  await q(`INSERT INTO subscriptions (tenant_id, plan) VALUES ($1, 'STANDARD'), ($2, 'PREMIUM')`, [id.tA, id.tB]);
  const domain = (t: string, h: string) =>
    one(
      `INSERT INTO domains (tenant_id, hostname, verification_status, scan_consent_level)
       VALUES ($1, $2, 'verified', 'standard') RETURNING id`,
      [t, h],
    );
  id.dA = await domain(id.tA, 'a.example.test');
  id.dB = await domain(id.tB, 'b.example.test');
  const src = (await q(`SELECT id FROM event_sources WHERE code = 'builtin_tls'`)).rows[0].id;
  id.src = src;
  const event = (t: string, d: string, fp: string) =>
    one(
      `INSERT INTO security_events (tenant_id, domain_id, event_type, severity, source_id, title, confidence, fingerprint)
       VALUES ($1, $2, 'tls.expired', 'high', $3, 'expired', 'high', $4) RETURNING id`,
      [t, d, src, Buffer.from(fp)],
    );
  id.eA = await event(id.tA, id.dA, 'fp-a');
  id.eB = await event(id.tB, id.dB, 'fp-b');
  const job = (t: string, d: string, queue: string, status: string) =>
    one(
      `INSERT INTO monitoring_jobs (tenant_id, domain_id, queue, job_type, status) VALUES ($1, $2, $3, 'x', $4) RETURNING id`,
      [t, d, queue, status],
    );
  id.jLight = await job(id.tA, id.dA, 'light', 'queued');
  id.jScanRunning = await job(id.tA, id.dA, 'medium', 'running');
  id.jScanQueued = await job(id.tB, id.dB, 'heavy', 'queued');
});

after(() => pool.end());

test('application roles cannot bypass RLS and own no tables', async () => {
  const r = await pool.query(
    `SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN ('app_api', 'app_worker', 'app_scanner')`,
  );
  assert.equal(r.rowCount, 3);
  for (const row of r.rows) assert.deepEqual([row.rolsuper, row.rolbypassrls], [false, false], row.rolname);
  const owned = await pool.query(
    `SELECT count(*)::int AS n FROM pg_tables WHERE schemaname = 'public' AND tableowner LIKE 'app\\_%'`,
  );
  assert.equal(owned.rows[0].n, 0);
});

test('every table has RLS enabled', async () => {
  const r = await pool.query(
    `SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relrowsecurity AND relname <> 'schema_migrations'`,
  );
  assert.deepEqual(r.rows, []);
});

test('customer admin of A sees only A', async () => {
  await as('app_api', { role: 'tenant_admin', user: id.aAdmin, tenant: id.tA }, async (q) => {
    for (const table of ['domains', 'security_events', 'subscriptions', 'monitoring_jobs']) {
      const r = await q(`SELECT DISTINCT tenant_id FROM ${table}`);
      assert.deepEqual(r.rows.map((x) => x.tenant_id), [id.tA], table);
    }
    assert.deepEqual((await q('SELECT id FROM tenants')).rows.map((x) => x.id), [id.tA]);
    assert.equal((await q('SELECT 1 FROM security_events WHERE id = $1', [id.eB])).rowCount, 0);
    assert.equal((await q('SELECT 1 FROM users WHERE id = $1', [id.bAdmin])).rowCount, 0);
    assert.equal((await q('SELECT 1 FROM audit_logs')).rowCount, 0);
  });
});

test('naming another tenant in the context grants nothing without membership', async () => {
  await as('app_api', { role: 'tenant_admin', user: id.aAdmin, tenant: id.tB }, async (q) => {
    assert.equal((await q('SELECT 1 FROM domains')).rowCount, 0);
    assert.equal((await q('SELECT 1 FROM security_events')).rowCount, 0);
    assert.equal((await q('SELECT 1 FROM tenants')).rowCount, 0);
  });
});

test('customer admin cannot write into another tenant', async () => {
  const ctx = { role: 'tenant_admin', user: id.aAdmin, tenant: id.tA };
  await as('app_api', ctx, (q) =>
    denied(q(`INSERT INTO domains (tenant_id, hostname) VALUES ($1, 'evil.example.test')`, [id.tB])),
  );
  await as('app_api', ctx, async (q) => {
    const r = await q(`UPDATE security_events SET status = 'resolved' WHERE id = $1`, [id.eB]);
    assert.equal(r.rowCount, 0);
  });
  await as('app_api', ctx, (q) =>
    denied(q(`UPDATE security_events SET tenant_id = $1 WHERE id = $2`, [id.tB, id.eA])),
  );
});

test('customer read-only user can read but not change', async () => {
  await as('app_api', { role: 'tenant_user', user: id.aUser, tenant: id.tA }, async (q) => {
    assert.equal((await q('SELECT 1 FROM security_events')).rowCount, 1);
    assert.equal((await q(`UPDATE security_events SET status = 'resolved'`)).rowCount, 0);
    assert.equal((await q('SELECT 1 FROM users WHERE id <> $1', [id.aUser])).rowCount, 0);
  });
  await as('app_api', { role: 'tenant_user', user: id.aUser, tenant: id.tA }, (q) =>
    denied(q(`INSERT INTO domains (tenant_id, hostname) VALUES ($1, 'x.example.test')`, [id.tA])),
  );
});

test('a customer user cannot claim a higher role than their membership', async () => {
  await as('app_api', { role: 'tenant_admin', user: id.aUser, tenant: id.tA }, async (q) => {
    assert.equal((await q('SELECT 1 FROM security_events')).rowCount, 0);
  });
});

test('customer admin cannot change plan, tenant or membership', async () => {
  const ctx = { role: 'tenant_admin', user: id.aAdmin, tenant: id.tA };
  await as('app_api', ctx, async (q) => {
    assert.equal((await q(`UPDATE subscriptions SET plan = 'PREMIUM'`)).rowCount, 0);
    assert.equal((await q(`UPDATE tenants SET name = 'x'`)).rowCount, 0);
    assert.equal((await q(`UPDATE users SET system_role = 'system_admin' WHERE id = $1`, [id.aAdmin])).rowCount, 0);
  });
  await as('app_api', ctx, (q) =>
    denied(q(`INSERT INTO tenant_members (tenant_id, user_id, role_code) VALUES ($1, $2, 'tenant_admin')`, [id.tB, id.aAdmin])),
  );
});

test('operator sees assigned customers only', async () => {
  await as('app_api', { role: 'operator', user: id.op }, async (q) => {
    assert.deepEqual((await q('SELECT id FROM tenants')).rows.map((x) => x.id), [id.tA]);
    assert.equal((await q('SELECT 1 FROM security_events WHERE id = $1', [id.eB])).rowCount, 0);
    assert.equal((await q(`UPDATE security_events SET status = 'in_progress' WHERE id = $1`, [id.eA])).rowCount, 1);
  });
});

test('system administrator sees all customers', async () => {
  await as('app_api', { role: 'system_admin', user: id.admin }, async (q) => {
    assert.equal((await q('SELECT 1 FROM tenants')).rowCount, 2);
    assert.equal((await q('SELECT 1 FROM security_events')).rowCount, 2);
  });
});

test('no context means no data', async () => {
  await as('app_api', {}, async (q) => {
    for (const table of ['tenants', 'users', 'domains', 'security_events', 'sessions', 'plan_features']) {
      assert.equal((await q(`SELECT 1 FROM ${table}`)).rowCount, 0, table);
    }
  });
});

test('a row cannot reference another tenant’s domain', async () => {
  await assert.rejects(
    pool.query(
      `INSERT INTO security_events (tenant_id, domain_id, event_type, severity, source_id, title, confidence, fingerprint)
       VALUES ($1, $2, 't', 'low', $3, 't', 'low', 'zz')`,
      [id.tA, id.dB, id.src],
    ),
    (e: { code?: string }) => e.code === '23503',
  );
});

test('worker writes findings only for the tenant its job is bound to', async () => {
  const insert = (q: Q, tenant: string, domain: string) =>
    q(
      `INSERT INTO security_events (tenant_id, domain_id, event_type, severity, source_id, title, confidence, fingerprint)
       VALUES ($1, $2, 't', 'low', $3, 't', 'low', 'w1')`,
      [tenant, domain, id.src],
    );
  await as('app_worker', { role: 'worker', tenant: id.tA }, async (q) => {
    await insert(q, id.tA, id.dA);
    assert.deepEqual((await q('SELECT DISTINCT tenant_id FROM security_events')).rows.map((x) => x.tenant_id), [id.tA]);
    assert.equal((await q('SELECT 1 FROM monitoring_jobs')).rowCount, 3);
  });
  await as('app_worker', { role: 'worker', tenant: id.tA }, (q) => denied(insert(q, id.tB, id.dB)));
  await as('app_worker', { role: 'worker', tenant: id.tA }, (q) => denied(q('SELECT password_hash FROM users')));
  await as('app_worker', { role: 'worker', tenant: id.tA }, (q) => denied(q('SELECT 1 FROM sessions')));
});

test('scanner role is confined to its queues and cannot read customer data', async () => {
  for (const table of ['tenants', 'users', 'sessions', 'domains', 'security_events', 'tenant_members', 'scan_results', 'notifications', 'external_api_settings', 'audit_logs']) {
    await as('app_scanner', {}, (q) => denied(q(`SELECT 1 FROM ${table}`)));
  }
  await as('app_scanner', {}, async (q) => {
    const jobs = await q('SELECT id FROM monitoring_jobs');
    assert.deepEqual(jobs.rows.map((x) => x.id).sort(), [id.jScanRunning, id.jScanQueued].sort());
    assert.equal((await q(`UPDATE monitoring_jobs SET status = 'failed' WHERE id = $1`, [id.jLight])).rowCount, 0);
    await q(
      `INSERT INTO scan_results (tenant_id, job_id, domain_id, check_type, outcome) VALUES ($1, $2, $3, 'nuclei', 'ok')`,
      [id.tA, id.jScanRunning, id.dA],
    );
    const t = await q('SELECT * FROM app.scan_target($1)', [id.jScanRunning]);
    assert.deepEqual(t.rows, [
      { hostname: 'a.example.test', verified: true, scan_consent_level: 'standard', tenant_active: true, plan: 'STANDARD' },
    ]);
    assert.equal((await q('SELECT * FROM app.scan_target($1)', [id.jLight])).rowCount, 0);
  });
  // Result for a tenant other than the job's tenant.
  await as('app_scanner', {}, (q) =>
    denied(q(`INSERT INTO scan_results (tenant_id, job_id, domain_id, check_type, outcome) VALUES ($1, $2, $3, 'nuclei', 'ok')`,
      [id.tB, id.jScanRunning, id.dB])),
  );
  // Result for a job it is not running.
  await as('app_scanner', {}, (q) =>
    denied(q(`INSERT INTO scan_results (tenant_id, job_id, domain_id, check_type, outcome) VALUES ($1, $2, $3, 'nuclei', 'ok')`,
      [id.tB, id.jScanQueued, id.dB])),
  );
  await as('app_scanner', {}, (q) => denied(q(`UPDATE monitoring_jobs SET payload = '{}' WHERE id = $1`, [id.jScanRunning])));
  await as('app_scanner', {}, (q) => denied(q(`UPDATE monitoring_jobs SET queue = 'light' WHERE id = $1`, [id.jScanRunning])));
});

test('a failed check must carry an error category and is distinct from ok', async () => {
  const ins = (outcome: string, cat: string | null) =>
    as('app_worker', { role: 'worker', tenant: id.tA }, (q) =>
      q(`INSERT INTO scan_results (tenant_id, domain_id, check_type, outcome, error_category) VALUES ($1, $2, 'tls', $3, $4)`,
        [id.tA, id.dA, outcome, cat]),
    );
  await ins('error', 'timeout');
  await ins('ok', null);
  await assert.rejects(ins('error', null), (e: { code?: string }) => e.code === '23514');
  await assert.rejects(ins('ok', 'timeout'), (e: { code?: string }) => e.code === '23514');
});

test('audit log is append-only and tamper-evident', async () => {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query('SET LOCAL ROLE app_api');
    await c.query(`SELECT set_config('app.role', 'system_admin', true)`);
    for (const action of ['login', 'tenant.update', 'logout']) {
      await c.query(`INSERT INTO audit_logs (tenant_id, actor_id, action, ip, meta) VALUES ($1, $2, $3, '203.0.113.5', '{"k": 1}')`,
        [id.tA, id.admin, action]);
    }
    assert.equal((await c.query('SELECT app.audit_logs_first_broken() AS b')).rows[0].b, null);
    await assert.rejects(c.query(`SAVEPOINT s; UPDATE audit_logs SET action = 'x'`), (e: { code?: string }) => e.code === '42501');
    await c.query('ROLLBACK TO s');
    await assert.rejects(c.query(`DELETE FROM audit_logs`), (e: { code?: string }) => e.code === '42501');
    await c.query('ROLLBACK TO s');

    // Even the owner is stopped by the trigger; simulate tampering by someone who disabled it.
    await c.query('RESET ROLE');
    await assert.rejects(c.query(`UPDATE audit_logs SET action = 'x'`), /append-only/);
    await c.query('ROLLBACK TO s');
    await c.query('RESET ROLE'); // the rollback restored the application role
    await c.query('ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_immutable');
    const second = (await c.query('SELECT id FROM audit_logs ORDER BY id OFFSET 1 LIMIT 1')).rows[0].id;
    await c.query(`UPDATE audit_logs SET action = 'tampered' WHERE id = $1`, [second]);
    assert.equal((await c.query('SELECT app.audit_logs_first_broken() AS b')).rows[0].b, second);
  } finally {
    await c.query('ROLLBACK');
    c.release();
  }
});

test('migrations are idempotent', async () => {
  const applied: string[] = [];
  await migrate(url, (m) => applied.push(m));
  assert.deepEqual(applied, []);
});
