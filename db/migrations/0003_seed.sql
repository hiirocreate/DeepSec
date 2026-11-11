-- Reference data. Plan features are defaults and can be changed from the admin screen.

INSERT INTO roles (code, description) VALUES
  ('system_admin', 'システム管理者'),
  ('operator',     '運営担当者'),
  ('tenant_admin', '顧客管理者'),
  ('tenant_user',  '顧客一般ユーザー');

INSERT INTO event_sources (code, name, kind, min_plan, attribution_text, coverage_note) VALUES
  ('builtin_tls',     'SSL/HTTPS 監視',         'builtin',    'BASIC', NULL, '登録ドメインの 443 番ポートを 1 日 1 回確認'),
  ('builtin_dns',     'DNS 監視',               'builtin',    'BASIC', NULL, 'A / AAAA / MX / NS を 1 日 1 回確認'),
  ('builtin_mail',    'メール認証設定監視',      'builtin',    'BASIC', NULL, 'SPF / DKIM / DMARC。DKIM は既知のセレクタのみ確認可能'),
  ('builtin_headers', 'HTTP セキュリティヘッダー監視', 'builtin', 'BASIC', NULL, 'トップページの応答ヘッダーを 1 日 1 回確認'),
  ('nvd',             'NVD',                    'vuln_feed',  'BASIC',
     'This product uses the NVD API but is not endorsed or certified by the NVD.',
     '外部から観測できた製品・バージョン情報との照合。判定確度を併記'),
  ('cisa_kev',        'CISA KEV',               'vuln_feed',  'BASIC', 'Source: CISA Known Exploited Vulnerabilities Catalog', '悪用が確認された脆弱性の一覧との照合'),
  ('osv',             'OSV.dev',                'vuln_feed',  'BASIC', 'Source: OSV.dev', 'オープンソース製品の脆弱性情報との照合'),
  ('nuclei',          'Nuclei',                 'scanner',    'STANDARD', NULL, '許可リストに登録した情報取得型・軽度の検査のみ。週 1 回'),
  ('zap_passive',     'OWASP ZAP（受動診断）',   'scanner',    'STANDARD', NULL, '受動的な診断のみ'),
  ('subdomains',      '公開資産調査',            'scanner',    'STANDARD', NULL, '公開情報から判明するサブドメインのみ。週 1 回'),
  ('github_code',     'GitHub 公開リポジトリ',   'public_web', 'STANDARD', NULL, 'GitHub の公開リポジトリのみ。検索 API で取得できる範囲'),
  ('ransomlook',      'RansomLook',             'leak_feed',  'PREMIUM', 'Source: RansomLook (https://www.ransomlook.io/) — CC BY 4.0',
     'RansomLook が追跡しているランサムウェアグループの公開リーク掲載情報のみ。掲載から取得まで遅延がある'),
  ('tor_leak_sites',  'Tor 上の公開リークサイト', 'tor',        'PREMIUM', NULL,
     '運営者が登録した公開サイトの一覧ページのみ。ダークウェブ全体は対象外。サイト停止時は取得不可');

INSERT INTO external_api_settings (source_id, enabled)
  SELECT id, false FROM event_sources WHERE kind IN ('vuln_feed', 'public_web', 'leak_feed', 'tor');

INSERT INTO plan_features (plan, feature_key, enabled, limits)
SELECT p.plan, f.key, p.rank >= f.min_rank, f.limits
FROM (VALUES ('BASIC', 1), ('STANDARD', 2), ('PREMIUM', 3)) AS p (plan, rank)
CROSS JOIN (VALUES
  ('check.tls',          1, '{"interval_hours": 24}'::jsonb),
  ('check.dns',          1, '{"interval_hours": 24}'),
  ('check.mail_auth',    1, '{"interval_hours": 24}'),
  ('check.http_headers', 1, '{"interval_hours": 24}'),
  ('check.vuln_feeds',   1, '{"interval_hours": 24}'),
  ('scan.nuclei',        2, '{"interval_hours": 168}'),
  ('scan.zap_passive',   2, '{"interval_hours": 168}'),
  ('scan.subdomains',    2, '{"interval_hours": 168}'),
  ('leak.public_web',    2, '{"interval_hours": 24}'),
  ('leak.gitleaks',      2, '{"interval_hours": 24}'),
  ('leak.ransom_feed',   3, '{"interval_hours": 6}'),
  ('leak.tor_sites',     3, '{"interval_hours": 24}'),
  ('report.monthly',     1, '{}'),
  ('report.detailed',    2, '{}'),
  ('limit.domains',      1, '{"max": 3}')
) AS f (key, min_rank, limits);

UPDATE plan_features SET limits = '{"max": 10}' WHERE feature_key = 'limit.domains' AND plan = 'STANDARD';
UPDATE plan_features SET limits = '{"max": 30}' WHERE feature_key = 'limit.domains' AND plan = 'PREMIUM';

INSERT INTO monitoring_settings (tenant_id, key, value) VALUES
  (NULL, 'queue.concurrency', '{"light": 4, "medium": 1, "heavy": 1, "notify": 2, "report": 1}'),
  (NULL, 'resource.thresholds', '{"cpu_percent": 85, "memory_percent": 85, "disk_percent": 90}'),
  (NULL, 'job.heartbeat_timeout_seconds', '120'),
  (NULL, 'notify.retry_delays_seconds', '[300, 1800, 7200]'),
  (NULL, 'notify.daily_send_limit', '90');
