# DeepSec

中小企業向けセキュリティ統合監視サービス。

- 設計書: [docs/DESIGN.md](docs/DESIGN.md)
- 実装状況: 仕様 20-1 の手順 1（データベース）まで完了。手順 2（認証・権限管理）以降は未実装。

## 構成

| パス | 内容 |
|---|---|
| `db/migrations/` | スキーマ、RLS（顧客データ分離）、初期データ |
| `scripts/migrate.ts` | マイグレーション実行 |
| `test/db/` | 顧客分離・権限・監査ログのテスト |

## 開発

Node.js 22.18 以上と PostgreSQL 16 以上が必要。

```bash
npm install
```

```bash
npm run test:db
```

`test:db` は一時的な PostgreSQL を起動し、マイグレーションを適用してテストを実行する。

既存の DB にマイグレーションを適用する場合（所有者ロールで接続）:

```bash
MIGRATION_DATABASE_URL=postgres://owner@localhost/deepsec npm run migrate
```
