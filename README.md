TutoPay Postgres Persistence Patch (Railway)

What this patch does
- Keeps your existing in-memory logic (fast + same behavior).
- If DATABASE_URL is set (Railway Postgres), it will:
  - connect to Postgres (SSL enabled)
  - create tables if missing
  - load existing data into memory on boot
  - persist new/updated items, requests, transactions, and audit logs

Requirements
- Add the pg dependency:
  npm i pg
  (or add "pg" to dependencies in package.json and push)

How to apply
1) Replace your backend repo server.js with this patched server.js
2) Ensure "pg" is installed in package.json dependencies
3) Push to GitHub -> Railway redeploys
4) Check Railway logs for:
   [DB] Connected + memory hydrated.

How to verify persistence
- Create an item / transaction in the app
- Redeploy the backend
- Refresh the app -> the created data should still exist

Notes
- Tables used: tp_items, tp_transactions, tp_requests, tp_audit
- Objects are stored as JSONB for demo speed and to avoid a heavy migration.
