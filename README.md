# TrustVault
Secure document sharing with a tamper-evident audit trail. FastAPI + PostgreSQL; the same app serves the web pages (one origin, no CORS).

## Roles
| Action | Admin | Owner of the doc | `edit` grant | `read` grant | No grant |
|---|---|---|---|---|---|
| See it exists / metadata | yes | yes | yes | yes | no (404) |
| Download | **no** | yes | yes | yes | no |
| Rename / replace file | no | yes | yes | no | no |
| Delete, share, revoke | no | yes | no | no | no |
| Read audit log | yes | no | no | no | no |

Signup creates only `owner` or `viewer`. Admins are created by `seed.py`.

## Run locally
1. `createdb trustvault` and `psql trustvault -f backend/migrations/001_init.sql`
2. `cd backend && python -m venv .venv`, activate it (Windows: `.venv\Scripts\activate`; Mac/Linux: `source .venv/bin/activate`)
3. `pip install -r requirements.txt`, copy `.env.example` to `.env`, set `DATABASE_URL`
4. `python seed.py` then `uvicorn app.main:app`, open http://localhost:8000

Demo accounts (password `ChangeMe-Demo-123`): `admin@trustvault.test`, `owner@trustvault.test`, `viewer@trustvault.test`. **Change or remove these on any real deployment.**

## Tests
Use a separate empty database: set `DATABASE_URL` to it, load `001_init.sql`, then `cd backend && pytest`.

## Deploy (verify each step on your host)
Managed PostgreSQL + one Python web service. Env vars: `DATABASE_URL`, `COOKIE_SECURE=true`. Build: `pip install -r backend/requirements.txt`. Start from `backend/`: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Run `001_init.sql` and `seed.py` once. Then open the live URL in a private window.

## What is not finished
See THREATS.md (accepted risks). Files are stored in the database (5 MB cap). No password reset, no groups or folders, no email.
