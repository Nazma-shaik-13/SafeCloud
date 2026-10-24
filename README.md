# SafeCloud

A document-sharing site where only the people you choose can open a file, and every action is recorded.

**Live site:** https://safecloud-k5e5.onrender.com
The free server sleeps when idle, so the first page can take up to a minute.

## Demo accounts

| Role | Email |
|---|---|
| Admin | `admin@safecloud.test` |
| Owner | `owner@safecloud.test` |
| Viewer | `viewer@safecloud.test` |

Password for all three: `Safepvt13613`

## What it does

- Sign up and log in. Passwords are hashed with Argon2.
- Owners upload, rename, replace, delete and search documents (by name, category, owner and date).
- Owners give named people read or edit access, and take it back.
- Every important action is logged, including refused attempts.
- Admins see an activity page with filters and a button to verify the log. They can also disable and enable owner and viewer accounts.
- Uploads are checked for size and type. Each file has a SHA-256 hash that is checked on every download.
- Deleting a document erases the stored file.

## Roles

| | Admin | Owner | Viewer |
|---|---|---|---|
| Upload documents | no | yes | no |
| See document details | all documents | own and shared | shared |
| Download | no | own, and shared | shared |
| Edit, replace | no | own | if given edit access |
| Delete, share, take access back | no | own | no |
| See the activity log | yes | no | no |
| Disable or enable owners and viewers | yes | no | no |

## How permissions work

Each document has one owner. The owner can give another person read or edit access. Every document action goes through one function, `authorize()` in `backend/app/permissions.py`. It checks the database every time, so taking access away works on the next request. People with no access get "not found", so they cannot tell the document exists. Admins see file details and the activity log but never file contents.

## Audit log and file integrity

Each log row stores who did what, when, from which IP, and whether it was allowed or refused. Each row also holds the hash of the row before it. The database blocks changes and deletes on the log, and the admin page can check the whole chain. For files, the SHA-256 is saved at upload and checked at every download. A file that does not match is refused and logged.

## Built with

HTML, CSS and JavaScript, FastAPI (Python), PostgreSQL, pytest. Hosted on Render. The app serves the pages and the API from one address.

## Run it on your computer

1. Create the database and tables:
   `psql -U postgres -c "CREATE DATABASE safecloud;"`
   `psql -U postgres -d safecloud -f backend/migrations/001_init.sql`
2. In `backend`, create and start a virtual environment: `python -m venv .venv`, then `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Mac/Linux).
3. `python -m pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and set `DATABASE_URL`.
5. `python seed.py` creates the three demo accounts. Set `SEED_PASSWORD` first to choose their password(default password: ChangeMe-Demo-123).
6. `python -m uvicorn app.main:app`, then open http://localhost:8000

## Run the tests

Use a separate empty database with the same tables. Set `DATABASE_URL` to it, then run `python -m pytest` in `backend`. There are 26 tests.

## Deploy on Render

1. Create a Render PostgreSQL database. Load `backend/migrations/001_init.sql` and run `seed.py` against it.
2. Create a Web Service from this repo, with Root Directory empty.
   Build: `pip install -r backend/requirements.txt`
   Start: `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"`
3. Set `DATABASE_URL` (the internal database URL) and `COOKIE_SECURE=true`.

My database was created on 2026-10-23. Free Render databases expire after 30 days.

## What I did not build

Groups, folders, sharing with people outside the site, versions, restoring deleted files, password reset, and changing a user's role.

## Not finished

See `THREATS.md` for the risks I accepted. The main ones: removing access cannot take back a file already downloaded, a database administrator could rewrite the audit log, and files are stored in the database, so only small files are supported.

## AI use

I used Claude for design, code and test help. `PROMPTS.md` lists what it got wrong and what I changed. More docs: `API.md` (who can call each endpoint) and `THREATS.md`.