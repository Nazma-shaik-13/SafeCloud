# PROMPTS.md
> **Candidate: this file must be YOUR honest record.** The entries below describe real problems found in AI-written code during this build. Re-read the code, confirm each one yourself, replace `<commit>` with your real commit link, and add your own entries. Delete this note.

## Entry format
Date · what I asked · what the tool produced · what was wrong · what I did (commit link)

## 2026-10-21 · audit trail: oversize uploads left no record
- **Asked:** write the upload route with a 5 MB limit and audit logging.
- **Produced:** a route that returned HTTP 413 for big files without writing any audit event, while other refusals were logged.
- **Wrong:** the challenge says refused attempts must be provable. This one vanished.
- **Fixed:** `read_valid_file()` in `main.py` audits every rejection; added `test_oversize_upload_is_rejected_and_audited`. `<commit>`

## 2026-10-21 · audit trail: denied downloads logged under the wrong action name
- **Asked:** central `authorize()` that logs denials.
- **Produced:** denials logged as action `read`, while successes were logged as `download`.
- **Wrong:** an admin filtering by `download` would never see refused downloads. Found when my new test failed.
- **Fixed:** `AUDIT_NAME` mapping in `permissions.py`. `<commit>`

## 2026-10-21 · access control: how I checked `authorize()`
- **Checked:** removed the `authorize()` call from the download route; 4 tests failed; restored it; all 12 passed. `<commit>`
- **Known gap:** the document list query repeats the visibility rule in SQL, so there are two places to keep correct.

## 2026-10-21 · setup: missing dependency and unneeded extension
- **Produced:** `uvicorn --env-file` without `python-dotenv`; `seed.py` that ignored `.env`; a migration requiring `pgcrypto`.
- **Fixed:** `python-dotenv` + `load_dotenv()` in `config.py`; removed `pgcrypto` (`gen_random_uuid()` is built into PostgreSQL 13+). `<commit>`

## 2026-10-21 · frontend: CSP vs inline styles
- **Produced:** first UI draft used inline `style=` attributes, which the app's own CSP (`default-src 'self'`) blocks.
- **Fixed:** moved them to CSS classes. `<commit>`

## Prompts and context files I reused
(Paste your own here: the instructions, reference images and prompts you reused across the week.)
