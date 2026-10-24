# PROMPTS.md: SafeCloud

How I used AI on this project, what it got wrong, and what I did about it.

**Tool:** Claude (claude.ai) for design, code and test help. I also used an AI-written roadmap and a written code review as input.

**Note:** Entries 1 to 5 are dated when I did the work. I committed the backend on 2026-10-23, after fixing the first AI drafts, so the commit shows the corrected code.

---

## 1. Architecture (2026-10-21)
**Asked:** I gave an AI-written roadmap (Netlify frontend, separate FastAPI host, database) and asked if it was a good plan.
**Problem:** Too many services to deploy in four days. A frontend and API on different sites make login cookies harder and riskier. Permission checks had no single place.
**What I did:** One FastAPI app that serves the pages and the API, PostgreSQL, files stored in the database (5 MB limit), and one `authorize()` function for all document access.
**Check:** It runs at one address, locally and on Render.
**Limit:** Storing files in the database only suits small files.
**Commit:** https://github.com/Nazma-shaik-13/SafeCloud/commit/25e9598

## 2. Roles and permissions: access control (2026-10-21)
**Asked:** For the role rules and database tables before writing any code.
**AI gave:** Admins see file details but never contents. People without access get "not found". Only the owner can share or delete. "Edit" cannot widen access. Access is checked in the database on every request, so removing it works at once.
**Problem I found:** The document list repeats the access rule in SQL, so there are two places to keep correct.
**What I did:** Kept it, and tested both.
**Tests:** `test_stranger_cannot_read_edit_or_delete`, `test_reader_cannot_edit_delete_or_share`, `test_edit_grant_can_replace_content_but_read_grant_cannot`, `test_admin_sees_metadata_but_never_contents`.
**Commit:** https://github.com/Nazma-shaik-13/SafeCloud/commit/25e9598

## 3. Audit trail: refused uploads were not logged (2026-10-22)
**Asked:** For an upload route with a 5 MB limit and audit logging.
**AI gave:** A route that returned an error for big files without writing an audit record.
**Problem:** The challenge says refused attempts must be provable. A code review I received also pointed this out.
**What I did:** One function now checks size and type and logs every rejected upload with its reason.
**Check:** My Activity log shows a bad upload as `upload` / `denied` / `invalid type`. Test: `test_oversize_upload_is_rejected_and_audited`.
**Limit:** Requests with no login are refused but not logged.
**Commit:** https://github.com/Nazma-shaik-13/SafeCloud/commit/25e9598

## 4. Audit trail: refused downloads had the wrong name (2026-10-22)
**Asked:** For one `authorize()` function that logs every refusal.
**AI gave:** Refusals logged as `read`, while successful downloads were logged as `download`.
**Problem:** An admin filtering by `download` would miss refused attempts. A test caught this.
**What I did:** Mapped refusals to the same action names as successes.
**Check:** My Activity log shows the viewer's refused `download` right after the owner's `revoke`. Test: `test_denied_download_is_audited_with_hashes_and_chain_verifies`.
**Commit:** https://github.com/Nazma-shaik-13/SafeCloud/commit/25e9598

## 5. Do the tests really protect access? (2026-10-22)
**Asked:** For tests that fail if an access check is removed.
**Trial:** The AI tool removed the `authorize()` call in its own test environment: 4 of the 12 tests then failed. All 12 passed on my machine. I repeated the removal myself on 2026-10-24: see entry 9.
**Check:** My Activity log shows grant, allowed download, revoke, and then the same viewer's download denied. Logged in as the viewer, `/admin/audit` answered "Admins only".
**Limit:** I tried this on the download route only.
**Commit:** https://github.com/Nazma-shaik-13/SafeCloud/commit/25e9598

## 6. SHA-256 was saved but never checked (2026-10-23)
**Asked:** Whether my requirement list was met, including SHA-256 for integrity.
**Problem:** The hash was stored on upload, but nothing compared it on download.
**What I did:** Download now recalculates the hash and refuses the file if it does not match, and logs an `integrity_failure`. Admins do not see the hash, because it could help them test guesses about a file.
**Tests:** `test_download_carries_matching_sha256_and_hash_hidden_from_admin`, `test_tampered_file_is_refused_and_audited`.
**Limit:** Someone who can edit both the file and its hash in the database can still cheat.
**Commits:** https://github.com/Nazma-shaik-13/SafeCloud/commit/c835605 (check), https://github.com/Nazma-shaik-13/SafeCloud/commit/2e2371e (hash shown on cards)

## 7. Login form blocked valid logins (2026-10-23)
**Problem:** The login page reused the signup rule "password at least 10 characters". It is not needed at login and could stop people with shorter passwords.
**What I did:** Removed the rule from the login form.
**Commit:** https://github.com/Nazma-shaik-13/SafeCloud/commit/1330a1f

## 8. Duplicate uploads (2026-10-23)
**Problem:** The page let me click Upload again while the first upload was running. On the live site this created several copies.
**What I did:** The button is now disabled while an upload runs.
**Commit:** https://github.com/Nazma-shaik-13/SafeCloud/commit/07131fa

## 9. Closing test gaps (2026-10-24)
**Asked:** To add tests for the three threats that had none (script injection, stolen sessions, SQL injection), make delete erase the file, and let admins disable users.
**AI gave:** 12 new tests, a delete that erases the stored file, and an admin Users page. Disabling a user ends their sessions. Admins cannot disable themselves or other admins.
**Problem:** The AI's first stolen-cookie test did not send the copied cookie, so it failed. A second test flagged the word `innerHTML` in a comment, which was a false alarm. Both were fixed.
**Check:** All 26 tests pass on my machine. I removed the `authorize()` call from the download route: 5 tests failed. After I put it back, all 26 passed.
**Limit:** An erased file may stay on the database disk until PostgreSQL cleans up, and in backups.
**Commits:** https://github.com/Nazma-shaik-13/SafeCloud/commit/039a22d and https://github.com/Nazma-shaik-13/SafeCloud/commit/f24e846
---

**Other context I used:** the challenge problem statement, two UI reference images (for style and section order only), and my requirement checklist.
