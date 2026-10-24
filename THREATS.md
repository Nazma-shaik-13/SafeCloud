# THREATS.md: SafeCloud

Ways I think SafeCloud could be broken, what I did about each, and what I left open. Every row below has an automated test (26 tests in `backend/tests`).

## Covered

| # | Threat | What I did | Test |
|---|---|---|---|
| 1 | Guessing or opening another person's document | Random document IDs. Every document route calls `authorize()`. No access gives "not found". | `test_stranger_cannot_read_edit_or_delete` |
| 2 | Keeping access after it was removed | Access is checked in the database on every request. | `test_revocation_is_immediate` |
| 3 | A reader editing, deleting or sharing | Each access level has fixed rights. Only the owner can delete or share. | `test_reader_cannot_edit_delete_or_share`, `test_edit_grant_can_replace_content_but_read_grant_cannot` |
| 4 | An admin reading private files | Admins see file details and activity, never contents. | `test_admin_sees_metadata_but_never_contents` |
| 5 | Becoming admin, or taking over an admin | Signup accepts only owner or viewer. Admins cannot disable themselves or other admins. | `test_upload_rejects_fake_pdf_and_signup_cannot_make_admin`, `test_only_admin_can_manage_users_and_never_other_admins` |
| 6 | A non-admin using admin pages | Role check on every admin route. The refused attempt is logged. | `test_non_admin_cannot_read_audit`, `test_only_admin_can_manage_users_and_never_other_admins` |
| 7 | Changing or deleting audit records | A database trigger blocks update, delete and truncate. Each row holds the hash of the row before it. Admins can verify the chain. | `test_audit_rows_cannot_be_updated_or_deleted`, `test_denied_download_is_audited_with_hashes_and_chain_verifies` |
| 8 | Refused attempts leaving no trace | `authorize()` logs every refusal. Rejected uploads are logged too. | `test_denied_download_is_audited_with_hashes_and_chain_verifies`, `test_oversize_upload_is_rejected_and_audited` |
| 9 | Bad or oversized uploads | 5 MB limit, allowed types only, file start bytes checked, filenames cleaned. | `test_upload_rejects_fake_pdf_and_signup_cannot_make_admin`, `test_oversize_upload_is_rejected_and_audited` |
| 10 | Password guessing | Argon2 password hashes. The account locks for 15 minutes after 5 wrong tries. Same error for every failure. | `test_login_lockout_after_repeated_failures` |
| 11 | Forged requests from other sites | Strict cookie plus a required header on every change. | `test_state_changing_request_without_csrf_header_is_refused` |
| 12 | A stored file being changed | SHA-256 is checked on every download. A mismatch is refused and logged. | `test_tampered_file_is_refused_and_audited` |
| 13 | An admin guessing a file's contents from its hash | The hash is shown only to people who can read the file. | `test_download_carries_matching_sha256_and_hash_hidden_from_admin` |
| 14 | Script injection (XSS) | Filenames are cleaned. Pages show data as plain text and never build HTML from it. A Content-Security-Policy is set. Downloads are attachments with nosniff. | `test_filename_is_cleaned_and_download_cannot_run_in_browser`, `test_pages_send_security_headers`, `test_frontend_never_builds_html_from_data` |
| 15 | A copied login cookie after logout | Logout ends the session on the server. | `test_old_cookie_stops_working_after_logout` |
| 16 | A person who left keeping access | An admin can disable the account. Their sessions end at once and stay ended if the account is enabled again. | `test_disabled_user_loses_access_immediately` |
| 17 | Old sessions living forever | Sessions expire after 8 hours. | `test_expired_session_is_refused` |
| 18 | Sessions leaking from the database | Only a hash of the session token is stored. The cookie is HttpOnly and SameSite=Strict, and Secure on the live site. | `test_session_cookie_flags_and_token_not_stored_in_clear` |
| 19 | SQL injection | All queries use parameters. | `test_search_inputs_cannot_inject_sql`, `test_login_inputs_cannot_inject_sql` |
| 20 | A deleted file staying readable | Delete hides the document and erases the stored file. | `test_delete_erases_file_bytes_and_hides_document` |

## Risks I accepted

- Removing access cannot take back a file someone already downloaded.
- A database administrator could rewrite the whole audit chain and the file hashes. There is no copy of the chain outside the database.
- Erasing a file replaces the stored bytes. PostgreSQL may keep old copies on disk until it cleans up, and a backup would keep them.
- Signup shows whether an email is already registered. Login does not.
- Someone can lock another person's account for 15 minutes by guessing wrong passwords.
- The size limit is checked after the server has received the file.
- Requests with no login are refused but not logged.
- The document list repeats the access rule in SQL, so the rule exists in two places. Tests cover both.
- Categories are stored as typed. They are only ever shown as plain text.
- Admins cannot be disabled from the website, only in the database.
- The demo accounts are public on purpose. A real deployment would remove them.
- Files are stored in the database with a 5 MB limit, so this suits small files only.
- Free hosting: the server sleeps when idle, and the free database expires about 30 days after it was created.