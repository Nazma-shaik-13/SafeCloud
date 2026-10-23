# THREATS
| # | Threat | What stops it | Test |
|---|---|---|---|
| 1 | Guess or reuse another document's ID (IDOR) | UUID ids; `authorize()` on every route; 404 hides existence | test_stranger_cannot_read_edit_or_delete |
| 2 | Keep access after revocation | grant checked in the DB on every request; no permission in the cookie | test_revocation_is_immediate |
| 3 | Reader tries to edit, delete or share | capability table in `permissions.py` | test_reader_cannot_edit_delete_or_share, test_edit_grant_can_replace_content_but_read_grant_cannot |
| 4 | Admin reads confidential files | admin capability is metadata only | test_admin_sees_metadata_but_never_contents |
| 5 | Self-register as admin | signup accepts only owner/viewer | test_upload_rejects_fake_pdf_and_signup_cannot_make_admin |
| 6 | Non-admin reads audit log | role check on admin routes | test_non_admin_cannot_read_audit |
| 7 | Edit or delete audit history | DB trigger blocks UPDATE/DELETE/TRUNCATE; hash chain + verify endpoint | test_audit_rows_cannot_be_updated_or_deleted, test_denied_download_is_audited_with_hashes_and_chain_verifies |
| 8 | Refused attempts leave no trace | `authorize()` logs every denial | test_denied_download_is_audited_with_hashes_and_chain_verifies |
| 9 | Oversize or disguised uploads | 5 MB limit, extension allowlist, magic-byte check, safe filenames; rejections audited | test_upload_rejects_fake_pdf_..., test_oversize_upload_is_rejected_and_audited |
| 10 | Password guessing | Argon2id, lockout after 5 failures, same error for all failures | test_login_lockout_after_repeated_failures |
| 11 | Cross-site request forgery | SameSite=Strict cookie + required custom header | test_state_changing_request_without_csrf_header_is_refused |
| 12 | Script injection via names or audit data | frontend inserts data as text only; CSP `default-src 'self'` | **no automated test yet** |
| 13 | Stolen session | tokens stored hashed, expire in 8 h, revoked on logout / user disable | **no automated test yet** |
| 14 | SQL injection | parameterised queries only | **no automated test yet** |

## Knowingly accepted
- Revocation cannot recall a file already downloaded.
- A database superuser could rewrite the whole audit chain; it is not anchored outside the database.
- Signup reveals whether an email exists (409). Login does not.
- Failed-login lockout can be used to lock someone else out for 15 minutes.
- Upload size is checked after the server receives the file; add a proxy limit when deploying.
- Files live in the database (5 MB cap) for simplicity.
- Allowed downloads are logged by each route, not centrally, so a new route could forget; denials are central.
