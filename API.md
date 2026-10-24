# API.md: who can call what

All changes (POST, PUT, PATCH, DELETE) need the header `X-Requested-With: trustvault`. Login sets a cookie `tv_session` (HttpOnly, SameSite=Strict).

Answers: `401` not logged in, `403` not allowed, `404` document not visible to you, `413` file over 5 MB, `415` file type not allowed.

| Endpoint | Who can call it | Notes |
|---|---|---|
| `POST /signup` | Anyone | Role must be `owner` or `viewer` |
| `POST /login` | Anyone | Account locks for 15 minutes after 5 wrong tries |
| `POST /logout`, `GET /me` | Logged-in users | |
| `POST /documents` | Owners | Multipart upload with a category |
| `GET /documents` | Logged-in users | Only your documents, shared ones, or (admin) details of all. Filters: `q`, `category`, `owner`, `date_from`, `date_to`. The SHA-256 is shown only if you can read the file |
| `GET /documents/{id}/download` | Document owner, people with read or edit access | Admins get 403. Sends `X-Content-SHA256` and refuses a file that no longer matches its hash |
| `PATCH /documents/{id}` | Document owner, people with edit access | Name and category |
| `PUT /documents/{id}/content` | Document owner, people with edit access | New file must keep the same extension |
| `DELETE /documents/{id}` | Document owner | Hides the document and erases the stored file |
| `GET /documents/{id}/grants` | Document owner | Who has access |
| `POST /documents/{id}/grants` | Document owner | Give `read` or `edit` access to a person by email |
| `DELETE /documents/{id}/grants/{user_id}` | Document owner | Take access back |
| `GET /admin/audit` | Admins | Filters: `action`, `outcome` |
| `GET /admin/audit/verify` | Admins | Checks the whole hash chain |
| `GET /admin/users` | Admins | Email, role, status. No password data |
| `POST /admin/users/{id}/disable` | Admins | Owners and viewers only. Ends their sessions |
| `POST /admin/users/{id}/enable` | Admins | Owners and viewers only |

Every document route calls `authorize()` in `backend/app/permissions.py`. Refused attempts, including non-admins calling admin routes, are written to the audit log.