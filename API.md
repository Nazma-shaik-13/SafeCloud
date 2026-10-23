# API: who may call what
All state-changing requests need header `X-Requested-With: trustvault`. Session cookie `tv_session` (HttpOnly, SameSite=Strict).

| Endpoint | Who | Notes |
|---|---|---|
| POST /signup | anyone | role must be `owner` or `viewer` |
| POST /login | anyone | lockout after 5 failures (15 min) |
| POST /logout, GET /me | logged in | |
| POST /documents | role `owner` | multipart; type + size checked |
| GET /documents | logged in | only docs you own, hold a grant for, or (admin) metadata of all; filters q, category, owner, date_from, date_to |
| GET /documents/{id}/download | owner, `read`/`edit` grant | admins refused (403) |
| PATCH /documents/{id} | owner, `edit` grant | name, category |
| PUT /documents/{id}/content | owner, `edit` grant | same extension as current name |
| DELETE /documents/{id} | owner only | soft delete |
| GET/POST /documents/{id}/grants | owner only | list / add or change a grant |
| DELETE /documents/{id}/grants/{user_id} | owner only | revoke |
| GET /admin/audit | admin | filters action, outcome |
| GET /admin/audit/verify | admin | recomputes the hash chain |

Every document route calls `authorize()` in `backend/app/permissions.py`. No access gives 404; visible but not permitted gives 403.
