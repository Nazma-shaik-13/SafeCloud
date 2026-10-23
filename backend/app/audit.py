import hashlib
import json
from datetime import datetime, timezone

from psycopg.types.json import Jsonb

GENESIS = "0" * 64


def log(conn, actor_id, action, outcome, document_id=None, detail=None):
    """Append one audit row, chained to the previous row's hash.
    Changing or deleting an old row would break every hash after it."""
    at = datetime.now(timezone.utc)
    detail = detail or {}
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(7001)")   # one writer at a time keeps the chain in order
        row = conn.execute("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        payload = json.dumps([prev, at.isoformat(), str(actor_id), action,
                              str(document_id), outcome, detail], sort_keys=True, default=str)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        conn.execute(
            """INSERT INTO audit_events(at, actor_id, action, document_id, outcome, detail, prev_hash, hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (at, actor_id, action, document_id, outcome, Jsonb(detail), prev, digest))


def verify_chain(conn):
    """Recompute every hash from the start. Any edited, removed or reordered row breaks the chain."""
    prev, n = GENESIS, 0
    for r in conn.execute("SELECT * FROM audit_events ORDER BY id"):
        payload = json.dumps([prev, r["at"].astimezone(timezone.utc).isoformat(), str(r["actor_id"]), r["action"],
                              str(r["document_id"]), r["outcome"], r["detail"]], sort_keys=True, default=str)
        if r["prev_hash"] != prev or hashlib.sha256(payload.encode()).hexdigest() != r["hash"]:
            return {"ok": False, "checked": n, "broken_at": r["id"]}
        prev, n = r["hash"], n + 1
    return {"ok": True, "checked": n, "broken_at": None}
