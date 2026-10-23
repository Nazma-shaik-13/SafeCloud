"""Creates demo accounts (one per role). Run once: python seed.py"""
import psycopg
from app.config import DATABASE_URL
from app.security import hash_password

DEMO = [("admin@trustvault.test", "admin"), ("owner@trustvault.test", "owner"), ("viewer@trustvault.test", "viewer")]
with psycopg.connect(DATABASE_URL, autocommit=True) as c:
    for email, role in DEMO:
        c.execute("INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                  (email, hash_password("ChangeMe-Demo-123"), role))
print("Seeded:", [e for e, _ in DEMO])
