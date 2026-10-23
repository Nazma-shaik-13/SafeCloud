from dotenv import load_dotenv

load_dotenv()   # reads backend/.env so uvicorn, seed.py and pytest all see DATABASE_URL
import os

DATABASE_URL = os.environ["DATABASE_URL"]            # set in .env, never committed
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
MAX_UPLOAD = 5 * 1024 * 1024                         # 5 MB
SESSION_HOURS = 8
MAX_FAILED = 5                                       # failed logins before lockout
LOCK_MINUTES = 15
