import psycopg
from psycopg.rows import dict_row
from .config import DATABASE_URL


def get_conn():
    """One DB connection per request. autocommit: each statement saves itself,
    and we open explicit transactions (conn.transaction()) where we need several together."""
    with psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row) as conn:
        yield conn
