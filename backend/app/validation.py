import os
import re

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
# extension -> (content type, required first bytes). Extension alone is never trusted.
ALLOWED = {
    ".pdf": ("application/pdf", b"%PDF"),
    ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
    ".docx": (DOCX, b"PK\x03\x04"),
    ".txt": ("text/plain", None),
}


def safe_name(name: str) -> str:
    name = os.path.basename(name or "")
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:100] or "file"


def detect_type(filename: str, data: bytes):
    """Returns the content type, or None if the file is not allowed."""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED or not data:
        return None
    ctype, magic = ALLOWED[ext]
    if magic and not data.startswith(magic):
        return None
    if ext == ".txt":
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return ctype
