"""Atomic local storage for installation state."""
import json
import os
from pathlib import Path
import re
import tempfile


def atomic_write(path, data, *, private=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    fd, name = tempfile.mkstemp(prefix=".cyberos-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            if private and os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, value):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2))


def safe_name(value):
    """Use an external label as a filename, never as a path."""
    value = re.sub(r"[^\w.\-]", "_", str(value), flags=re.UNICODE).strip(". ")
    return value[:120] or "report"


def child_file(directory, name):
    if not name or Path(name).name != name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("Nom de fichier invalide")
    directory = Path(directory).resolve()
    target = directory / name
    if target.is_symlink() or target.resolve().parent != directory:
        raise ValueError("Chemin hors du coffre")
    return target
