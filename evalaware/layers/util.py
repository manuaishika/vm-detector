import os
from pathlib import Path
from typing import Optional


def read(root: Path, rel: str, limit: int = 65536) -> Optional[str]:
    try:
        with open(Path(root) / rel.lstrip("/"), "r", errors="replace") as f:
            return f.read(limit)
    except (OSError, ValueError):
        return None


def exists(root: Path, rel: str) -> bool:
    return os.path.exists(Path(root) / rel.lstrip("/"))


def listdir(root: Path, rel: str):
    try:
        return sorted(os.listdir(Path(root) / rel.lstrip("/")))
    except OSError:
        return None
