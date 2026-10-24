"""Helpers for CyberOS_Security."""
import os
from pathlib import Path

def ensure_dirs():
    root = Path(__file__).parent.parent
    for d in [
        "logs","reports/forensic","reports/scans",
        "security/keys","security/vault","security/integrity",
        "security/auth","security/honeypots",
        "quarantine/vault","sandbox/analysis","threat_db","data"
    ]:
        (root / d).mkdir(parents=True, exist_ok=True)
