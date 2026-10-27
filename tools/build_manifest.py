"""Explicit release operation: regenerate hashes only after reviewing source."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.security_vault import source_files, INTEGRITY_DIR
from utils.storage import write_json


def build(root=None):
    files = source_files() if root is None else source_files(root)
    result = {name: hashlib.sha3_256(file.read_bytes()).hexdigest()
              for name, file in sorted(files.items())}
    result["_version"] = "2026.2.1"
    result["_algorithm"] = "sha3_256"
    target = INTEGRITY_DIR / "manifest.json" if root is None else root / "security/integrity/manifest.json"
    write_json(target, result)
    return result


if __name__ == "__main__":
    print(f"Manifest: {len(build()) - 2} sources. Ce manifeste n'est pas une signature d'éditeur.")
