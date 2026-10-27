"""Explicit v2026.2 AES migration with backup, validation and rollback.

Close CyberOS first. python tools/migrate_legacy.py
After a power loss: python tools/migrate_legacy.py --rollback
Never upload security/, quarantine/vault or .local-backups to GitHub.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utils.storage import atomic_write, write_json

LEGACY_PASSWORD = b"CyberOS_ELPATI_2026_MasterKey_v2"
PREFIX = b"CYBEROS2:"


def rollback(root=ROOT):
    journal = root / "security/migration_in_progress.json"
    state = json.loads(journal.read_text(encoding="utf-8"))
    backup = root / ".local-backups" / state["backup_id"]
    if backup.resolve().parent != (root / ".local-backups").resolve():
        raise ValueError("Chemin de sauvegarde invalide")
    for rel in state["files"]:
        if Path(rel).is_absolute() or ".." in Path(rel).parts:
            raise ValueError("Chemin de restauration invalide")
        saved = backup / rel
        target = root / rel
        if saved.exists():
            atomic_write(target, saved.read_bytes())
        else:
            target.unlink(missing_ok=True)
    journal.unlink()
    return str(backup)


def migrate(root=ROOT):
    keys = root / "security/keys"
    journal = root / "security/migration_in_progress.json"
    if journal.exists():
        raise RuntimeError("Migration inachevée : exécuter --rollback avant de recommencer.")
    if (keys / "master.key").exists():
        raise RuntimeError("La clé v2 existe déjà. Aucune donnée modifiée.")
    salt_file = keys / "master.salt"
    salt = salt_file.read_bytes()
    if len(salt) != 32:
        raise ValueError("Sel historique invalide")
    old_key = hashlib.pbkdf2_hmac("sha256", LEGACY_PASSWORD, salt, 600000)
    candidates = []
    for rel, pattern in (("security/auth", "*.enc"), ("security/vault", "*.enc"),
                         ("security/keys", "*.enc"), ("security/keys", "*.lic"),
                         ("quarantine/vault", "*.qvault")):
        candidates.extend((root / rel).glob(pattern))
    new_key = AESGCM.generate_key(bit_length=256)
    backup_id = "migration-" + uuid4().hex
    backup = root / ".local-backups" / backup_id
    staging = backup / ".staged"
    staging.mkdir(parents=True, mode=0o700)
    converted = []
    # Authenticate every old file before touching any live data.
    for file in candidates:
        if file.is_symlink():
            raise ValueError(f"Lien symbolique refusé : {file}")
        raw = base64.b64decode(file.read_bytes(), validate=True)
        if len(raw) < 28:
            raise ValueError(f"Données tronquées : {file}")
        try:
            plain = AESGCM(old_key).decrypt(raw[:12], raw[12:], None)
        except Exception as exc:
            raise ValueError(f"Déchiffrement impossible, fichier conservé : {file}") from exc
        nonce = os.urandom(12)
        updated = PREFIX + base64.b64encode(nonce + AESGCM(new_key).encrypt(nonce, plain, PREFIX))
        if AESGCM(new_key).decrypt(nonce, base64.b64decode(updated[len(PREFIX):])[12:], PREFIX) != plain:
            raise ValueError("Vérification de migration échouée")
        rel = file.relative_to(root).as_posix()
        atomic_write(staging / rel, updated)
        converted.append(rel)
    # Preserve old evidence integrity records independently of the new source manifest.
    evidence_index = {}
    for rel in converted:
        if rel.startswith("security/vault/") and rel.endswith(".enc"):
            raw = base64.b64decode((root / rel).read_bytes(), validate=True)
            plain = AESGCM(old_key).decrypt(raw[:12], raw[12:], None)
            evidence_index[Path(rel).name] = hashlib.sha256(plain).hexdigest()
    config_file = root / "data/config.json"
    safe_config = None
    if config_file.exists():
        safe_config = json.loads(config_file.read_text(encoding="utf-8"))
        if not isinstance(safe_config, dict):
            raise ValueError("Configuration historique invalide")
        safe_config.update(auto_protect=False, auto_quarantine=False)
    extra = ["security/keys/master.key", "security/keys/installation.initialized",
             "security/keys/auth.initialized", "security/vault/index.json"]
    if safe_config is not None:
        extra.append("data/config.json")
    file_list = sorted(set(converted + extra + ["security/keys/master.salt"]))
    for rel in file_list:
        source = root / rel
        if source.exists():
            atomic_write(backup / rel, source.read_bytes())
    write_json(backup / "backup_manifest.json", {"files": file_list, "version": "2026.2"})
    write_json(journal, {"backup_id": backup_id, "files": file_list})
    try:
        for rel in converted:
            atomic_write(root / rel, (staging / rel).read_bytes())
        if evidence_index:
            write_json(root / "security/vault/index.json", evidence_index)
        if safe_config is not None:
            write_json(config_file, safe_config)
        atomic_write(keys / "master.key", new_key)
        atomic_write(keys / "installation.initialized", "CyberOS 2026.2.1\n")
        if (root / "security/auth/password.enc").exists():
            atomic_write(keys / "auth.initialized", "initialized\n")
        journal.unlink()
    except Exception:
        rollback(root)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return {"converted": len(converted), "backup": str(backup)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    try:
        result = rollback() if args.rollback else migrate()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as exc:
        print(f"[ERREUR] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
