"""Local password authentication. Corruption never resets authentication."""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from datetime import datetime
from pathlib import Path
from utils.storage import atomic_write, write_json

AUTH_DIR = Path(__file__).resolve().parent.parent / "security" / "auth"
AUTH_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_PASSWORD = "cyberos2026"  # Legacy installs only; never initialized on a fresh install.
_AUTH_LOCK = threading.RLock()


class ElpatiAuthVoice:
    def __init__(self):
        from elpati.elpati_crypto import ElpatiCrypto, KEYS_DIR
        from elpati.elpati_log import ElpatiLog
        self.crypto = ElpatiCrypto()
        self.log = ElpatiLog()
        self._pw_file = AUTH_DIR / "password.enc"
        self._meta_file = AUTH_DIR / "auth_meta.json"
        self._marker = KEYS_DIR / "auth.initialized"
        self._session = None
        self._auth_error = ""
        with _AUTH_LOCK:
            self._meta = self._load_meta()
            self._attempts = self._meta.get("attempts", 0)
            self._locked_until = self._meta.get("locked_until", 0)
            self.needs_setup = not any(p.exists() for p in
                                       (self._pw_file, self._meta_file, self._marker))
            if not self.needs_setup:
                try:
                    self._read_password()
                except Exception:
                    self._auth_error = "Authentification endommagée. Restaurer security/auth et security/keys depuis la sauvegarde."
                    self.log.error(self._auth_error)

    def _load_meta(self):
        default = {"created": "", "last_login": "", "login_count": 0,
                   "password_changed": False, "attempts": 0, "locked_until": 0}
        if self._meta_file.exists():
            try:
                value = json.loads(self._meta_file.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("Invalid metadata")
                default.update(value)
                if not isinstance(default["attempts"], int) or not isinstance(default["locked_until"], (int, float)):
                    raise ValueError("Invalid lockout")
            except Exception:
                self._auth_error = "Métadonnées d'authentification corrompues."
                default.update(attempts=5, locked_until=time.time() + 300)
        return default

    def _save_meta(self):
        self._meta.update(attempts=self._attempts, locked_until=self._locked_until)
        write_json(self._meta_file, self._meta)

    def _read_password(self):
        raw = self.crypto.decrypt(self._pw_file.read_bytes()).decode("utf-8")
        if len(raw) == 64 and all(c in "0123456789abcdef" for c in raw):
            return {"legacy_hash": raw}
        value = json.loads(raw)
        if (value.get("algorithm") != "pbkdf2-sha256" or
            value.get("iterations") != 600000 or
            len(base64.b64decode(value["salt"], validate=True)) != 32 or
            len(bytes.fromhex(value["digest"])) != 32):
            raise ValueError("Format de mot de passe invalide")
        return value

    def _write_password(self, password):
        salt = secrets.token_bytes(32)
        value = {"algorithm": "pbkdf2-sha256", "iterations": 600000,
                 "salt": base64.b64encode(salt).decode(),
                 "digest": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000).hex()}
        atomic_write(self._pw_file, self.crypto.encrypt(json.dumps(value).encode()))
        atomic_write(self._marker, "initialized\n")

    def set_password(self, password: str) -> bool:
        """Initial setup or authenticated password change only."""
        with _AUTH_LOCK:
            if self._auth_error or len(password) < 12 or not (self.needs_setup or self._session):
                return False
            self._write_password(password)
            self.needs_setup = False
            self._meta["password_changed"] = True
            self._meta["pw_changed_at"] = datetime.utcnow().isoformat()
            self._attempts = 0
            self._locked_until = 0
            self._save_meta()
            self.log.audit("Auth: Password updated")
            return True

    def verify_password(self, password: str) -> bool:
        with _AUTH_LOCK:
            if self.needs_setup or self._auth_error:
                return False
            # Refresh lockout persisted by another login widget/instance.
            self._meta = self._load_meta()
            self._attempts = self._meta.get("attempts", 0)
            self._locked_until = self._meta.get("locked_until", 0)
            if self._auth_error or self.is_locked():
                return False
            try:
                stored = self._read_password()
                if "legacy_hash" in stored:
                    valid = hmac.compare_digest(stored["legacy_hash"], self.crypto.hash_data(password.encode()))
                else:
                    salt = base64.b64decode(stored["salt"], validate=True)
                    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, stored["iterations"]).hex()
                    valid = hmac.compare_digest(stored["digest"], candidate)
                if valid:
                    self._session = secrets.token_hex(32)
                    self._attempts = 0
                    self._locked_until = 0
                    self._meta["last_login"] = datetime.utcnow().isoformat()
                    self._meta["login_count"] = self._meta.get("login_count", 0) + 1
                    if "legacy_hash" in stored:
                        self._write_password(password)
                    self._save_meta()
                    self.log.audit("Auth: Login successful")
                    return True
                self._attempts += 1
                if self._attempts >= 5:
                    self._locked_until = time.time() + 300
                self._save_meta()
                return False
            except Exception:
                self._auth_error = "Fichier d'authentification illisible. Restauration requise."
                self.log.error(self._auth_error)
                return False

    def change_password(self, current: str, new_pw: str, confirm: str) -> dict:
        if not self.verify_password(current):
            return {"success": False, "error": self._auth_error or "Mot de passe actuel incorrect"}
        if new_pw != confirm:
            return {"success": False, "error": "Les mots de passe ne correspondent pas"}
        if len(new_pw) < 12:
            return {"success": False, "error": "Minimum 12 caractères requis"}
        if not self.set_password(new_pw):
            return {"success": False, "error": "Mise à jour du mot de passe refusée"}
        return {"success": True}

    def logout(self):
        self._session = None

    def is_locked(self):
        return time.time() < self._locked_until

    def get_status(self):
        return {"attempts": self._attempts, "locked": self.is_locked(),
                "session_active": self._session is not None,
                "password_changed": self._meta.get("password_changed", False),
                "last_login": self._meta.get("last_login", ""),
                "login_count": self._meta.get("login_count", 0),
                "needs_setup": self.needs_setup, "error": self._auth_error}
