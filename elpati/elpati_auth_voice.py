"""ELPATI AUTH - Password management with change capability. Fixed for cross-platform."""
import hashlib, time, json, os
from pathlib import Path

AUTH_DIR = Path(__file__).parent.parent / "security" / "auth"
AUTH_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_PASSWORD = "cyberos2026"

class ElpatiAuthVoice:
    # No singleton here - causes issues with encrypted files across machines
    def __init__(self):
        from elpati.elpati_crypto import ElpatiCrypto
        from elpati.elpati_log import ElpatiLog
        self.crypto = ElpatiCrypto()
        self.log = ElpatiLog()
        self._pw_file = AUTH_DIR / "password.enc"
        self._meta_file = AUTH_DIR / "auth_meta.json"
        self._attempts = 0
        self._locked_until = 0
        self._session = None
        self._meta = self._load_meta()
        self._ensure_default_password()

    def _ensure_default_password(self):
        """Always ensure a valid password file exists."""
        if not self._pw_file.exists():
            self._write_password(DEFAULT_PASSWORD)
            self.log.audit("Auth: Default password initialized")
            return
        # Verify the file is readable with current crypto key
        try:
            stored = self.crypto.decrypt(self._pw_file.read_bytes()).decode()
            if len(stored) < 32:  # SHA3-256 is 64 chars
                raise ValueError("Invalid hash")
        except Exception:
            # File exists but can't be read (different machine/key) - reset to default
            self.log.warning("Auth: Password file corrupted or from different install - resetting to default")
            self._pw_file.unlink(missing_ok=True)
            self._write_password(DEFAULT_PASSWORD)

    def _write_password(self, password: str):
        h = self.crypto.hash_data(password.encode())
        self._pw_file.write_bytes(self.crypto.encrypt(h.encode()))

    def _load_meta(self):
        if self._meta_file.exists():
            try:
                return json.loads(self._meta_file.read_text())
            except:
                pass
        return {"created": "", "last_login": "", "login_count": 0, "password_changed": False}

    def _save_meta(self):
        try:
            self._meta_file.write_text(json.dumps(self._meta, indent=2))
        except:
            pass

    def set_password(self, password: str) -> bool:
        if len(password) < 6:
            return False
        self._write_password(password)
        self._meta["password_changed"] = True
        import datetime
        self._meta["pw_changed_at"] = datetime.datetime.utcnow().isoformat()
        self._save_meta()
        self.log.audit("Auth: Password updated")
        return True

    def verify_password(self, password: str) -> bool:
        if time.time() < self._locked_until:
            return False
        try:
            encrypted = self._pw_file.read_bytes()
            stored_hash = self.crypto.decrypt(encrypted).decode()
            input_hash = self.crypto.hash_data(password.encode())
            if stored_hash == input_hash:
                self._attempts = 0
                self._session = self.crypto.hash_data(f"{password}{time.time()}".encode())[:32]
                import datetime
                self._meta["last_login"] = datetime.datetime.utcnow().isoformat()
                self._meta["login_count"] = self._meta.get("login_count", 0) + 1
                self._save_meta()
                self.log.audit("Auth: Login successful")
                return True
            self._attempts += 1
            if self._attempts >= 5:
                self._locked_until = time.time() + 300
                self.log.warning("Auth: Account locked 5 minutes")
            return False
        except Exception as e:
            self.log.error(f"Auth: verify error: {e}")
            # If we can't verify, reset to default and try again
            self._pw_file.unlink(missing_ok=True)
            self._write_password(DEFAULT_PASSWORD)
            return self.crypto.hash_data(password.encode()) == self.crypto.hash_data(DEFAULT_PASSWORD.encode())

    def change_password(self, current: str, new_pw: str, confirm: str) -> dict:
        if not self.verify_password(current):
            return {"success": False, "error": "Mot de passe actuel incorrect"}
        if new_pw != confirm:
            return {"success": False, "error": "Les mots de passe ne correspondent pas"}
        if len(new_pw) < 6:
            return {"success": False, "error": "Minimum 6 caractères requis"}
        self.set_password(new_pw)
        return {"success": True}

    def logout(self):
        self._session = None

    def is_locked(self):
        return time.time() < self._locked_until

    def get_status(self):
        return {
            "attempts": self._attempts,
            "locked": self.is_locked(),
            "session_active": self._session is not None,
            "password_changed": self._meta.get("password_changed", False),
            "last_login": self._meta.get("last_login", ""),
            "login_count": self._meta.get("login_count", 0)
        }
