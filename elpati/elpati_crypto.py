"""AES-256-GCM with an installation secret; RSA-PSS signatures; file hashes.

Keep security/keys private and backed up. Legacy installations must migrate
explicitly. No weak encryption fallback is supported.
"""
import base64
import hashlib
import os
from pathlib import Path
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utils.storage import atomic_write

HAS_CRYPTO = True
KEYS_DIR = Path(__file__).resolve().parent.parent / "security" / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)
_KEY_LOCK = threading.RLock()
_PREFIX = b"CYBEROS2:"


class KeyRecoveryRequired(RuntimeError):
    pass


class ElpatiCrypto:
    def __init__(self):
        self._key = self._derive_key()
        self._rsa_priv = None
        self._rsa_pub = None

    def _derive_key(self):
        with _KEY_LOCK:
            if (KEYS_DIR.parent / "migration_in_progress.json").exists():
                raise KeyRecoveryRequired("Migration interrompue. Fermer CyberOS et lancer python tools/migrate_legacy.py --rollback")
            key_file = KEYS_DIR / "master.key"
            if key_file.is_symlink():
                raise KeyRecoveryRequired("La clé ne peut pas être un lien symbolique.")
            if key_file.exists():
                key = key_file.read_bytes()
                if len(key) != 32:
                    raise KeyRecoveryRequired("Clé locale corrompue. Restaurer la sauvegarde de security/keys.")
                if os.name != "nt":
                    key_file.chmod(0o600)
                return key
            root = KEYS_DIR.parent.parent
            marker = KEYS_DIR / "installation.initialized"
            encrypted_data = (any((root / "security/auth").glob("*.enc")) or
                              any((root / "security/vault").glob("*.enc")) or
                              any((root / "quarantine/vault").glob("*.qvault")))
            if (KEYS_DIR / "master.salt").exists():
                raise KeyRecoveryRequired("Anciennes clés détectées. Fermer CyberOS puis lancer : python tools/migrate_legacy.py")
            if marker.exists() or encrypted_data:
                raise KeyRecoveryRequired("Clé locale absente. Restaurer security/keys depuis votre sauvegarde.")
            key = AESGCM.generate_key(bit_length=256)
            try:
                fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                return self._derive_key()
            with os.fdopen(fd, "wb") as stream:
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
            atomic_write(marker, "CyberOS 2026.2.1\n")
            return key

    def _load_rsa(self):
        with _KEY_LOCK:
            if self._rsa_priv is not None:
                return
            private_file = KEYS_DIR / "rsa_private.enc"
            old_file = KEYS_DIR / "rsa_priv.pem"
            if private_file.exists():
                raw = self.decrypt(private_file.read_bytes())
                self._rsa_priv = serialization.load_pem_private_key(raw, password=None)
            elif old_file.exists():
                raw = old_file.read_bytes()
                self._rsa_priv = serialization.load_pem_private_key(raw, password=None)
                atomic_write(private_file, self.encrypt(raw))
                old_file.unlink()
            else:
                if (KEYS_DIR / "rsa_pub.pem").exists():
                    raise KeyRecoveryRequired("Clé privée RSA absente. Restaurer la sauvegarde de security/keys.")
                self._rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
                raw = self._rsa_priv.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                atomic_write(private_file, self.encrypt(raw))
            self._rsa_pub = self._rsa_priv.public_key()
            atomic_write(KEYS_DIR / "rsa_pub.pem", self._rsa_pub.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        return _PREFIX + base64.b64encode(nonce + AESGCM(self._key).encrypt(nonce, data, _PREFIX))

    def decrypt(self, data: bytes) -> bytes:
        if not data.startswith(_PREFIX):
            raise KeyRecoveryRequired("Ancien format chiffré : migration explicite requise.")
        raw = base64.b64decode(data[len(_PREFIX):], validate=True)
        if len(raw) < 28:
            raise ValueError("Données chiffrées tronquées")
        return AESGCM(self._key).decrypt(raw[:12], raw[12:], _PREFIX)

    def hash_file(self, path):
        try:
            return self.file_hashes(path)["sha3_256"]
        except OSError:
            return ""

    def file_hashes(self, path):
        algorithms = {"md5": hashlib.md5(usedforsecurity=False),
                      "sha256": hashlib.sha256(), "sha3_256": hashlib.sha3_256()}
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                for digest in algorithms.values():
                    digest.update(chunk)
        return {name: digest.hexdigest() for name, digest in algorithms.items()}

    def hash_data(self, data: bytes) -> str:
        return hashlib.sha3_256(data).hexdigest()

    def hash_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def sign(self, data: bytes) -> str:
        self._load_rsa()
        return base64.b64encode(self._rsa_priv.sign(data, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())).decode()

    def verify(self, data: bytes, sig: str) -> bool:
        try:
            self._load_rsa()
            self._rsa_pub.verify(base64.b64decode(sig, validate=True), data, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
