"""ELPATI CRYPTO - AES-256-GCM + RSA-4096 + SHA-3 cryptography."""
import os, base64, hashlib, json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

KEYS_DIR = Path(__file__).parent.parent / "security" / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)

class ElpatiCrypto:
    def __init__(self):
        self._key = self._derive_key()
        self._rsa_priv = None
        self._rsa_pub = None
        self._load_rsa()

    def _derive_key(self):
        sf = KEYS_DIR / "master.salt"
        salt = sf.read_bytes() if sf.exists() else os.urandom(32)
        if not sf.exists(): sf.write_bytes(salt)
        pw = b"CyberOS_ELPATI_2026_MasterKey_v2"
        if HAS_CRYPTO:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                             iterations=600000, backend=default_backend())
            return kdf.derive(pw)
        return hashlib.pbkdf2_hmac("sha256", pw, salt, 600000)

    def _load_rsa(self):
        pf = KEYS_DIR / "rsa_priv.pem"
        uf = KEYS_DIR / "rsa_pub.pem"
        if not HAS_CRYPTO: return
        if pf.exists():
            with open(pf, "rb") as f: self._rsa_priv = serialization.load_pem_private_key(f.read(), password=None)
            with open(uf, "rb") as f: self._rsa_pub = serialization.load_pem_public_key(f.read())
        else:
            self._rsa_priv = rsa.generate_private_key(65537, 4096, default_backend())
            self._rsa_pub = self._rsa_priv.public_key()
            pf.write_bytes(self._rsa_priv.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            uf.write_bytes(self._rsa_pub.public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))

    def encrypt(self, data: bytes) -> bytes:
        if HAS_CRYPTO:
            nonce = os.urandom(12)
            return base64.b64encode(nonce + AESGCM(self._key).encrypt(nonce, data, None))
        k = self._key
        return base64.b64encode(bytes([data[i] ^ k[i % len(k)] for i in range(len(data))]))

    def decrypt(self, data: bytes) -> bytes:
        raw = base64.b64decode(data)
        if HAS_CRYPTO:
            return AESGCM(self._key).decrypt(raw[:12], raw[12:], None)
        k = self._key
        return bytes([raw[i] ^ k[i % len(k)] for i in range(len(raw))])

    def hash_file(self, path):
        h = hashlib.sha3_256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
            return h.hexdigest()
        except: return ""

    def hash_data(self, d: bytes) -> str: return hashlib.sha3_256(d).hexdigest()
    def hash_sha256(self, d: bytes) -> str: return hashlib.sha256(d).hexdigest()

    def sign(self, data: bytes) -> str:
        if HAS_CRYPTO and self._rsa_priv:
            sig = self._rsa_priv.sign(data, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return base64.b64encode(sig).decode()
        return self.hash_sha256(data)

    def verify(self, data: bytes, sig: str) -> bool:
        try:
            if HAS_CRYPTO and self._rsa_pub:
                self._rsa_pub.verify(base64.b64decode(sig), data, padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                return True
            return self.hash_sha256(data) == sig
        except: return False
