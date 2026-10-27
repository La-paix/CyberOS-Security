"""Owner-only offline licensing utility. Never distribute the private key."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import getpass
import json
import os
from pathlib import Path
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def issue(private_key, tier="PRO", days=365, machine_id="GLOBAL", now=None):
    if tier not in {"FREE", "PRO", "ENTERPRISE"} or not 1 <= days <= 36500:
        raise ValueError("Niveau ou durée invalide")
    now = now or datetime.now(timezone.utc)
    value = {"v": 2, "tier": tier, "issued": now.isoformat(),
             "expires": (now + timedelta(days=days)).isoformat(),
             "machine_id": machine_id, "id": uuid4().hex}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    encode = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    return "CYBEROS2." + encode(raw) + "." + encode(private_key.sign(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--private", type=Path, required=True, help="Chemin privé hors du dépôt")
    init.add_argument("--public", type=Path, required=True, help="security/license_public_key.pub à publier")
    sign = sub.add_parser("issue")
    sign.add_argument("--private", type=Path, required=True)
    sign.add_argument("--tier", choices=["FREE", "PRO", "ENTERPRISE"], default="PRO")
    sign.add_argument("--days", type=int, default=365)
    sign.add_argument("--machine-id", default="GLOBAL")
    args = parser.parse_args()
    password = getpass.getpass("Mot de passe de la clé privée : ").encode()
    if len(password) < 12:
        parser.error("Utiliser au moins 12 caractères")
    if args.command == "init":
        if args.private.exists() or args.public.exists():
            parser.error("Un fichier cible existe déjà; aucune clé remplacée.")
        private = Ed25519PrivateKey.generate()
        args.private.parent.mkdir(parents=True, exist_ok=True)
        args.public.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)))
        with args.public.open("xb") as stream:
            stream.write(private.public_key().public_bytes(serialization.Encoding.Raw,
                         serialization.PublicFormat.Raw))
        print("Clés créées. Sauvegarder la clé privée hors de GitHub; distribuer seulement la clé publique.")
    else:
        private = serialization.load_pem_private_key(args.private.read_bytes(), password=password)
        if not isinstance(private, Ed25519PrivateKey):
            parser.error("Clé Ed25519 requise")
        print(issue(private, args.tier, args.days, args.machine_id))


if __name__ == "__main__":
    main()
