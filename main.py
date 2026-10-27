#!/usr/bin/env python3
"""CyberOS Security 2026.2.1 — local security tools, CLI and Tkinter UI."""
import argparse
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
VERSION = "2026.2.1"


def check_deps():
    missing = []
    for name in ("psutil", "cryptography", "reportlab"):
        try:
            __import__(name)
        except ImportError:
            missing.append(name)
    if missing:
        raise RuntimeError("Modules absents : " + ", ".join(missing) +
                           ". Installer : python -m pip install -r requirements.txt")


def start(args):
    from utils.helpers import ensure_dirs
    from elpati.elpati_log import ElpatiLog
    from core.security_vault import SecurityVault
    ensure_dirs()
    vault = SecurityVault()
    if not vault.verify_integrity():
        raise RuntimeError("Vérification des sources échouée. Réinstaller la version complète; consulter docs/INSTALLATION_WINDOWS.md.")
    log = ElpatiLog()
    if not log.verify_chain()[0]:
        raise RuntimeError("Journal d'audit endommagé. Conserver les fichiers logs pour diagnostic.")
    if args.check:
        print("[OK] Dépendances et intégrité des sources vérifiées.")
        return
    log.info("CyberOS Security " + VERSION + " démarré")
    if args.cli or args.no_gui:
        from core.controller import CentralController
        CentralController().run_cli()
        return
    try:
        import tkinter as tk
        from gui.dashboard import launch_gui
    except ImportError:
        print("[INFO] Tkinter absent, passage en CLI.")
        from core.controller import CentralController
        CentralController().run_cli()
        return
    # Only a missing display triggers fallback. Application errors remain visible.
    try:
        launch_gui()
    except tk.TclError as exc:
        log.error(f"Tkinter: {exc}")
        if "display" in str(exc).lower():
            print(f"[INFO] GUI indisponible ({exc}), passage en CLI.")
            from core.controller import CentralController
            CentralController().run_cli()
        else:
            raise
    finally:
        log.flush_chain()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--no-gui", action="store_true")
    parser.add_argument("--check", action="store_true", help="Vérifier dépendances et intégrité")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    try:
        check_deps()
        from utils.instance_lock import InstanceLock
        with InstanceLock(ROOT / "security/instance.lock"):
            start(args)
        return 0
    except KeyboardInterrupt:
        print("\nOpération interrompue.")
        return 130
    except Exception as exc:
        print(f"[ERREUR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
