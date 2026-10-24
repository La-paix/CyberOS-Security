#!/usr/bin/env python3
"""
CyberOS_Security v2026.2 — Système ELPATI
Advanced EDR/XDR Platform — Protection locale 100%
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

def check_deps():
    missing = []
    for pkg, imp in [("psutil","psutil"),("cryptography","cryptography"),
                     ("reportlab","reportlab")]:
        try: __import__(imp)
        except ImportError: missing.append(pkg)
    if missing:
        print(f"[ERREUR] Modules manquants : {', '.join(missing)}")
        print(f"[FIX]   Lancez : pip install {' '.join(missing)}")
        sys.exit(1)

def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║           CyberOS_Security  v2026.2                       ║
║           Système ELPATI — EDR/XDR Platform               ║
║           Protection locale · IA hybride · 2026-2036      ║
╚═══════════════════════════════════════════════════════════╝""")

    check_deps()

    from utils.helpers import ensure_dirs
    ensure_dirs()

    from elpati.elpati_self_protection import ElpatiSelfProtection
    from elpati.elpati_log import ElpatiLog
    from core.security_vault import SecurityVault

    ElpatiSelfProtection().activate()
    log = ElpatiLog()
    log.info("CyberOS_Security v2026.2 démarré")

    vault = SecurityVault()
    if not vault.verify_integrity():
        log.critical("ECHEC VÉRIFICATION INTÉGRITÉ")
        print("[CRITIQUE] Vérification d'intégrité échouée.")
        sys.exit(1)

    log.info("Intégrité vérifiée. Système prêt.")

    if "--cli" in sys.argv or "--no-gui" in sys.argv:
        from core.controller import CentralController
        CentralController().run_cli()
    else:
        try:
            from gui.dashboard import launch_gui
            launch_gui()
        except Exception as e:
            print(f"[INFO] GUI indisponible ({e}), passage en mode CLI...")
            from core.controller import CentralController
            CentralController().run_cli()

if __name__ == "__main__":
    main()
