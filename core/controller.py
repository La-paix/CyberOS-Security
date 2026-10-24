"""CENTRAL CONTROLLER v2 - Full orchestration with AI integration."""
import os, json, threading, time
from datetime import datetime
from pathlib import Path

class CentralController:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_done = False
        return cls._instance

    def __init__(self):
        if self._init_done: return
        self._init_done = True
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_backend import ElpatiBackend
        from elpati.elpati_crypto import ElpatiCrypto
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        from elpati.elpati_payment import ElpatiPayment
        from core.ai_core import AICore
        from core.config import Config
        self.log = ElpatiLog()
        self.backend = ElpatiBackend()
        self.crypto = ElpatiCrypto()
        self.auth = ElpatiAuthVoice()
        self.payment = ElpatiPayment()
        self.ai = AICore()
        self.config = Config()
        self._modules = {}
        self._initialized = False
        self._alert_callbacks = []
        self._protection_active = False

    def initialize_all_modules(self):
        from elpati.elpati_monitor import ElpatiMonitor
        from elpati.elpati_behavior import ElpatiBehavior
        from elpati.elpati_memory_scan import ElpatiMemoryScan
        from elpati.elpati_network_guard import ElpatiNetworkGuard
        from elpati.elpati_ransom_guard import ElpatiRansomGuard
        from elpati.elpati_shield import ElpatiShield
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        from elpati.elpati_ai_analyzer import ElpatiAIAnalyzer
        from elpati.elpati_self_protection import ElpatiSelfProtection
        from core.engine import CyberEngine
        from quarantine.quarantine_manager import QuarantineManager
        from forensic.forensic_engine import ForensicEngine
        from sandbox.malware_lab import MalwareLab
        from elpati.elpati_scheduler import ElpatiScheduler
        from elpati.elpati_integrity import ElpatiIntegrity
        from elpati.elpati_vulnscan import ElpatiVulnScan
        from elpati.elpati_autoresponse import ElpatiAutoResponse
        from elpati.elpati_dashboard_data import ElpatiDashboardData

        sp = ElpatiSelfProtection()
        sp.activate()

        self._modules = {
            "monitor": ElpatiMonitor(),
            "behavior": ElpatiBehavior(),
            "memory_scan": ElpatiMemoryScan(),
            "network_guard": ElpatiNetworkGuard(),
            "ransom_guard": ElpatiRansomGuard(),
            "shield": ElpatiShield(),
            "threat_intel": ElpatiThreatIntel(),
            "ai_analyzer": ElpatiAIAnalyzer(),
            "engine": CyberEngine(),
            "quarantine": QuarantineManager(),
            "forensic": ForensicEngine(),
            "sandbox": MalwareLab(),
            "self_protect": sp,
            "scheduler": ElpatiScheduler(),
            "integrity": ElpatiIntegrity(),
            "vuln_scan": ElpatiVulnScan(),
            "auto_response": ElpatiAutoResponse(),
            "dashboard_data": ElpatiDashboardData(),
        }
        self._initialized = True
        self.log.info(f"Controller v2: {len(self._modules)} modules initialized")
        # Register alert callbacks
        for mod_name in ["monitor", "ransom_guard", "network_guard"]:
            mod = self._modules.get(mod_name)
            if hasattr(mod, "register_alert_callback"):
                mod.register_alert_callback(self._on_alert)

    def _on_alert(self, alert: dict):
        """Central alert handler with AI analysis and auto-response."""
        score = alert.get("score", 0)
        # AI-enhanced analysis
        ai_result = self.ai.analyze_threat({
            "type": alert.get("severity", "unknown"),
            "local_score": score,
            "indicators": {alert.get("message", ""): True},
        })
        alert["ai_analysis"] = ai_result
        final_score = max(score, ai_result.get("score", 0))

        # Auto-response logic
        if self.config.get("auto_protect", True):
            if final_score >= self.config.get("threat_score_kill", 80):
                pid = alert.get("pid")
                if pid and self._modules.get("shield"):
                    self._modules["shield"].kill_process(pid)
            elif final_score >= self.config.get("threat_score_isolate", 60):
                pid = alert.get("pid")
                if pid and self._modules.get("shield"):
                    self._modules["shield"].isolate_process(pid)

        self.log.threat(f"ALERT [{alert.get('severity')}] score={final_score}: {alert.get('message','')}")
        # Auto-response playbook
        if "auto_response" in self._modules:
            try:
                self._modules["auto_response"].process_alert(alert, self)
            except: pass
        for cb in self._alert_callbacks:
            try: cb(alert)
            except: pass

    def start_protection(self):
        if not self._initialized: self.initialize_all_modules()
        self._modules["monitor"].start()
        if self.payment.has_feature("network_guard"):
            self._modules["network_guard"].start()
        if self.payment.has_feature("ransomguard"):
            self._modules["ransom_guard"].start()
        self._protection_active = True
        self.backend.update_state("protection_active", True)
        # Start FIM monitoring
        if "integrity" in self._modules:
            try:
                self._modules["integrity"].create_baseline()
                self._modules["integrity"].start_monitoring(interval=120)
            except: pass
        # Start scheduler
        if "scheduler" in self._modules:
            try:
                sched = self._modules["scheduler"]
                sched.register_callback(self._on_scheduled_task)
                sched.start()
            except: pass
        self.log.info("Protection ACTIVE")

    def _on_scheduled_task(self, task):
        """Exécuter une tâche planifiée."""
        ttype = task.get("type","")
        try:
            if ttype == "quick_scan":
                self.run_quick_scan()
            elif ttype == "full_scan":
                import pathlib
                self.run_full_scan(path=str(pathlib.Path.home()))
            elif ttype == "memory_scan" and "memory_scan" in self._modules:
                self._modules["memory_scan"].scan_all_processes(top_risk_only=True)
            elif ttype == "report" and "forensic" in self._modules:
                self._modules["forensic"].generate_report(f"SCHED-{task.get('name','?')}")
            self.log.audit(f"Tâche planifiée exécutée: {task.get('name','?')}")
        except Exception as e:
            self.log.error(f"Tâche planifiée erreur: {e}")

    def stop_protection(self):
        for key in ["monitor", "network_guard", "ransom_guard"]:
            mod = self._modules.get(key)
            if mod and hasattr(mod, "stop"): mod.stop()
        self._protection_active = False
        self.backend.update_state("protection_active", False)

    def run_quick_scan(self, callback=None):
        if not self._initialized: self.initialize_all_modules()
        self.backend.increment("scan_count")
        result = self._modules["engine"].quick_scan(callback=callback)
        self._post_process_scan(result)
        return result

    def run_full_scan(self, path=None, callback=None):
        if not self._initialized: self.initialize_all_modules()
        self.backend.increment("scan_count")
        result = self._modules["engine"].full_scan(root_path=path, callback=callback)
        self._post_process_scan(result)
        return result

    def _post_process_scan(self, result):
        threats = result.get("threats", [])
        if threats:
            self.backend.increment("threats_found", len(threats))
            # Run AI correlation on all threats
            for t in threats[:10]:  # Limit API calls
                ctx = {"type": "file_threat", "file_path": t.get("path", ""),
                       "local_score": t.get("score", 0),
                       "indicators": {"known_malware": t.get("type") == "KNOWN_MALWARE"}}
                ai = self.ai.analyze_threat(ctx)
                t["ai_verdict"] = ai.get("verdict", "")
                t["ai_actions"] = ai.get("actions", [])
            # Auto-quarantine if configured
            if self.config.get("auto_quarantine", False):
                for t in threats:
                    if t.get("score", 0) >= 80 and os.path.exists(t.get("path", "")):
                        self._modules["quarantine"].quarantine_file(
                            t["path"], {"type": t.get("type"), "score": t.get("score")})
                        self.backend.increment("quarantined")

    def get_system_status(self):
        monitor = self._modules.get("monitor")
        snapshot = monitor.get_system_snapshot() if monitor else {}
        return {
            "initialized": self._initialized,
            "protection_active": self._protection_active,
            "system": snapshot,
            "state": self.backend.get_state(),
            "license": self.payment.get_info(),
            "ai_mode": "CLAUDE" if self.ai.is_claude_available() else "LOCAL",
            "ai_key_set": self.ai.has_api_key(),
            "modules": list(self._modules.keys()),
            "ts": datetime.utcnow().isoformat()
        }

    def register_alert_callback(self, cb): self._alert_callbacks.append(cb)

    def run_cli(self):
        """CLI interface."""
        print("\n[CyberOS_Security v2026.2 - ELPATI CLI]")
        pw = input("Mot de passe (défaut: cyberos2026): ").strip() or "cyberos2026"
        if not self.auth.verify_password(pw):
            print("[ERREUR] Authentification échouée"); return
        print("[OK] Authentifié\n")
        self.initialize_all_modules()
        while True:
            print("\n" + "="*55)
            print("  CYBEROS_SECURITY v2026.2 - ELPATI SYSTEM")
            print("="*55)
            menu = [
                ("1", "Scan rapide"), ("2", "Scan complet"), ("3", "Processus"),
                ("4", "Mémoire"), ("5", "Réseau"), ("6", "Rapport forensic"),
                ("7", "Statut système"), ("8", "Quarantaine"),
                ("9", "Sandbox analyse"), ("10", "Analyse IA"),
                ("11", "Générer licence"), ("12", "Activer licence"),
                ("0", "Quitter"),
            ]
            for k, v in menu: print(f"  {k:3}. {v}")
            try: choice = input("\n> ").strip()
            except (EOFError, KeyboardInterrupt): break

            if choice == "1":
                print("[*] Scan rapide...")
                def cb(p): print(f"\r  {p['scanned']}/{p['total']} | Threats: {p['threats']}", end="", flush=True)
                r = self.run_quick_scan(callback=cb)
                print(f"\n[OK] {r['files_scanned']} fichiers | {r['threats_found']} menaces | {r['duration_sec']}s")
                if r.get("threats"):
                    for t in r["threats"][:5]:
                        print(f"  [{t.get('type','?')}] {t.get('score',0)} | {t.get('path','?')}")
                        if t.get("ai_verdict"): print(f"      IA: {t['ai_verdict']}")

            elif choice == "11":
                print("\n[GÉNÉRATEUR DE LICENCES]")
                print("1. Démo 7j PRO | 2. Essai 30j PRO | 3. PRO 1 an | 4. ENTERPRISE 1 an")
                c2 = input("Choix: ").strip()
                keys_map = {"1": ("PRO",7), "2": ("PRO",30), "3": ("PRO",365), "4": ("ENTERPRISE",365)}
                if c2 in keys_map:
                    t, d = keys_map[c2]
                    key = self.payment.generate_key(t, d)
                    print(f"\n[CLÉ] {key}")

            elif choice == "12":
                key = input("Entrez la clé de licence: ").strip()
                if key:
                    result = self.payment.activate(key)
                    if result["success"]:
                        print(f"[OK] Licence activée: {result['tier']} | Expire: {result['expires']}")
                    else:
                        print(f"[ERREUR] {result['error']}")

            elif choice == "0":
                self.stop_protection(); break
