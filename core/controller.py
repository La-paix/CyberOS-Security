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
        self._init_done = True

    def initialize_all_modules(self):
        if self._initialized:
            return
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
        self._modules["shield"].set_protection_level(
            "ACTIVE" if self.config.get("auto_protect", False) else "PASSIVE")
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
        review_only = bool(alert.get("review_required"))
        # AI-enhanced analysis
        ai_result = self.ai.analyze_threat({
            "type": alert.get("severity", "unknown"),
            "local_score": score,
            "unconfirmed_file": review_only,
            "indicators": {alert.get("message", ""): True},
        })
        alert["ai_analysis"] = ai_result
        final_score = max(score, ai_result.get("score", 0))

        # Apply the current setting, including changes made after startup.
        shield = self._modules.get("shield")
        requested_level = "ACTIVE" if self.config.get("auto_protect", False) else "PASSIVE"
        if shield and shield.get_status()["protection_level"] != requested_level:
            shield.set_protection_level(requested_level)
        if self.config.get("auto_protect", False) and not review_only:
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
        if "auto_response" in self._modules and not review_only:
            try:
                self._modules["auto_response"].process_alert(alert, self)
            except: pass
        for cb in self._alert_callbacks:
            try: cb(alert)
            except: pass

    def start_protection(self):
        if self._protection_active:
            return
        if not self._initialized: self.initialize_all_modules()
        if self.payment.has_feature("realtime_monitor"):
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
        for key in ["monitor", "network_guard", "ransom_guard", "scheduler"]:
            mod = self._modules.get(key)
            if mod and hasattr(mod, "stop"): mod.stop()
        if "integrity" in self._modules:
            self._modules["integrity"].stop_monitoring()
        if "self_protect" in self._modules:
            self._modules["self_protect"].deactivate()
        if "engine" in self._modules:
            self._modules["engine"].stop_scan()
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
                if not t.get("confirmed"):
                    t["ai_verdict"] = "Indice statique a examiner; infection non confirmee."
                    t["ai_actions"] = ["INVESTIGATE"]
                    continue
                ctx = {"type": "file_threat", "file_path": t.get("path", ""),
                       "local_score": t.get("score", 0),
                       "indicators": {"known_malware": t.get("type") == "KNOWN_MALWARE"}}
                ai = self.ai.analyze_threat(ctx)
                t["ai_verdict"] = ai.get("verdict", "")
                t["ai_actions"] = ai.get("actions", [])
            # Auto-quarantine if configured
            if self.config.get("auto_quarantine", False):
                for t in threats:
                    if (t.get("confirmed") and t.get("type") == "KNOWN_MALWARE" and
                            t.get("score", 0) >= 80 and os.path.exists(t.get("path", ""))):
                        outcome = self._modules["quarantine"].quarantine_file(
                            t["path"], {"type": t.get("type"), "score": t.get("score")})
                        if outcome.get("success"):
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
        """Complete interactive command-line interface."""
        from getpass import getpass
        print("\n[CyberOS Security 2026.2.1 — CLI]")
        if self.auth.needs_setup:
            print("Première installation : créer votre mot de passe (12 caractères minimum).")
            new = getpass("Nouveau mot de passe : ")
            if new != getpass("Confirmer : ") or not self.auth.set_password(new):
                print("[ERREUR] Confirmation différente ou mot de passe trop court.")
                return
        try:
            password = getpass("Mot de passe : ")
        except (EOFError, KeyboardInterrupt):
            return
        if not self.auth.verify_password(password):
            print("[ERREUR] " + (self.auth.get_status().get("error") or "Authentification refusée"))
            return
        self.initialize_all_modules()
        menu = [("1", "Scan rapide"), ("2", "Scan complet d'un dossier"), ("3", "Processus"),
                ("4", "Mémoire (métadonnées)"), ("5", "Connexions réseau"),
                ("6", "Rapport forensic"), ("7", "Statut système"), ("8", "Quarantaine"),
                ("9", "Analyse statique d'un fichier"), ("10", "Analyse locale"),
                ("11", "Informations de licence"), ("12", "Activer licence"),
                ("13", "Changer le mot de passe"), ("14", "Analyse URL"),
                ("15", "Contrôles de configuration"), ("0", "Quitter")]
        try:
            while True:
                print("\n" + "\n".join(f"  {key}. {label}" for key, label in menu))
                try:
                    choice = input("> ").strip()
                    if choice == "0":
                        break
                    if choice in ("1", "2"):
                        if choice == "1":
                            result = self.run_quick_scan()
                        else:
                            path = input("Dossier ou fichier à scanner : ").strip().strip('"')
                            if not path:
                                print("Chemin requis.")
                                continue
                            result = self.run_full_scan(path=path)
                    elif choice == "3":
                        result = self._modules["engine"].scan_processes()
                    elif choice == "4":
                        result = self._modules["memory_scan"].scan_all_processes(top_risk_only=True)
                    elif choice == "5":
                        result = self._modules["network_guard"].get_active_connections()
                    elif choice == "6":
                        result = {"report": self._modules["forensic"].generate_report()}
                    elif choice == "7":
                        result = self.get_system_status()
                    elif choice == "8":
                        qm = self._modules["quarantine"]
                        action = input("Lister [l], restaurer [r], supprimer [s] : ").strip().lower()
                        if action == "r":
                            identifier = input("Identifiant : ").strip()
                            dest = input("Nouveau chemin (vide = chemin original) : ").strip()
                            result = qm.restore_file(identifier, dest or None)
                        elif action == "s":
                            identifier = input("Identifiant : ").strip()
                            if input("Suppression définitive : taper SUPPRIMER : ") != "SUPPRIMER":
                                continue
                            result = qm.delete_quarantined(identifier)
                        else:
                            result = qm.list_quarantined()
                    elif choice in ("9", "10"):
                        path = input("Fichier : ").strip().strip('"')
                        result = (self._modules["sandbox"].analyze_file(path) if choice == "9"
                                  else self._modules["ai_analyzer"].analyze_file_heuristic(path))
                    elif choice == "11":
                        result = self.payment.get_info()
                    elif choice == "12":
                        result = self.payment.activate(input("Licence signée : ").strip())
                    elif choice == "13":
                        current = getpass("Mot de passe actuel : ")
                        new = getpass("Nouveau mot de passe : ")
                        result = self.auth.change_password(current, new, getpass("Confirmer : "))
                    elif choice == "14":
                        from elpati.elpati_url_scanner import ElpatiURLScanner
                        result = ElpatiURLScanner().scan_url(input("URL : ").strip(), use_ai=False)
                    elif choice == "15":
                        result = self._modules["vuln_scan"].run_full_scan()
                    else:
                        print("Choix inconnu.")
                        continue
                    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
                except (EOFError, KeyboardInterrupt):
                    break
                except Exception as exc:
                    self.log.error(f"CLI: {exc}")
                    print(f"[ERREUR] {exc}")
        finally:
            self.stop_protection()
            self.auth.logout()
            self.log.flush_chain()
