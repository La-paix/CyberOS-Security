"""
ELPATI AUTO-RESPONSE - Réponse automatique aux incidents (SOAR)
Playbooks de réponse automatique — comme un SOC automatisé
"""
import json, threading, time
from datetime import datetime
from pathlib import Path

class ElpatiAutoResponse:
    """
    Moteur de réponse automatique aux incidents.
    Applique des playbooks selon le type et score de menace.
    """
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._enabled = False
        self._actions_taken = []
        self._playbooks = self._load_playbooks()

    def _load_playbooks(self) -> list:
        """Playbooks de réponse automatique."""
        return [
            {
                "name":      "RANSOMWARE_RESPONSE",
                "trigger":   {"type": "ransomware", "min_score": 70},
                "actions":   ["alert_critical", "generate_forensic"],
                "auto":      True,
                "description": "Alerte ransomware et rapport local"
            },
            {
                "name":      "MALWARE_QUARANTINE",
                "trigger":   {"type": "known_malware", "min_score": 80},
                "actions":   ["quarantine_file", "alert_high"],
                "auto":      True,
                "description": "Quarantaine automatique des malwares connus"
            },
            {
                "name":      "SUSPICIOUS_NETWORK",
                "trigger":   {"type": "suspicious_network", "min_score": 65},
                "actions":   ["alert_medium"],
                "auto":      True,
                "description": "Alerte IP suspecte"
            },
            {
                "name":      "CREDENTIAL_ATTACK",
                "trigger":   {"type": "brute_force", "min_score": 60},
                "actions":   ["alert_high"],
                "auto":      True,
                "description": "Verrouillage suite à tentative de force brute"
            },
            {
                "name":      "HIGH_RISK_ALERT",
                "trigger":   {"min_score": 60},
                "actions":   ["alert_medium"],
                "auto":      True,
                "description": "Alerte générique pour score élevé"
            },
        ]

    def process_alert(self, alert: dict, controller=None) -> dict:
        """Traiter une alerte et appliquer le playbook correspondant."""
        if not self._enabled:
            return {"processed": False, "reason": "auto_response_disabled"}

        score = alert.get("score", 0)
        threat_type = alert.get("type", "unknown").lower()
        actions_executed = []

        # Trouver le playbook correspondant
        playbook = self._match_playbook(threat_type, score)
        if not playbook:
            return {"processed": False, "reason": "no_matching_playbook"}

        # Exécuter les actions
        for action in playbook.get("actions", []):
            result = self._execute_action(action, alert, controller)
            actions_executed.append({"action": action, "result": result})

        record = {
            "ts": datetime.utcnow().isoformat(),
            "playbook": playbook["name"],
            "alert": alert,
            "actions": actions_executed,
        }
        self._actions_taken.insert(0, record)
        self._actions_taken = self._actions_taken[:200]
        self.log.audit(f"AutoResponse: Playbook '{playbook['name']}' exécuté pour score={score}")
        return {"processed": True, "playbook": playbook["name"], "actions": actions_executed}

    def _match_playbook(self, threat_type, score):
        for pb in self._playbooks:
            trigger = pb.get("trigger", {})
            min_score = trigger.get("min_score", 0)
            req_type = trigger.get("type", "")
            if score >= min_score:
                if not req_type or req_type in threat_type:
                    return pb
        return None

    def _execute_action(self, action: str, alert: dict, controller) -> str:
        """Exécuter une action de réponse."""
        try:
            if action == "kill_process":
                pid = alert.get("pid")
                if pid and controller and "shield" in controller._modules:
                    result = controller._modules["shield"].kill_process(pid)
                    return f"Action processus : {result}"

            elif action == "quarantine_file":
                path = alert.get("path") or alert.get("file_path")
                if path and controller and "quarantine" in controller._modules:
                    import os
                    if os.path.exists(path):
                        result = controller._modules["quarantine"].quarantine_file(
                            path, {"type": alert.get("type","?"), "score": alert.get("score",0)})
                        return f"Quarantaine : {result}"

            elif action == "block_ip":
                ip = alert.get("ip")
                if ip and controller and "network_guard" in controller._modules:
                    controller._modules["network_guard"].block_ip(ip)
                    return f"IP bloquée: {ip}"

            elif action == "alert_critical":
                self.log.threat(f"[AUTO-RESPONSE CRITIQUE] {alert.get('message','?')}")
                return "Alerte critique envoyée"

            elif action == "alert_high":
                self.log.threat(f"[AUTO-RESPONSE ÉLEVÉ] {alert.get('message','?')}")
                return "Alerte haute envoyée"

            elif action == "alert_medium":
                self.log.warning(f"[AUTO-RESPONSE MOYEN] {alert.get('message','?')}")
                return "Alerte moyenne envoyée"

            elif action == "generate_forensic":
                if controller and "forensic" in controller._modules:
                    threading.Thread(
                        target=controller._modules["forensic"].generate_report,
                        args=(f"AUTO-{datetime.now().strftime('%Y%m%d%H%M%S')}",),
                        daemon=True).start()
                    return "Rapport forensic lancé"

            elif action == "increase_monitoring":
                return "Action non prise en charge : surveillance renforcée"

            return f"{action}: non effectuée (action indisponible ou données manquantes)"
        except Exception as e:
            return f"{action}: erreur — {str(e)[:50]}"

    def enable(self):  self._enabled = True
    def disable(self): self._enabled = False
    def get_history(self, n=50): return self._actions_taken[:n]
    def get_playbooks(self): return self._playbooks
    def get_status(self):
        return {"enabled": self._enabled,
                "playbooks": len(self._playbooks),
                "actions_taken": len(self._actions_taken)}
