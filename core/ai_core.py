"""
CORE AI - Hybrid AI Engine
La clé API est lue depuis config.env (fichier admin uniquement).
Elle n'apparaît JAMAIS dans l'interface utilisateur.
Sans clé : IA locale 100% fonctionnelle.
Avec clé  : Claude AI pour analyses encore plus profondes.
"""
import json, os, urllib.request, urllib.error
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent

def _load_env() -> dict:
    """Charge config.env depuis la racine du projet."""
    env = {}
    env_file = ROOT / "config.env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    # Variables d'environnement système ont priorité
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_MODEL", "AI_REMOTE_ENABLED", "LOG_LEVEL", "AUTO_PROTECT", "AUTO_QUARANTINE"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env

class AICore:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._env = _load_env()
        self._api_key = self._env.get("ANTHROPIC_API_KEY", "").strip()
        self._claude_available = False
        self._stats = {"local_analyses": 0, "claude_analyses": 0, "total": 0}
        if self._api_key:
            self.log.info("AI: Clé configurée. Utilisation distante désactivée tant que AI_REMOTE_ENABLED n'est pas activé.")
        else:
            self.log.info("AI: Aucune clé API — mode local actif, contrôles heuristiques disponibles")

    def _test_on_startup(self):
        """Test silencieux de la clé au démarrage."""
        try:
            req_data = json.dumps({
                "model": self._env.get("ANTHROPIC_MODEL", ""),
                "max_tokens": 5,
                "messages": [{"role": "user", "content": "ok"}]
            }).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=req_data,
                headers={"Content-Type": "application/json",
                         "x-api-key": self._api_key,
                         "anthropic-version": "2023-06-01"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=8):
                self._claude_available = True
                self.log.info("AI: Claude API connectée ✓")
        except Exception as e:
            self._claude_available = False
            self.log.warning(f"AI: Claude API inaccessible ({e}) — basculement IA locale")

    def reload_config(self):
        """Recharge config.env sans redémarrer l'app."""
        self._env = _load_env()
        self._api_key = self._env.get("ANTHROPIC_API_KEY", "").strip()
        self._claude_available = False
        self.log.audit("AI: Configuration rechargée")

    def analyze_threat(self, context: dict) -> dict:
        self._stats["total"] += 1
        if context.get("unconfirmed_file"):
            self._stats["local_analyses"] += 1
            score = max(0, min(65, int(context.get("local_score", 0) or 0)))
            return {"score": score, "risk_level": "REVIEW" if score else "NO_INDICATOR",
                    "verdict": "Indices statiques a examiner" if score else "Aucun indice statique retenu",
                    "explanation": "Analyse statique partielle; aucune execution ni absence de menace certifiee.",
                    "actions": ["INVESTIGATE"] if score else [], "source": "LOCAL_AI",
                    "ts": datetime.utcnow().isoformat()}
        if self._api_key and self._env.get("ANTHROPIC_MODEL") and self._env.get("AI_REMOTE_ENABLED", "").lower() in {"1", "true", "yes"}:
            result = self._claude_analyze(context)
            if result:
                self._stats["claude_analyses"] += 1
                return result
        self._stats["local_analyses"] += 1
        return self._local_analyze(context)

    def _claude_analyze(self, context: dict) -> dict:
        try:
            prompt = (
                f"Analyse de menace cybersécurité:\n"
                f"Type: {context.get('type','unknown')}\n"
                f"Score local: {context.get('local_score',0)}/100\n"
                f"Indicateurs: {json.dumps(context.get('indicators',{}), ensure_ascii=False)}\n"
                f"Comportement: {json.dumps(context.get('behavior',{}), ensure_ascii=False)}\n\n"
                f"Réponds UNIQUEMENT en JSON valide avec les clés: "
                f"score (0-100), risk_level (CLEAN/LOW/MEDIUM/HIGH/CRITICAL), "
                f"verdict (string), actions (liste strings), explanation (string)."
            )
            req_data = json.dumps({
                "model": self._env.get("ANTHROPIC_MODEL", ""),
                "max_tokens": 600,
                "system": ("Tu es un expert EDR/XDR. "
                           "Analyse les indicateurs de menace. "
                           "Réponds uniquement en JSON valide."),
                "messages": [{"role": "user", "content": prompt}]
            }).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=req_data,
                headers={"Content-Type": "application/json",
                         "x-api-key": self._api_key,
                         "anthropic-version": "2023-06-01"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                text = data["content"][0]["text"].strip()
                if "```" in text:
                    text = text.split("```")[1]
                    if text.startswith("json"): text = text[4:]
                result = json.loads(text.strip())
                if not isinstance(result, dict) or not isinstance(result.get("score"), (int, float)):
                    raise ValueError("Réponse IA invalide")
                result["score"] = max(0, min(100, int(result["score"])))
                result["risk_level"] = ("CRITICAL" if result["score"] >= 80 else "HIGH" if result["score"] >= 60
                                        else "MEDIUM" if result["score"] >= 40 else "LOW" if result["score"] >= 20 else "CLEAN")
                result["actions"] = result.get("actions", []) if isinstance(result.get("actions", []), list) else []
                self._claude_available = True
                result["source"] = "CLAUDE_AI"
                result["ts"] = datetime.utcnow().isoformat()
                return result
        except Exception as e:
            self.log.warning(f"AI: Analyse Claude échouée ({e}) — basculement local")
            self._claude_available = False
            return None

    def _local_analyze(self, context: dict) -> dict:
        """IA locale — scoring multi-facteurs, 100% hors-ligne."""
        score = max(0, min(100, int(context.get("local_score", 0) or 0)))
        reasons = []
        actions = []
        weights = {
            "known_malware": 100, "malicious_process": 95, "ransomware_ext": 90,
            "memory_injection": 88, "privilege_escalation": 85, "yara_match": 82,
            "c2_communication": 78, "suspicious_network": 70, "high_entropy": 65,
            "suspicious_string": 60, "mass_file_modification": 85,
            "anomalous_behavior": 55, "hidden_process": 75, "cpu_anomaly": 25,
            "new_autorun": 50, "unsigned_exec": 35, "extension_mismatch": 45,
        }
        for ind, present in context.get("indicators", {}).items():
            if ind in weights and present:
                w = weights[ind]
                if isinstance(present, (int, float)) and present != 1:
                    w = int(w * max(0.0, min(present, 1.0)))
                score += w
                reasons.append(f"{ind} (+{w})")

        behavior = context.get("behavior", {})
        if behavior.get("rapid_file_changes", 0) > 50:
            score += 30; reasons.append("rapid_file_changes (+30)")
        if behavior.get("network_scan_detected"):
            score += 20; reasons.append("port_scan_detected (+20)")
        if behavior.get("process_hollowing"):
            score += 40; reasons.append("process_hollowing (+40)")

        module_scores = context.get("module_scores", {})
        if sum(1 for s in module_scores.values() if s > 50) >= 3:
            score += 15; reasons.append("multi_module_agreement (+15)")

        score = min(score, 100)
        risk = ("CRITICAL" if score >= 80 else "HIGH" if score >= 60
                else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "CLEAN")

        if score >= 80: actions = ["KILL_PROCESS", "QUARANTINE_FILE", "BLOCK_NETWORK"]
        elif score >= 60: actions = ["ISOLATE_PROCESS", "ALERT_ADMIN"]
        elif score >= 40: actions = ["ALERT_ADMIN", "MONITOR_CLOSELY"]

        explanations = {
            "CRITICAL": "ACTION IMMÉDIATE: Isoler et supprimer. Infection active probable.",
            "HIGH":     "RISQUE ÉLEVÉ: Analyser immédiatement. Bloquer et surveiller.",
            "MEDIUM":   "SUSPECT: Analyse approfondie recommandée.",
            "LOW":      "RISQUE FAIBLE: Surveiller l'activité future.",
            "CLEAN":    "Aucune action requise. Système sain.",
        }
        return {
            "score": score, "risk_level": risk,
            "verdict": f"[IA LOCALE] {risk} — Score: {score}/100",
            "explanation": explanations[risk],
            "reasons": reasons[:10], "actions": actions,
            "source": "LOCAL_AI",
            "ts": datetime.utcnow().isoformat()
        }

    def correlate_modules(self, scores: dict) -> dict:
        if not scores:
            return {"global_score": 0, "risk": "CLEAN", "dominant_threat": "none"}
        weights = {"memory": 1.3, "network": 1.2, "behavior": 1.2,
                   "file": 1.0, "process": 1.1, "ransom": 1.4}
        total, w_total = 0, 0
        for mod, s in scores.items():
            w = weights.get(mod, 1.0)
            total += s * w; w_total += w
        global_score = min(int(total / w_total) if w_total else 0, 100)
        dominant = max(scores.items(), key=lambda x: x[1])[0] if scores else "none"
        return {
            "global_score": global_score, "module_scores": scores,
            "risk": ("CRITICAL" if global_score >= 80 else "HIGH" if global_score >= 60
                     else "MEDIUM" if global_score >= 40 else "LOW" if global_score >= 20 else "CLEAN"),
            "dominant_threat": dominant
        }

    def has_api_key(self) -> bool:
        return bool(self._api_key)

    def is_claude_available(self) -> bool:
        return self._claude_available

    def get_mode_label(self) -> str:
        if self._claude_available:
            return "Claude AI (avancé)"
        if self._api_key:
            return "Clé API configurée (hors-ligne)"
        return "IA Locale (heuristiques embarquées)"

    def get_stats(self) -> dict:
        return dict(self._stats)
