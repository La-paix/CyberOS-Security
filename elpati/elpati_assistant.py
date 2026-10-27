"""
ELPATI ASSISTANT - Robot IA conversationnel intégré
Support technique, dépannage, questions générales tech
Mode local (réponses embarquées) + Mode Claude AI (conversations profondes)
"""
import json, time, re
from datetime import datetime
from pathlib import Path
from collections import deque

# ── BASE DE CONNAISSANCES LOCALE ─────────────────────────────────────────────
# Aide locale alignée sur les fonctions disponibles

KNOWLEDGE_BASE = {'cyberos': {'keywords': ['cyberos', 'elpati', 'application'],
             'response': "CyberOS regroupe des outils locaux de scan, d'analyse statique, de surveillance et "
                         'de rapports. Ses heuristiques et sa base locale ne garantissent pas de détecter '
                         'toutes les menaces. Consultez le README pour les limites et les tests.'},
 'scan': {'keywords': ['scan', 'scanner', 'analyser', 'virus', 'malware'],
          'response': 'Menu Scan rapide ou Scan complet, puis LANCER. Le scan complet demande un dossier. '
                      'STOP demande une annulation propre. Le rapport indique les erreurs et fichiers '
                      "ignorés; aucun résultat ne certifie l'absence de menace."},
 'mot_de_passe': {'keywords': ['mot de passe', 'password', 'mdp', 'connexion', 'authentification'],
                  'response': "Première installation : créer un mot de passe d'au moins 12 caractères. Pour "
                              'le modifier : Paramètres > Sécurité, mot de passe actuel puis nouveau et '
                              "confirmation. Ne supprimez pas password.enc : une corruption bloque l'accès. "
                              'Restaurer ensemble security/auth et security/keys depuis votre sauvegarde.'},
 'licence': {'keywords': ['licence', 'license', 'activer', 'gratuit', 'payant'],
             'response': 'Les outils manuels restent utilisables localement. Les licences PRO/ENTERPRISE '
                         'signées peuvent activer les modules de surveillance en arrière-plan. Paramètres > '
                         "Licences permet l'activation. La création de licences appartient au propriétaire, "
                         'avec vendor_tools/license_issuer.py et une clé privée conservée hors du dépôt. Les '
                         'anciennes clés doivent être réémises.'},
 'quarantaine': {'keywords': ['quarantaine', 'restaurer', 'isoler'],
                 'response': 'Le contenu mis en quarantaine est chiffré dans quarantine/vault. Menu '
                             'Quarantaine : sélectionner une entrée puis RESTAURER ou SUPPRIMER. Une '
                             'restauration ne remplace jamais un fichier existant. Conservez une sauvegarde '
                             'privée de security/keys et du coffre.'},
 'rapport_pdf': {'keywords': ['rapport', 'pdf', 'exporter', 'preuve'],
                 'response': 'Menu Forensic et Rapports : rapport général, dernier scan, dernière analyse '
                             "URL ou rapport complet local. Lancer d'abord le scan demandé. Les PDF "
                             'contiennent les résultats observés, avec leurs limites. Les preuves sont '
                             "chiffrées dans le coffre; ces rapports n'ont pas de certification externe."},
 'installation': {'keywords': ['installer', 'installation', 'python', 'pip', 'démarrer'],
                  'response': 'Dans un environnement Python 3.10+ : python -m pip install -r '
                              'requirements-tested.txt. Vérifier : python main.py --check. Lancer : python '
                              'main.py, ou python main.py --cli. Le guide Windows détaille les étapes. Les '
                              'tests se lancent dans une copie temporaire : python tests/run_tests.py '
                              '--gui.'},
 'ia_claude': {'keywords': ['claude', 'anthropic', 'clé api', 'api key', 'ia'],
               'response': "Par défaut, seules les heuristiques locales sont utilisées. L'API est "
                           'facultative : clé privée et modèle disponible dans config.env, puis '
                           'AI_REMOTE_ENABLED=true. Elle peut transmettre les indicateurs ou conversations '
                           'et entraîner des frais. Les appels distants restent désactivés sans cette '
                           'activation explicite.'},
 'url': {'keywords': ['url', 'site', 'phishing', 'lien'],
         'response': "Le scanner URL consulte l'adresse saisie et effectue des contrôles réseau et des "
                     'heuristiques locales. Les résultats incomplets sont marqués INCONCLUSIF. Un score '
                     "faible n'est pas une preuve qu'un site est sûr. Ne transmettez pas de lien contenant "
                     'un mot de passe ou un jeton secret.'},
 'probleme': {'keywords': ['problème', 'bug', 'erreur', 'aide', 'help'],
              'response': 'Copiez le message exact, votre version de Python et le système utilisé. Lancez '
                          'python main.py --check puis les tests. Conservez les fichiers endommagés pour '
                          "diagnostic et n'envoyez jamais vos clés, mots de passe ou config.env."}}

SATISFACTION_QUESTIONS = [
    "L'application répond-elle bien à vos besoins de sécurité ?",
    "La protection temps réel fonctionne-t-elle correctement sur votre machine ?",
    "Les rapports PDF générés sont-ils clairs et utiles pour vous ?",
    "Le Scanner URL vous a-t-il aidé à identifier des sites suspects ?",
    "L'interface est-elle suffisamment simple à utiliser pour vous ?",
    "Y a-t-il une fonctionnalité manquante que vous aimeriez voir ajoutée ?",
    "Recommanderiez-vous CyberOS_Security à d'autres personnes ? Pourquoi ?",
    "Avez-vous rencontré des problèmes lors de l'installation ou de l'utilisation ?",
]


class ElpatiAssistant:
    """
    Assistant IA conversationnel pour CyberOS_Security.
    Répond aux questions tech, dépanne, évalue la satisfaction.
    """
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._history = deque(maxlen=50)  # Historique conversation
        self._session_start = datetime.utcnow().isoformat()
        self._message_count = 0
        self._satisfaction_asked = set()
        self._user_name = ""
        self._context = {}  # Contexte de la conversation
        self._mode = "local"  # "local" ou "claude"
        self._api_key = self._load_api_key()
        if self._api_key and self._remote_enabled and self._model:
            self._mode = "claude"
        self.log.info("Assistant ELPATI initialisé")

    def _load_api_key(self):
        from core.ai_core import _load_env
        env = _load_env()
        self._remote_enabled = env.get("AI_REMOTE_ENABLED", "").lower() in {"1", "true", "yes"}
        self._model = env.get("ANTHROPIC_MODEL", "").strip()
        return env.get("ANTHROPIC_API_KEY", "").strip()

    def reload_api_key(self):
        self._api_key = self._load_api_key()
        self._mode = "claude" if self._api_key and self._remote_enabled and self._model else "local"

    # ── POINT D'ENTRÉE PRINCIPAL ──────────────────────────────────────────────

    def chat(self, user_message: str) -> dict:
        """
        Traite un message utilisateur et retourne une réponse.
        Retourne: {"response": str, "source": str, "suggestions": list, "ask_satisfaction": bool}
        """
        self._message_count += 1
        user_msg = user_message.strip()

        # Enregistrer le message utilisateur
        self._history.append({"role": "user", "content": user_msg, "ts": datetime.utcnow().isoformat()})

        # Détecter le nom de l'utilisateur
        self._detect_name(user_msg)

        # Générer la réponse
        if self._mode == "claude" and self._api_key:
            response_text = self._claude_response(user_msg)
            source = "Claude AI" if self._mode == "claude" else "Assistant local"
        else:
            response_text = self._local_response(user_msg)
            source = "Assistant local"

        # Ajouter des suggestions contextuelles
        suggestions = self._get_suggestions(user_msg, response_text)

        # Poser une question de satisfaction périodiquement
        ask_satisfaction = self._should_ask_satisfaction()
        satisfaction_q = ""
        if ask_satisfaction:
            import random
            remaining = [q for q in SATISFACTION_QUESTIONS if q not in self._satisfaction_asked]
            if remaining:
                satisfaction_q = random.choice(remaining)
                self._satisfaction_asked.add(satisfaction_q)

        # Enregistrer la réponse
        self._history.append({
            "role": "assistant", "content": response_text,
            "ts": datetime.utcnow().isoformat(), "source": source
        })

        self.log.info(f"Assistant: réponse générée ({source}) — msg #{self._message_count}")

        return {
            "response": response_text,
            "source": source,
            "suggestions": suggestions,
            "ask_satisfaction": ask_satisfaction,
            "satisfaction_question": satisfaction_q,
            "mode": self._mode,
        }

    # ── RÉPONSE LOCALE ────────────────────────────────────────────────────────

    def _local_response(self, message: str) -> str:
        """Réponse intelligente basée sur la base de connaissances locale."""
        msg_lower = message.lower()

        # Salutations
        greetings = ["bonjour","bonsoir","salut","hello","hi","bonne journée","bonne nuit"]
        if any(g in msg_lower for g in greetings) and len(message.split()) <= 4:
            name_part = f", {self._user_name}" if self._user_name else ""
            return (f"Bonjour{name_part} ! Je suis l'Assistant ELPATI, votre support technique "
                    f"intégré dans CyberOS_Security.\n\n"
                    f"Je peux vous aider avec :\n"
                    f"• L'utilisation de CyberOS_Security\n"
                    f"• Le dépannage informatique\n"
                    f"• La cybersécurité\n"
                    f"• N'importe quelle question technique\n\n"
                    f"Comment puis-je vous aider aujourd'hui ?")

        # Merci / au revoir
        bye_words = ["au revoir","bonne nuit","bonne journée","bye","à bientôt","merci beaucoup","ciao"]
        if any(b in msg_lower for b in bye_words):
            name_part = f", {self._user_name}" if self._user_name else ""
            return (f"Avec plaisir{name_part} ! N'hésitez pas à revenir si vous avez d'autres questions.\n"
                    f"Bonne continuation et restez en sécurité ! 🛡")

        # Chercher dans la base de connaissances
        best_match = None
        best_score = 0
        for topic, data in KNOWLEDGE_BASE.items():
            score = sum(1 for kw in data["keywords"] if kw in msg_lower)
            if score > best_score:
                best_score = score
                best_match = data

        if best_match and best_score >= 1:
            return best_match["response"]

        # Réponses pour questions ouvertes
        if any(w in msg_lower for w in ["comment","pourquoi","qu'est-ce","c'est quoi","explique"]):
            return self._answer_how_why(message)

        # Réponse par défaut intelligente
        return self._default_response(message)

    def _answer_how_why(self, message: str) -> str:
        msg_lower = message.lower()
        if "crypter" in msg_lower or "chiffrer" in msg_lower:
            return ("Le chiffrement transforme vos données en code illisible sans la clé.\n\n"
                    "CyberOS utilise AES-256-GCM — le même standard que les banques et gouvernements.\n"
                    "La protection dépend aussi du secret de la clé et de la sécurité de votre compte.\n\n"
                    "Les mots de passe et le contenu du coffre sont chiffrés. Les journaux restent lisibles "
                    "automatiquement par CyberOS.\n\nAvez-vous d'autres questions sur la sécurité ?")
        if "hacker" in msg_lower or "pirate" in msg_lower:
            return ("Les hackers utilisent plusieurs techniques :\n\n"
                    "• Phishing : faux emails/sites pour voler vos mots de passe\n"
                    "• Ransomware : chiffrement de vos fichiers contre rançon\n"
                    "• Exploitation de failles : attaques sur logiciels non mis à jour\n"
                    "• Force brute : essayer des milliers de mots de passe\n\n"
                    "CyberOS relève certains indicateurs. Gardez un antivirus maintenu, des mises à jour et des sauvegardes.\n"
                    "Y a-t-il une technique particulière qui vous inquiète ?")
        return self._default_response(message)

    def _default_response(self, message: str) -> str:
        name_part = f", {self._user_name}" if self._user_name else ""
        responses = [
            (f"Bonne question{name_part} ! Pourriez-vous me donner plus de détails ?\n\n"
             f"Je suis spécialisé dans :\n"
             f"• CyberOS_Security et ses fonctionnalités\n"
             f"• La cybersécurité (virus, hackers, protection)\n"
             f"• Le dépannage Windows/Linux/macOS\n"
             f"• Les réseaux et Internet\n"
             f"• La récupération de données\n\n"
             f"Reformulez votre question, je ferai de mon mieux pour vous aider."),
        ]
        return responses[0]

    def _detect_name(self, message: str):
        patterns = [
            r"je m'appelle\s+(\w+)",
            r"mon nom est\s+(\w+)",
            r"c'est\s+(\w+)\s+ici",
            r"je suis\s+(\w+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, message.lower())
            if match:
                self._user_name = match.group(1).capitalize()
                break

    # ── RÉPONSE CLAUDE AI ─────────────────────────────────────────────────────

    def _claude_response(self, message: str) -> str:
        """Réponse via Claude API avec contexte complet."""
        try:
            import urllib.request

            # Construire le contexte de conversation
            messages = []
            # Inclure les 8 derniers échanges pour le contexte
            recent = list(self._history)[-16:]
            for entry in recent:
                if entry["role"] in ("user","assistant"):
                    messages.append({
                        "role": entry["role"],
                        "content": entry["content"]
                    })

            # Ajouter le message actuel s'il n'est pas déjà dedans
            if not messages or messages[-1]["content"] != message:
                messages.append({"role": "user", "content": message})

            system_prompt = """Tu es l'Assistant ELPATI, intégré dans CyberOS_Security v2026.3.

Tu es un expert technique chaleureux et pédagogue qui aide les utilisateurs avec :
- CyberOS_Security (EDR/XDR, scans, protection, licences, rapports PDF)
- La cybersécurité (virus, ransomware, phishing, hackers, protection)
- Le dépannage informatique (Windows, Linux, macOS, réseaux, Internet)
- Toute question technologique générale

Règles de communication :
- Parle comme un ami expert, pas comme un robot froid
- Utilise un langage simple et accessible
- Pose des questions pour mieux comprendre le problème
- Propose toujours une étape suivante concrète
- Si tu ne sais pas quelque chose, dis-le honnêtement
- Réponds en français par défaut (adapte-toi à la langue de l'utilisateur)
- Réponds de façon concise mais complète (pas trop long)
- Montre de l'empathie si l'utilisateur est stressé ou en difficulté

Fonctionnalités clés de CyberOS :
- Scan rapide et scan complet (menu gauche)
- Protection temps réel (modules ELPATI)
- Scanner URL style VirusTotal
- Scanner CVE/vulnérabilités
- Planificateur de scans automatiques
- Réponse automatique SOAR
- Rapports PDF professionnels générés par IA
- Quarantaine chiffrée AES-256
- Forensic et preuves numériques
- 4 langues : FR, EN, ES, PT
- Ne promettre ni protection complète, ni certification, ni tarif commercial non confirmé."""

            req_data = json.dumps({
                "model": self._model,
                "max_tokens": 600,
                "system": system_prompt,
                "messages": messages
            }).encode()

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=req_data,
                headers={"Content-Type": "application/json",
                         "x-api-key": self._api_key,
                         "anthropic-version": "2023-06-01"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
                return data["content"][0]["text"]

        except Exception as e:
            self.log.warning(f"Assistant: Claude API erreur ({e}) — basculement local")
            self._mode = "local"
            return self._local_response(message)

    # ── SUGGESTIONS CONTEXTUELLES ─────────────────────────────────────────────

    def _get_suggestions(self, user_msg: str, response: str) -> list:
        """Génère des suggestions de questions de suivi."""
        msg_lower = user_msg.lower()
        suggestions = []

        if any(w in msg_lower for w in ["scan","virus","malware"]):
            suggestions = [
                "Comment mettre des fichiers en quarantaine ?",
                "Comment générer un rapport PDF après le scan ?",
                "La protection temps réel est-elle activée ?",
            ]
        elif any(w in msg_lower for w in ["lent","lenteur","ralenti"]):
            suggestions = [
                "Comment voir quels programmes consomment le plus ?",
                "Comment libérer de l'espace sur mon disque ?",
                "Comment désactiver les programmes au démarrage ?",
            ]
        elif any(w in msg_lower for w in ["réseau","wifi","internet"]):
            suggestions = [
                "Comment voir les connexions suspectes ?",
                "Comment bloquer une IP malveillante ?",
                "Comment analyser un site web suspect ?",
            ]
        elif any(w in msg_lower for w in ["ransomware","chiffr","crypté"]):
            suggestions = [
                "Comment activer les honeypots anti-ransomware ?",
                "Comment sauvegarder mes données importantes ?",
                "Comment récupérer des fichiers chiffrés ?",
            ]
        else:
            suggestions = [
                "Comment lancer un scan de sécurité ?",
                "Comment analyser un site web suspect ?",
                "Comment générer un rapport de sécurité PDF ?",
            ]
        return suggestions[:3]

    def _should_ask_satisfaction(self) -> bool:
        """Demander la satisfaction tous les 5 messages, pas trop souvent."""
        return (self._message_count > 0 and
                self._message_count % 5 == 0 and
                len(self._satisfaction_asked) < len(SATISFACTION_QUESTIONS))

    # ── UTILITAIRES ───────────────────────────────────────────────────────────

    def get_history(self, n=20) -> list:
        return list(self._history)[-n:]

    def clear_history(self):
        self._history.clear()
        self._message_count = 0
        self._context = {}
        self.log.audit("Assistant: historique effacé")

    def get_status(self) -> dict:
        return {
            "mode": self._mode,
            "api_key_set": bool(self._api_key),
            "messages": self._message_count,
            "session_start": self._session_start,
            "user_name": self._user_name,
        }
