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
# Réponses embarquées quand pas de clé API — couvre 95% des questions courantes

KNOWLEDGE_BASE = {
    # ── APPLICATION CYBEROS ───────────────────────────────────────────────────
    "cyberos": {
        "keywords": ["cyberos","elpati","application","logiciel","programme","app"],
        "response": """CyberOS_Security est une plateforme EDR/XDR (détection et réponse aux menaces) développée avec le système ELPATI.

Elle protège votre ordinateur contre :
• Les virus et malwares
• Les ransomwares (virus qui chiffrent vos fichiers)
• Les intrusions réseau
• Les comportements suspects

Elle fonctionne 100% hors ligne — vos données ne quittent jamais votre machine.

Que souhaitez-vous savoir de plus sur l'application ?"""
    },
    "scan": {
        "keywords": ["scan","scanner","analyser","analyse","virus","malware","fichier"],
        "response": """L'application propose 2 types de scans :

• SCAN RAPIDE : analyse les zones critiques (Downloads, Temp, AppData)
  Durée : 30 secondes à 5 minutes
  Usage : quotidien, de routine

• SCAN COMPLET : analyse tout un dossier ou disque
  Durée : variable selon la taille
  Usage : hebdomadaire ou après un incident

Pour lancer un scan : Menu gauche → "Scan Rapide" ou "Scan Complet"

Voulez-vous que je vous guide pas à pas ?"""
    },
    "mot_de_passe": {
        "keywords": ["mot de passe","password","mdp","connexion","login","authentification","oublié"],
        "response": """Pour changer votre mot de passe dans CyberOS :

1. Connectez-vous avec votre mot de passe actuel
2. Allez dans Paramètres (menu gauche, en bas)
3. Cliquez sur "Sécurité"
4. Entrez votre ancien mot de passe
5. Entrez et confirmez le nouveau

Mot de passe par défaut : cyberos2026
Minimum 6 caractères requis.

Si vous avez oublié votre mot de passe, supprimez le fichier :
security/auth/password.enc
L'application reviendra au mot de passe par défaut cyberos2026.

Avez-vous réussi à vous connecter ?"""
    },
    "licence": {
        "keywords": ["licence","license","clé","activer","gratuit","pro","payant","acheter"],
        "response": """CyberOS propose 3 niveaux de licence :

🆓 GRATUIT — Scan rapide uniquement, quarantaine de base

💼 PROFESSIONNEL (49€/an) — Scan complet, protection temps réel,
   analyse mémoire, réseau, IA, forensic, rapports PDF

🏢 ENTREPRISE (199€/an) — Tout PRO + multi-postes, SIEM, support prioritaire

Pour activer une licence :
1. Paramètres → Licences
2. Collez votre clé dans "Activer une licence"
3. Cliquez Activer

Pour obtenir une clé de démonstration 7 jours : Paramètres → Licences → "Générer clé"

Avez-vous besoin d'aide pour activer votre licence ?"""
    },
    "ransomware": {
        "keywords": ["ransomware","rançon","chiffrement","fichiers chiffrés","wannacry","cryptolocker","wncry"],
        "response": """Un ransomware est un virus qui chiffre vos fichiers et demande une rançon.

Comment CyberOS vous protège :
• Honeypots : fichiers pièges qui alertent dès qu'un ransomware les touche
• Détection d'entropie : détecte le chiffrement massif de fichiers
• Surveillance des extensions : .locky, .wncry, .ryuk et 30+ autres bloqués
• Blocage automatique si score > 80

Si vous êtes déjà infecté :
1. Éteignez immédiatement le Wi-Fi et débranchez les câbles réseau
2. Ne payez PAS la rançon
3. Contactez un technicien
4. Si vous aviez des sauvegardes, restaurez depuis celles-ci

Avez-vous des fichiers qui semblent chiffrés en ce moment ?"""
    },
    "virus": {
        "keywords": ["virus","trojan","cheval de troie","spyware","adware","infecté","infection"],
        "response": """Si vous pensez avoir un virus, voici les étapes à suivre :

Étape 1 : Lancer un scan rapide
→ Menu gauche → Scan Rapide → LANCER LE SCAN

Étape 2 : Si des menaces sont trouvées
→ Elles apparaissent dans les résultats
→ Cliquez sur "Mettre en quarantaine"

Étape 3 : Générer un rapport
→ Menu Forensic → Rapport PDF
→ Ce rapport documente tout ce qui a été trouvé

Signes d'infection courants :
• Ordinateur très lent sans raison
• Fenêtres publicitaires qui s'ouvrent seules
• Programmes qui démarrent tout seuls
• Espace disque qui diminue rapidement

Avez-vous des symptômes particuliers ?"""
    },
    "lent": {
        "keywords": ["lent","lenteur","ralenti","freeze","bloqué","bloque","ram","cpu","mémoire"],
        "response": """Votre ordinateur est lent ? Voici les causes les plus courantes et les solutions :

Vérification rapide avec CyberOS :
→ Menu "Processus" : voir quels programmes consomment le plus
→ Menu "Mémoire" : vérifier si la RAM est saturée

Causes fréquentes :
• Trop de programmes au démarrage → désactivez-en dans le gestionnaire de tâches
• Disque dur presque plein → libérez de l'espace (minimum 15% libre)
• Virus/malware → lancez un scan CyberOS
• RAM insuffisante → envisagez une mise à niveau
• Poussière dans le ventilateur → nettoyage recommandé

Solutions immédiates :
1. Redémarrez l'ordinateur
2. Fermez les programmes inutilisés
3. Lancez un scan CyberOS pour vérifier les malwares

Depuis combien de temps votre ordinateur est-il lent ?"""
    },
    "wifi_internet": {
        "keywords": ["wifi","internet","connexion","réseau","connecter","déconnecté","box","routeur","câble"],
        "response": """Problème de connexion Internet ? Voici les étapes de dépannage :

Étape 1 : Vérification de base
• Le voyant Wi-Fi de votre box/routeur est-il allumé ?
• Êtes-vous connecté au bon réseau Wi-Fi ?
• Avez-vous le bon mot de passe Wi-Fi ?

Étape 2 : Redémarrage classique
1. Éteignez votre box/routeur (débranchez 30 secondes)
2. Rallumez et attendez 2 minutes
3. Reconnectez-vous

Étape 3 : Sur Windows
• Paramètres → Réseau → Dépannage réseau
• Ou : ipconfig /release puis ipconfig /renew (en admin)

Étape 4 : Vérifier si c'est un problème matériel
• Testez avec un autre appareil sur le même réseau
• Si ça marche sur l'autre appareil → problème sur votre PC

CyberOS peut analyser vos connexions réseau :
→ Menu "Réseau" → voir les connexions actives

Pouvez-vous me décrire précisément ce qui se passe ?"""
    },
    "windows_update": {
        "keywords": ["mise à jour","update","windows update","mettre à jour","version","patch"],
        "response": """Les mises à jour Windows sont très importantes pour la sécurité !

Pourquoi mettre à jour :
• Corrige les failles de sécurité exploitées par les hackers
• Améliore les performances
• Ajoute de nouvelles fonctionnalités

Comment mettre à jour Windows :
1. Démarrer → Paramètres → Windows Update
2. Cliquez "Rechercher des mises à jour"
3. Installez toutes les mises à jour critiques
4. Redémarrez si demandé

Important : ne jamais désactiver les mises à jour automatiques.
Les failles non corrigées sont la 1ère porte d'entrée des virus.

CyberOS vérifie si vos mises à jour sont activées dans le Scanner CVE.
→ Menu "Scanner CVE" → voir les résultats

Vos mises à jour automatiques sont-elles activées ?"""
    },
    "sauvegarde": {
        "keywords": ["sauvegarde","backup","sauvegarder","données perdues","récupérer","restaurer"],
        "response": """La sauvegarde est la protection N°1 contre la perte de données !

Règle des 3-2-1 :
• 3 copies de vos données
• Sur 2 supports différents
• Dont 1 hors site (cloud ou disque chez un proche)

Solutions gratuites :
• Windows : Sauvegarde Windows intégrée (Panneau de config → Sauvegarde)
• OneDrive / Google Drive / Dropbox : sauvegarde cloud automatique
• Disque externe : copiez manuellement vos dossiers importants

À sauvegarder en priorité :
• Documents personnels
• Photos et vidéos
• Mots de passe (utilisez un gestionnaire)
• Emails importants

Fréquence recommandée :
• Données importantes → quotidiennement
• Système complet → mensuellement

Avez-vous actuellement une sauvegarde de vos données importantes ?"""
    },
    "phishing": {
        "keywords": ["phishing","arnaque","escroquerie","email suspect","lien suspect","faux site","hameçonnage"],
        "response": """Le phishing est une tentative d'escroquerie par email ou faux site web.

Comment reconnaître un email de phishing :
• Expéditeur inconnu ou adresse suspecte (ex: paypal@gmail.com au lieu de paypal.com)
• Urgence excessive ("Votre compte sera fermé dans 24h !")
• Fautes d'orthographe
• Liens qui ne correspondent pas au vrai site
• Demande de mot de passe, carte bancaire, code secret

Comment vérifier un site web avec CyberOS :
→ Menu "Scanner URL" → entrez l'adresse → ANALYSER
→ L'IA analyse le site et vous dit s'il est dangereux

Que faire si vous avez cliqué sur un lien suspect :
1. Ne saisissez AUCUNE information
2. Fermez immédiatement la page
3. Lancez un scan CyberOS
4. Changez vos mots de passe depuis un autre appareil si nécessaire

Avez-vous reçu un email ou lien suspect ?"""
    },
    "rapport_pdf": {
        "keywords": ["rapport","pdf","générer","exporter","document","preuve"],
        "response": """CyberOS génère des rapports PDF professionnels complets !

Pour générer un rapport :
→ Menu "Forensic & Rapports"
→ Choisissez le type :
  • Rapport Général : état complet du système
  • Après un scan : avec résultats du dernier scan
  • Après analyse URL : avec résultats du scanner web
  • Rapport Complet : tout en un

Le rapport contient :
• Résumé en langage simple (compréhensible par tous)
• Score de risque global
• Détail de toutes les menaces trouvées
• État de l'ordinateur (CPU, RAM, disques)
• Recommandations personnalisées par l'IA
• Glossaire des termes techniques
• Certification d'intégrité

Le PDF s'ouvre automatiquement après génération.

Voulez-vous générer un rapport maintenant ?"""
    },
    "installation": {
        "keywords": ["installer","installation","python","pip","démarrer","lancer","erreur"],
        "response": """Pour installer et lancer CyberOS_Security :

Prérequis : Python 3.9 ou supérieur
Téléchargement : https://python.org (cochez "Add to PATH" à l'installation)

Installation des modules :
pip install psutil cryptography reportlab

Lancement :
cd CyberOS_v2
python main.py

Erreurs courantes :
• "pip non reconnu" → réinstallez Python en cochant "Add to PATH"
• "No module named pip" → lancez : python -m ensurepip --upgrade
• "tkinter not found" (Linux) → sudo apt install python3-tk
• "GUI indisponible" → vérifiez que tkinter est installé

Quel message d'erreur avez-vous exactement ?"""
    },
    "ia_claude": {
        "keywords": ["claude","anthropic","clé api","ia avancée","intelligence artificielle","api key"],
        "response": """L'intégration Claude AI dans CyberOS fonctionne ainsi :

Sans clé API (mode par défaut) :
→ IA locale embarquée — fonctionne 100% hors ligne
→ Analyse heuristique, scoring multi-facteurs, règles YARA
→ Rapports PDF générés avec explications locales

Avec clé API Anthropic :
→ Analyses encore plus profondes et explications détaillées
→ Textes de rapport en langage naturel parfait
→ Recommandations contextuelles précises

Pour configurer la clé API :
1. Obtenez une clé sur https://console.anthropic.com
2. Ouvrez le fichier config.env (racine du projet)
3. Modifiez : ANTHROPIC_API_KEY=sk-ant-votre-cle
4. Redémarrez l'application
5. Paramètres → IA → RECHARGER config.env

La clé est stockée uniquement dans config.env — jamais dans l'interface.

Avez-vous besoin d'aide pour configurer la clé API ?"""
    },
    "satisfait": {
        "keywords": ["satisfait","content","bien","super","excellent","parfait","merci","bravo"],
        "response": """Je suis vraiment content que vous soyez satisfait !

Si vous avez d'autres questions sur :
• L'utilisation de CyberOS_Security
• Un problème informatique quelconque
• La cybersécurité en général
• N'importe quoi d'autre en rapport avec la technologie

... n'hésitez pas, je suis là !

Y a-t-il autre chose que je peux faire pour vous aujourd'hui ?"""
    },
    "probleme": {
        "keywords": ["problème","bug","erreur","marche pas","fonctionne pas","aide","help"],
        "response": """Je suis là pour vous aider ! Pouvez-vous me décrire le problème plus précisément ?

Quelques questions pour mieux vous aider :
• Quel message d'erreur voyez-vous exactement ?
• Quand le problème est-il apparu ?
• Qu'avez-vous fait juste avant que ça se produise ?
• Sur quel système d'exploitation êtes-vous ? (Windows/Linux/macOS)

Plus vous me donnez de détails, plus je pourrai vous aider efficacement.

Décrivez-moi ce qui se passe, je vous guide pas à pas."""
    },
}

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
        if self._api_key:
            self._mode = "claude"
        self.log.info("Assistant ELPATI initialisé")

    def _load_api_key(self) -> str:
        env_file = Path(__file__).parent.parent / "config.env"
        if env_file.exists():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("ANTHROPIC_API_KEY="):
                    k = line.split("=",1)[1].strip()
                    if k and not k.startswith("#"):
                        return k
        return ""

    def reload_api_key(self):
        self._api_key = self._load_api_key()
        self._mode = "claude" if self._api_key else "local"

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
            source = "Claude AI"
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
                    "C'est actuellement incassable avec les ordinateurs actuels.\n\n"
                    "Vos données sensibles (mots de passe, journaux) sont toutes chiffrées "
                    "automatiquement par CyberOS.\n\nAvez-vous d'autres questions sur la sécurité ?")
        if "hacker" in msg_lower or "pirate" in msg_lower:
            return ("Les hackers utilisent plusieurs techniques :\n\n"
                    "• Phishing : faux emails/sites pour voler vos mots de passe\n"
                    "• Ransomware : chiffrement de vos fichiers contre rançon\n"
                    "• Exploitation de failles : attaques sur logiciels non mis à jour\n"
                    "• Force brute : essayer des milliers de mots de passe\n\n"
                    "CyberOS protège contre toutes ces techniques.\n"
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
- Licences : FREE, PRO (49€/an), ENTERPRISE (199€/an)"""

            req_data = json.dumps({
                "model": "claude-sonnet-4-20250514",
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
