# 📖 GUIDE COMPLET — CyberOS_Security v2026.2
## Système ELPATI | EDR/XDR Platform

---

## 🚀 INSTALLATION RAPIDE

### Prérequis
- Python 3.9+ (https://python.org)
- Système: Windows 10/11, Linux (Ubuntu/Debian/Arch), macOS 12+

### Étape 1 — Décompresser
```
Décompressez CyberOS_Security_v2026.2.zip dans le dossier de votre choix
```

### Étape 2 — Installer les dépendances
```bash
# Ouvrir un terminal dans le dossier CyberOS_Security/
pip install psutil cryptography
```

### Étape 3 — Lancer l'application
```bash
# Interface graphique (recommandé)
python main.py

# Mode ligne de commande
python main.py --cli
```

### Étape 4 — Première connexion
- Mot de passe par défaut: **cyberos2026**
- Changez-le immédiatement dans Paramètres → Sécurité

---

## 🔐 MOT DE PASSE ADMIN

**Changer le mot de passe (GUI):**
1. Connectez-vous avec `cyberos2026`
2. Menu → Paramètres → 🔒 Sécurité
3. Entrez l'ancien mot de passe
4. Entrez et confirmez le nouveau (min. 6 caractères)
5. Cliquez "CHANGER LE MOT DE PASSE"

**Changer le mot de passe (CLI):**
```
Lors du login CLI, entrez l'ancien mot de passe
Puis allez dans le menu et choisissez l'option Sécurité
```

---

## 💳 SYSTÈME DE LICENCES

### Niveaux disponibles

| Fonctionnalité         | GRATUIT | PRO     | ENTERPRISE |
|------------------------|---------|---------|------------|
| Scan rapide            | ✓       | ✓       | ✓          |
| Scan complet           | ✗       | ✓       | ✓          |
| Protection temps réel  | ✗       | ✓       | ✓          |
| Scan mémoire RAM       | ✗       | ✓       | ✓          |
| Surveillance réseau    | ✗       | ✓       | ✓          |
| Analyse IA locale      | ✗       | ✓       | ✓          |
| Analyse Claude AI      | ✗       | ✓       | ✓          |
| Rapports forensic      | ✗       | ✓       | ✓          |
| Anti-ransomware        | ✗       | ✓       | ✓          |
| Sandbox                | ✗       | ✓       | ✓          |
| Multi-postes           | ✗       | ✗       | ✓          |
| Prix                   | 0€      | 49€/an  | 199€/an    |

### Générer une clé de licence (Admin)
**Via GUI:**
1. Paramètres → 💳 Licences
2. Choisissez niveau (FREE/PRO/ENTERPRISE) et durée en jours
3. Cliquez "GÉNÉRER LA CLÉ"
4. Copiez la clé générée

**Via Python:**
```python
from elpati.elpati_payment import ElpatiPayment
pay = ElpatiPayment()
# Clé PRO 1 an
key = pay.generate_key("PRO", 365)
print(key)
# Clé Enterprise 1 an
key_ent = pay.generate_key("ENTERPRISE", 365)
print(key_ent)
# Clé démo 7 jours
demo = pay.generate_demo_key()
print(demo)
```

### Activer une licence
**Via GUI:**
1. Paramètres → 💳 Licences
2. Collez la clé dans "ACTIVER UNE LICENCE"
3. Cliquez "ACTIVER"

**Via CLI:**
```
Menu → Option 12 → Entrez la clé
```

---

## 🧠 INTELLIGENCE ARTIFICIELLE

### Mode IA Locale (sans clé API)
L'application fonctionne à 100% hors-ligne avec:
- Scoring heuristique multi-facteurs
- Corrélation multi-modules
- Analyse comportementale
- Règles YARA embarquées

### Mode Claude AI (avec clé API)
Avec une clé Anthropic, l'analyse est encore plus puissante:
- Analyse contextuelle profonde
- Explications détaillées en français
- Recommandations d'actions précises

**Configurer la clé API:**
1. Allez sur https://console.anthropic.com
2. Créez un compte → API Keys → Create Key
3. Dans l'app: Paramètres → 🧠 Clé API IA
4. Collez votre clé (commence par `sk-ant-`)
5. Cliquez "SAUVEGARDER" puis "TESTER LA CONNEXION"

> La clé est stockée chiffrée AES-256 sur votre machine. Elle ne quitte jamais votre ordinateur sauf pour les appels API directs.

---

## 🎨 PERSONNALISATION

### Thèmes visuels
Paramètres → 🎨 Apparence → Thème:
- 🌑 **Sombre** — Thème cybersécurité par défaut
- ☀️ **Clair** — Fond blanc, adapté à la lumière du jour
- ⚡ **Contraste élevé** — Pour les malvoyants (fond noir, texte blanc/jaune)
- 🌊 **Bleu nuit** — Tons bleus professionnels
- 💚 **Matrix Vert** — Style terminal vert

### Taille de police
Paramètres → 🎨 Apparence → Taille de police:
- 🔡 **Petite** (8pt)
- 🔤 **Moyenne** (10pt) — défaut
- 🔠 **Grande** (12pt) — recommandé si difficultés visuelles
- 🅰️ **Très grande** (15pt) — pour malvoyants

### Langue
Paramètres → 🌐 Langue:
- 🇫🇷 Français (défaut)
- 🇬🇧 English
- 🇪🇸 Español

---

## 🛡️ FONCTIONNALITÉS PRINCIPALES

### Scan Rapide
Analyse les emplacements critiques du système (TEMP, AppData, Downloads).
Durée: 30 secondes à 5 minutes.

### Scan Complet
Analyse complète d'un dossier ou disque entier.
Durée: variable selon le volume.

### Protection en Temps Réel
Surveille en continu:
- Création de nouveaux processus
- Connexions réseau
- Modifications de fichiers
- Comportements suspects

### Anti-Ransomware
- Fichiers honeypots (pièges)
- Détection d'entropie élevée (fichiers chiffrés)
- Blocage des modifications massives
- Détection des extensions malveillantes

### Analyse Mémoire
- Détection de code injecté
- Régions mémoire exécutables anonymes
- Patterns malveillants en RAM

### Forensic
Génère un rapport complet incluant:
- Snapshot système
- Liste des processus
- Connexions réseau
- Fichiers récents
- Comptes utilisateurs
- Hachage d'intégrité

---

## ⚙️ ARCHITECTURE SÉCURISÉE

```
Interface Utilisateur
        ↓
Contrôleur Central ELPATI
        ↓
Modules ELPATI (14 modules)
        ↓
Moteur CyberOS (scan, analyse, forensic)
        ↓
Security Vault (coffre-fort chiffré)
        ↓
Système d'exploitation
```

### Sécurité des données
- Logs chaînés cryptographiquement (comme une blockchain)
- Clés chiffrées AES-256-GCM
- Signatures RSA-4096
- Dérivation PBKDF2 avec 600 000 itérations
- Auto-protection: détection de tampering au démarrage

---

## 📱 UTILISATION SUR DIFFÉRENTS SYSTÈMES

### Windows
```cmd
cd C:\CyberOS_Security
pip install psutil cryptography
python main.py
```
> Note: Pour le scan complet, lancez en tant qu'Administrateur

### Linux / Ubuntu
```bash
cd ~/CyberOS_Security
pip3 install psutil cryptography
python3 main.py
```
> Note: `sudo python3 main.py` pour accès système complet

### macOS
```bash
cd ~/CyberOS_Security
pip3 install psutil cryptography
python3 main.py
```

---

## 🔧 DÉPANNAGE

**Problème: "tkinter not found"**
```bash
# Ubuntu/Debian
sudo apt install python3-tk
# macOS
brew install python-tk
# Windows: réinstaller Python avec tkinter coché
```

**Problème: Permission refusée**
```bash
sudo python3 main.py  # Linux/macOS
# Windows: Clic droit → Exécuter en admin
```

**Problème: Mot de passe oublié**
```bash
# Supprimer le fichier de mot de passe
rm security/auth/password.enc
# Redémarrer → mot de passe redevient cyberos2026
```

**Problème: Clé API ne fonctionne pas**
- Vérifiez que la clé commence par `sk-ant-`
- Vérifiez votre connexion internet pour les appels Claude
- L'IA locale fonctionne toujours sans clé API

---

## 📊 SCORING DES MENACES

| Score | Niveau   | Action automatique          |
|-------|----------|-----------------------------|
| 0-19  | PROPRE   | Aucune                      |
| 20-39 | FAIBLE   | Surveillance                |
| 40-59 | MOYEN    | Alerte administrateur       |
| 60-79 | ÉLEVÉ    | Isolation du processus      |
| 80-100| CRITIQUE | Suppression + quarantaine   |

---

## 🔄 MISES À JOUR

Pour mettre à jour CyberOS_Security:
1. Téléchargez la nouvelle version
2. Copiez vos fichiers `security/` dans le nouveau dossier
3. Vos licences, mots de passe et configurations sont préservés

---

## 📞 SUPPORT

- Communauté: Ouvrez une issue sur le dépôt
- Pro: Support email 48h avec votre numéro de licence
- Enterprise: Support prioritaire 24h

---

**CyberOS_Security v2026.2 — Système ELPATI**
*Protection locale · Intelligence embarquée · Architecture 2026-2036*

---

## 🧠 CONFIGURATION CLÉ API (ADMIN UNIQUEMENT)

La clé API Anthropic ne s'entre **jamais** dans l'interface utilisateur.
Elle est gérée uniquement par l'administrateur via le fichier `config.env`.

### Pourquoi ce choix ?
- Sécurité : la clé n'est jamais exposée dans l'UI ni dans les logs
- Contrôle : seul l'admin du poste peut activer/désactiver l'IA Claude
- Séparation : les utilisateurs finaux n'ont pas accès à la configuration

### Activer Claude AI

1. Ouvrez `config.env` à la racine du projet avec Notepad / VS Code
2. Trouvez la ligne :
   ```
   ANTHROPIC_API_KEY=
   ```
3. Ajoutez votre clé :
   ```
   ANTHROPIC_API_KEY=sk-ant-votre-cle-ici
   ```
4. Sauvegardez, relancez l'application
5. Dans Paramètres → IA, cliquez "RECHARGER config.env"

### Sans clé API
L'application fonctionne à 100% en IA locale.
Le score de menace, l'analyse comportementale, les règles YARA — tout fonctionne hors-ligne.

### ⚠ Règles de sécurité
- Ne jamais partager `config.env` avec les utilisateurs
- Ne jamais commiter `config.env` sur Git (ajoutez-le à `.gitignore`)
- La clé n'est jamais stockée en base de données ni chiffrée dans l'app
