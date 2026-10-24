# CyberOS Security

**v2026.2 · Système ELPATI**

Application Python de sécurité locale avec interface graphique Tkinter, mode CLI, modules d’analyse et assistant Elpati. L’analyse locale repose sur des signatures, des heuristiques et la corrélation de scores. Une intégration Anthropic Claude est optionnelle.

[Guide utilisateur](docs/GUIDE_COMPLET.md) · [Guide développeur](docs/GUIDE_DEVELOPPEUR_COMPLET.md) · [Signaler un problème](https://github.com/La-paix/CyberOS-Security/issues)

## Modules du projet

| Domaine | Sources principales |
| --- | --- |
| Scans de fichiers et orchestration | `core/engine.py`, `core/controller.py`, `scanner/` |
| Surveillance et analyse comportementale | `elpati/elpati_monitor.py`, `elpati/elpati_behavior.py` |
| Analyse mémoire et réseau | `elpati/elpati_memory_scan.py`, `elpati/elpati_network_guard.py` |
| Ransomware et réponse aux alertes | `elpati/elpati_ransom_guard.py`, `elpati/elpati_shield.py`, `elpati/elpati_autoresponse.py` |
| Analyse statique et collecte forensique | `sandbox/malware_lab.py`, `forensic/forensic_engine.py` |
| Intégrité, planification et analyse de vulnérabilités | `elpati/elpati_integrity.py`, `elpati/elpati_scheduler.py`, `elpati/elpati_vulnscan.py` |
| Analyse locale et intégration Claude | `core/ai_core.py`, `elpati/elpati_ai_analyzer.py` |
| Interface et préférences | `gui/dashboard.py`, `core/config.py`, `data/i18n.json` |

Ce tableau décrit les composants présents dans le code. Il ne constitue pas une certification de détection ou de protection.

## Prérequis

Les exemples suivants ciblent **Windows et PowerShell**.

- Git pour cloner le dépôt.
- Python avec le lanceur Windows `py`. Les guides indiquent Python 3.9 ou supérieur ; la compatibilité de chaque version dépend aussi des dépendances installées.
- Tkinter pour l’interface graphique.
- Les dépendances de `requirements.txt` : `psutil>=5.9.0`, `cryptography>=41.0.0` et `reportlab>=4.0.0`.

**ReportLab est obligatoire au démarrage dans cette version** : `main.py` vérifie sa présence, même avant la génération d’un rapport.

## Installation

### 1. Cloner le dépôt

```powershell
git clone https://github.com/La-paix/CyberOS-Security.git
Set-Location CyberOS-Security
```

Depuis un dossier source déjà présent, utilisez directement ce dossier.

### 2. Vérifier le gestionnaire de quarantaine

Le contrôleur importe `quarantine.quarantine_manager`. Le fichier source suivant doit donc être présent avant l’initialisation complète des modules :

```powershell
if (!(Test-Path -LiteralPath ".\quarantine\quarantine_manager.py")) {
    throw "Le fichier quarantine/quarantine_manager.py doit etre restaure depuis le dossier source du projet."
}
```

Le `.gitignore` autorise les fichiers source `quarantine/__init__.py` et `quarantine/quarantine_manager.py`. Les données mises en quarantaine restent exclues du dépôt.

### 3. Installer les dépendances dans un environnement virtuel

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Ces commandes utilisent directement Python dans `.venv` ; l’activation d’un script PowerShell n’est pas nécessaire.

Les paquets `pyaudio` et `yara-python` sont mentionnés comme optionnels dans `requirements.txt` et ne sont pas installés par défaut.

## Lancement

### Interface graphique

```powershell
.\.venv\Scripts\python.exe .\main.py
```

### Ligne de commande

```powershell
.\.venv\Scripts\python.exe .\main.py --cli
```

Le drapeau `--no-gui` est également reconnu par `main.py`. Si le lancement graphique échoue, le point d’entrée tente de passer en mode CLI.

### Première connexion

Lors de l’initialisation d’une nouvelle installation, le code crée un mot de passe par défaut : **`cyberos2026`**.

Changez-le dès la première connexion dans **Paramètres → Sécurité**. Une installation existante conserve ses propres fichiers d’authentification.

Les réponses automatiques peuvent interrompre des processus ou déplacer des fichiers. Vérifiez les réglages de protection et de quarantaine avant leur activation.

## Configuration et données locales

`core/config.py` fournit les préférences par défaut lorsque `data/config.json` n’existe pas. Les préférences sont sauvegardées lors de leur modification.

L’application crée les répertoires nécessaires et initialise ses fichiers cryptographiques et d’authentification. Conservez les fichiers d’une installation existante pour préserver son état local.

| Chemin | Usage |
| --- | --- |
| `config.env` | Configuration optionnelle de l’API Claude. |
| `data/config.json` | Préférences locales. |
| `security/auth/` | Données d’authentification. |
| `security/keys/` | Fichiers cryptographiques propres à l’installation. |
| `security/state.json` | État et compteurs locaux. |
| `security/vault/` | Éléments de preuve stockés localement. |
| `logs/`, `reports/` | Journaux et rapports produits par l’application. |
| `quarantine/vault/` | Données mises en quarantaine. |

Ces fichiers et répertoires locaux sont exclus du suivi Git. Le fichier `config.env.example` peut être versionné car il ne contient aucune clé.

## Claude : optionnel

Sans clé API, `AICore` utilise son analyse heuristique locale. Pour configurer Claude lors d’une nouvelle installation, créez le fichier local si nécessaire :

```powershell
if (!(Test-Path -LiteralPath ".\config.env")) {
    Copy-Item -LiteralPath ".\config.env.example" -Destination ".\config.env"
}
notepad .\config.env
```

Renseignez votre propre clé après le signe `=` de `ANTHROPIC_API_KEY`. La variable d’environnement système du même nom est prioritaire sur le fichier.

Relancez l’application après modification. Le mode Claude dépend de la clé, du réseau et du modèle configuré dans `core/ai_core.py`. En cas d’échec de l’appel Claude, le code prévoit un retour à l’analyse locale.

**L’activation de Claude transmet un contexte d’analyse à l’API Anthropic.** Gardez `config.env` hors du dépôt.

## Points à connaître

- Le gestionnaire `quarantine/quarantine_manager.py` doit être versionné pour permettre l’initialisation complète des modules.
- Le menu CLI affiche davantage d’entrées que celles actuellement traitées par `run_cli()`. Le code gère notamment le scan rapide et la génération/activation de licences.
- Les guides incluent des descriptions et des propositions commerciales qui ne remplacent pas une validation des fonctions sur le système utilisé.
- Les options dépendant des permissions et du système d’exploitation doivent être vérifiées dans l’environnement cible.

## Documentation et support

- [Guide complet](docs/GUIDE_COMPLET.md)
- [Guide développeur](docs/GUIDE_DEVELOPPEUR_COMPLET.md)
- [Issues GitHub](https://github.com/La-paix/CyberOS-Security/issues)

Pour signaler une erreur, indiquez le système utilisé, la version de Python, la commande exécutée et le message obtenu. Retirez les clés et les identifiants des journaux avant de les partager.

## Licence du code source

Le projet comprend un mécanisme de licences applicatives. Aucun fichier `LICENSE` n’est présent dans l’import initial du dépôt ; les conditions de distribution du code restent à préciser par le mainteneur.

## Mainteneur

[La-paix](https://github.com/La-paix)
