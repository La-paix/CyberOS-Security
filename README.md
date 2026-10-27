# CyberOS Security — ELPATI 2026.2.1

Application Python de sécurité locale avec interface Tkinter et CLI. Cette version corrige le commit public 429b6d6 et fournit une suite de tests reproductible.

**Révision du scanner : 27 octobre 2026.** Corrige les faux positifs et les exports trop volumineux observés lors d'un essai Windows. Validation : 149 tests réussis sous Linux et 149 sur le PC Windows de l'utilisateur, sans test ignoré. Voir les résultats et leur portée dans docs/VALIDATION.md.

Le logiciel relève des indicateurs avec une petite base de signatures et des heuristiques. Il ne constitue pas un antivirus certifié, un EDR d'entreprise complet ou une garantie d'absence de menace. Conservez votre antivirus habituel, vos mises à jour et vos sauvegardes.

## Démarrage

Python 3.10+ avec Tkinter. La validation locale de cette livraison utilise Python 3.12 sous Linux. Guide : [INSTALLATION_WINDOWS.md](docs/INSTALLATION_WINDOWS.md).

~~~powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-tested.txt
.\.venv\Scripts\python.exe main.py --check
.\.venv\Scripts\python.exe main.py
~~~

Au premier lancement, créez votre mot de passe d'au moins 12 caractères. Il n'existe pas de mot de passe par défaut sur une installation neuve.

Pour la CLI : ajouter --cli à la commande de lancement. Sous Linux, créer l'environnement avec python3 -m venv .venv puis utiliser .venv/bin/python. Tkinter peut nécessiter le paquet système python3-tk.

## Fonctions disponibles

- Scans MD5, SHA-256 et SHA3-256, signatures personnalisées, extensions et heuristiques. Les fichiers de plus de 100 Mio, liens symboliques et données internes sont exclus. Les erreurs et exclusions sont comptabilisées.
- Scan rapide limité à deux niveaux de sous-dossiers ; scan complet récursif sur le dossier choisi. Cette limitation ne s'applique pas au scan complet.
- Progression, annulation, erreurs visibles et distinction entre correspondances de signatures et indices non confirmés. Les noms d'API ordinaires et l'extension .enc ne suffisent pas à signaler un fichier.
- PDF synthétique du dernier scan et JSON joint contenant les données détaillées. L'interface et le PDF affichent un aperçu borné, sans supprimer les résultats du JSON.
- Quarantaine chiffrée à identifiants uniques, restauration sans écrasement et suppression explicite.
- Inventaire des processus, connexions et métadonnées mémoire ; certaines régions mémoire Linux sont lues si les permissions le permettent.
- Surveillance périodique des processus, connexions et fichiers leurres. Ces observations ne filtrent pas toutes les opérations du système.
- Quelques contrôles de configuration et ports locaux ; aucune détection exhaustive des CVE installées.
- Surveillance d'intégrité des fichiers et planification quotidienne/jours ouvrés/fins de semaine/jour nommé.
- Analyses URL avec DNS, TLS, redirections, contenu, en-têtes et heuristiques. Les contrôles incomplets sont signalés.
- Rapports forensic JSON, preuves chiffrées, PDF général, scan ou URL.
- Assistant local et intégration Anthropic facultative.
- Thèmes, tailles de police et traductions de l'interface ; certaines descriptions restent en français.

Le module nommé « sandbox » réalise une **analyse statique** : il ne lance pas le fichier et n'émule pas son comportement. Les rapports n'ont aucune certification judiciaire ou externe. SIEM, gestion multi-postes, mises à jour automatiques et authentification vocale ne sont pas implémentés.

## Tests

Les tests travaillent dans une copie temporaire des sources et ne réinitialisent pas votre installation.

La suite actuelle comprend 106 contrôles du cœur et 43 contrôles GUI. Ils ne mesurent pas l'efficacité contre l'ensemble des logiciels malveillants existants.

~~~powershell
.\.venv\Scripts\python.exe tests/run_tests.py
.\.venv\Scripts\python.exe tests/run_tests.py --gui
~~~

Le second appel exige un affichage Tkinter réel ou virtuel. Sous Linux sans bureau : xvfb-run -a .venv/bin/python tests/run_tests.py --gui.

La suite crée temporairement le fichier de test inoffensif EICAR. Si l'antivirus Windows l'intercepte, ce test peut être explicitement ignoré : ne désactivez pas l'antivirus. Les actions de pare-feu/processus sont testées avec des substituts contrôlés, sans modifier le système hôte.

Voir [VALIDATION.md](docs/VALIDATION.md). Le workflow GitHub fourni préparera les tests Windows/Linux après publication ; sa présence ne signifie pas qu'ils ont déjà été exécutés.

## Ancienne installation

**Gardez votre dossier actuel intact.** Décompressez dans un nouveau dossier et lisez le guide Windows avant de réutiliser vos données.

Une ancienne installation contenant master.salt doit lancer explicitement :

~~~powershell
.\.venv\Scripts\python.exe tools/migrate_legacy.py
~~~

La migration authentifie les fichiers avant modification, conserve une sauvegarde privée et remplace le secret fixe par une clé aléatoire d'installation. Elle refuse un fichier chiffré endommagé.

Sauvegardez ensemble security/keys, security/auth, security/vault et quarantine/vault. Perdre la clé empêche de déchiffrer les données. La clé est un fichier privé local : protégez les permissions du dossier et votre compte Windows. Une personne maîtrisant votre compte ou disposant de droits administrateur peut accéder aux secrets.

## API facultative

Aucun compte ni clé API n'est nécessaire aux outils locaux. Copier config.env.example vers config.env, renseigner votre clé et un modèle disponible sur votre compte Anthropic, puis activer AI_REMOTE_ENABLED=true.

Les appels peuvent être facturés et transmettre des indicateurs/conversations au fournisseur. Aucun appel payant de validation n'est fait au démarrage. Une panne distante déclenche le repli local. Ne publiez jamais config.env. L'API payante n'a pas été appelée pendant ces tests.

## Licences

Les outils manuels sont accessibles en FREE. Des licences PRO/ENTERPRISE signées peuvent activer la surveillance avancée en arrière-plan. Ces niveaux ne certifient pas les capacités de protection.

La clé privée d'émission appartient au propriétaire et reste hors du dépôt. Voir [LICENCES_VENDEUR.md](docs/LICENCES_VENDEUR.md). Les anciennes licences doivent être réémises ; réactiver une licence v2 ne repousse pas son échéance.

La protection de licence d'un programme distribué en source reste modifiable par son destinataire. Elle ne remplace pas un contrat et ne garantit aucun paiement.

## Documentation et intégrité

- [Guide utilisateur](docs/GUIDE_COMPLET.md)
- [Guide développeur](docs/GUIDE_DEVELOPPEUR_COMPLET.md)
- [Corrections](CHANGELOG.md)
- [Installation et publication GitHub](docs/INSTALLATION_WINDOWS.md)

Le manifeste vérifie la liste des sources avec des chemins portables. Il s'agit d'un contrôle de cohérence local, **pas d'une signature d'éditeur**. Après une modification volontaire revue, le mainteneur peut lancer python tools/build_manifest.py, puis les tests. Ne reconstruisez pas le manifeste pour simplement masquer une alerte.

Les conditions de distribution/vente doivent être fixées par le propriétaire, après vérification des droits sur les sources et dépendances.
