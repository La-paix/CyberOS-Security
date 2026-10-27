# Installation Windows et publication GitHub

## Conserver l'ancienne installation

Fermez CyberOS. Gardez votre dossier CyberOS_v2 actuel intact. Décompressez dans un **nouveau dossier**, par exemple Documents\CyberOS_Security_2026.2.1. Évitez de partager les clés locales.

## Installer et tester

Dans le nouveau dossier extrait, ouvrir PowerShell :

~~~powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-tested.txt
.\.venv\Scripts\python.exe main.py --check
.\.venv\Scripts\python.exe tests/run_tests.py --gui
.\.venv\Scripts\python.exe main.py
~~~

Le lanceur py -3 sélectionne un Python 3 déjà installé. Vérifier que la version affichée est au moins 3.10. Sinon, installer un Python compatible avec Tkinter depuis python.org. Les validations attestées sont Linux/Python 3.12 et une exécution Windows locale de 149 tests ; le dernier journal Windows ne réaffiche pas la version de Python. L'appel direct à l'exécutable de .venv ne demande pas de changer la politique PowerShell.

Au premier lancement, saisir puis confirmer un mot de passe d'au moins 12 caractères. Le défaut historique ne fonctionne pas sur une installation neuve.

Vérifier manuellement : connexion, scan d'un petit dossier, annulation, PDF, fermeture et réouverture. Conserver Defender actif ; il peut intercepter EICAR pendant les tests.

Les commandes natives de pare-feu et de contrôle des processus nécessitent une validation en VM Windows dédiée avant vente. La suite automatique ne les exécute pas sur votre ordinateur.

## Correctif du scanner du 27 octobre 2026

Cette archive remplace les sources et les tests de la première livraison 2026.2.1. Elle ne contient aucune clé ni aucun mot de passe personnel. Fermez l'application et gardez votre installation actuelle intacte avant de tester une nouvelle extraction.

Si les dépendances sont déjà installées dans l'ancien dossier, vous pouvez utiliser son exécutable .venv\Scripts\python.exe avec le chemin absolu du nouveau main.py ou de tests\run_tests.py. Cela évite de réinstaller les dépendances pour cet essai. Une nouvelle extraction sans données privées demande de créer son propre mot de passe.

Pour mettre à jour une installation 2026.2.1 déjà utilisée, sauvegardez-la d'abord. Copiez uniquement les sources, documents, tests et le nouveau security/integrity/manifest.json de l'archive ; conservez ensemble security/keys et security/auth, les coffres et data/config.json de votre installation. N'exécutez pas migrate_legacy.py pour cette simple mise à jour 2026.2.1 vers la révision du scanner : elle utilise déjà les clés v2. Ne supprimez aucun fichier .enc sur la seule base de son extension.

Rejouez main.py --check et tests/run_tests.py --gui. La suite compte maintenant 149 tests. Un éventuel test EICAR disque ignoré doit rester présenté comme non validé.

## Réutiliser les anciennes données (facultatif)

Tester d'abord sans données personnelles. Pour migrer :

1. Fermer les deux versions et sauvegarder l'ancien dossier complet.
2. Préparer une **autre extraction propre**, avant son premier lancement.
3. Copier de l'ancienne version seulement security/keys, security/auth, security/vault et quarantine/vault. Pour conserver les réglages/tâches, copier éventuellement data/config.json et data/schedules.json.
4. Ne pas remplacer les nouvelles sources ou security/integrity/manifest.json. Ne pas copier la référence FIM d'une autre machine.
5. Installer les dépendances dans cette extraction, puis lancer :

~~~powershell
.\.venv\Scripts\python.exe tools/migrate_legacy.py
.\.venv\Scripts\python.exe main.py --check
.\.venv\Scripts\python.exe main.py
~~~

La migration remet les actions automatiques en mode désactivé si elle reprend un ancien data/config.json. Elle reconnaît l'ancien master.salt, authentifie les anciens fichiers et conserve les originaux dans .local-backups\migration-…. Garder cette sauvegarde privée jusqu'à vérification.

En cas d'arrêt de machine pendant la migration, fermer CyberOS et lancer :

~~~powershell
.\.venv\Scripts\python.exe tools/migrate_legacy.py --rollback
~~~

Cette commande n'est applicable qu'en présence du journal security/migration_in_progress.json. Elle restaure les fichiers sauvegardés.

Une clé v2 déjà créée n'est jamais remplacée. Repartir d'une extraction neuve plutôt que supprimer les clés à l'aveugle. Une corruption du mot de passe n'est pas réparée par un retour au défaut historique.

## Publier les sources corrigées

Après validation sur votre PC, utiliser votre clone Git existant :

~~~powershell
git rev-parse --show-toplevel
git status --short
git pull --ff-only
~~~

Copier les fichiers de l'extraction propre dans ce clone, y compris .gitignore, .gitattributes, .github, tests, tools, vendor_tools et les deux sources de reports. Ne pas copier .venv, config.env, les coffres, clés ou autres données créées pendant les essais.

L'ancienne référence FIM doit cesser d'être suivie ; cette commande conserve son éventuelle copie locale :

~~~powershell
git rm --cached --ignore-unmatch -- security/fim_baseline.json
git add -- .gitignore .gitattributes .github README.md CHANGELOG.md requirements.txt requirements-tested.txt config.env.example main.py cli core data/i18n.json docs elpati forensic gui quarantine/__init__.py quarantine/quarantine_manager.py reports/__init__.py reports/pdf_generator.py sandbox/__init__.py sandbox/malware_lab.py scanner security/integrity/manifest.json tests tools utils vendor_tools
git diff --cached --stat
git status --short
~~~

Vérifier la liste : aucune clé, configuration privée, donnée de coffre ou sauvegarde ne doit apparaître. Relancer les tests et main.py --check depuis le clone. Puis :

~~~powershell
git commit -m "Corrige les scans, la securite locale et les rapports; ajoute les tests"
git push
~~~

Le workflow démarrera les tests Windows/Linux. Attendre son résultat avant de déclarer une plateforme validée. Aucune publication n'a été faite automatiquement par cette livraison.
