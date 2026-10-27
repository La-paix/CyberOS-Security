# Guide développeur — 2026.2.1

## Architecture

main.py vérifie les dépendances, acquiert un verrou local et contrôle le manifeste avant la CLI/GUI. core/controller.py orchestre 18 modules. core/engine.py gère scans, progression et annulation ; elpati/elpati_threat_intel.py fournit les indicateurs locaux.

Le gestionnaire de quarantaine chiffre les contenus et évite les collisions. core/security_vault.py sépare manifeste des sources et index des preuves. reports/pdf_generator.py est une source versionnée ; les PDF générés sont exclus de Git.

elpati_auth_voice.py gère le mot de passe local : son nom historique n'implique pas une authentification vocale disponible. utils/storage.py fournit les écritures atomiques. La journalisation est une chaîne d'empreintes locale, pas une preuve indépendante contre un administrateur.

## Tests

python tests/run_tests.py copie les sources nécessaires dans un dossier temporaire et lance tests/suite.py. --gui ajoute tests/gui_suite.py avec un affichage réel/virtuel. Le nettoyage de fixtures refuse de fonctionner hors de cette copie.

Les tests incluent corruption, collision, écrasement, échec d'écriture, annulation, expiration, signature modifiée et rollback. Les appels Anthropic sont simulés ; le serveur HTTP de test est limité au loopback. Les commandes de pare-feu/processus sont remplacées par des doubles.

Les tests n'attestent ni une couverture exhaustive ni une efficacité antivirale certifiée.

## Chiffrement et migration

AES-256-GCM utilise une clé aléatoire de 32 octets dans security/keys/master.key, un nonce aléatoire de 12 octets par message et le préfixe CYBEROS2: comme données associées. Aucun repli XOR.

Le secret est un fichier local. Les permissions et la sécurité du compte restent nécessaires ; un administrateur peut accéder aux secrets.

Le mot de passe utilise PBKDF2-SHA256 avec sel aléatoire et 600 000 itérations, puis un enregistrement chiffré. Un ancien hash SHA3 migré est mis à niveau après une connexion correcte.

tools/migrate_legacy.py est la seule route qui dérive l'ancien secret fixe pour convertir les données. L'outil authentifie les candidats, prépare de nouvelles copies, sauvegarde les originaux, écrit un journal et applique la conversion. Un arrêt en cours impose --rollback.

Les signatures locales RSA-PSS et les signatures de licences Ed25519 sont distinctes. Le propriétaire émet les licences hors du client, avec une clé privée absente de la distribution.

## Intégrité

Le manifeste utilise SHA3-256 et des chemins portables. Les séparateurs historiques Windows sont normalisés. Une source ajoutée, supprimée ou modifiée, ou un manifeste illisible, bloque le démarrage.

.gitattributes conserve les sources en LF sur Windows/Linux. Après une modification volontaire et revue, lancer python tools/build_manifest.py, puis les tests.

Le manifeste n'est pas une signature d'éditeur. Une personne maîtrisant tout le dossier peut remplacer source et manifeste. Les outils de développement, tests et guides ne font pas partie de ce contrôle applicatif ; la livraison fournit une empreinte externe de l'archive.

## Interface

Les travailleurs déposent leurs callbacks dans une file exécutée par le thread Tkinter. Un numéro de page rejette les résultats arrivés après navigation. L'état du scan est libéré même si sa page a été quittée. Les timers sont annulés à la fermeture.

Les actions nécessitant un résultat antérieur doivent le demander au lieu de produire un faux rapport.

## Distribution

Ne jamais distribuer clés, mots de passe, coffres, journaux, état, config.env, .venv ou sauvegardes. La référence FIM dépend de la machine et n'est plus publiée.

Le workflow prépare une matrice Windows/Linux après publication. Les résultats locaux documentés séparément ne sont pas des résultats déjà obtenus sur Windows.

Références techniques : documentation cryptography.io AES-GCM et Ed25519, modèle de threads Tkinter de docs.python.org, exemples officiels actions/checkout et actions/setup-python.
