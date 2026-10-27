# Guide utilisateur — 2026.2.1

Ce guide remplace les instructions historiques sur le mot de passe par défaut, les clés partagées et le générateur de licences intégré.

## Connexion et fichiers

Consulter [INSTALLATION_WINDOWS.md](INSTALLATION_WINDOWS.md). Créer un mot de passe au premier lancement. Une corruption bloque l'accès : ne pas supprimer des fichiers pour tenter de revenir au mot de passe par défaut.

Scan rapide sélectionne des emplacements courants et examine leurs deux premiers niveaux de sous-dossiers. Les sous-dossiers plus profonds ne sont pas couverts par ce mode. Scan complet demande un dossier et descend récursivement. Le moteur déduplique les chemins et exclut notamment liens symboliques, données internes et fichiers de plus de 100 Mio. STOP annule les travaux en attente ; quelques fichiers déjà en lecture peuvent se terminer.

Le résultat indique annulation, erreurs et exclusions. Il distingue les correspondances de signatures des indices statiques à examiner. Une correspondance identifie une empreinte enregistrée, pas une infection active. Une absence de détection ne prouve pas l'absence d'infection. Les heuristiques peuvent donner des faux positifs. La mise en quarantaine automatique est désactivée par défaut ; même activée, elle ne traite pas les indices non confirmés.

Une API comme GetProcAddress, une forte entropie ou une extension générique .enc ne suffisent pas à établir une menace. Le fichier reste contrôlé par empreinte. Les anciens compteurs de scans sont conservés et représentent des alertes cumulées, pas un nombre de virus confirmés.

## Quarantaine

Sélectionner une entrée puis RESTAURER ou SUPPRIMER. Une restauration ne remplace pas un fichier existant ; choisir un autre chemin si nécessaire. La suppression détruit le contenu chiffré local, sous réserve des sauvegardes conservées.

Sauvegarder ensemble quarantine/vault et security/keys. Ne jamais les publier.

## Processus, mémoire et réseau

Les écrans montrent les informations accessibles au compte courant. L'analyse mémoire utilise des métadonnées et certaines régions Linux accessibles ; elle ne réalise pas un dump complet de RAM Windows et ne garantit pas de détecter tout code injecté.

Les modules de surveillance interrogent périodiquement le système. Les leurres ne surveillent pas toutes les écritures de tous les dossiers. Les contrôles locaux de configuration ne constituent pas un inventaire complet des CVE ou correctifs.

Les actions de pare-feu/processus dépendent des droits et du système. Le mode passif est choisi par défaut. Réduire la priorité d'un processus ne l'isole pas du réseau.

## URL et assistant

Le scanner contacte l'URL et effectue des contrôles TLS/DNS/HTTP et des heuristiques locales. Il n'utilise pas VirusTotal et n'est pas un service de réputation exhaustif. INCONCLUSIF indique des contrôles inaccessibles. Un faible score ne prouve pas qu'un site est sûr.

L'assistant local donne une aide embarquée. L'API distante requiert une activation explicite dans config.env ; elle peut entraîner une facturation et une transmission d'indicateurs/conversations. Une panne distante déclenche le repli local.

## Rapports

Le menu Forensic produit JSON et PDF. Pour le PDF d'un scan ou d'une URL, lancer l'analyse correspondante d'abord. Les rapports peuvent contenir noms de processus, chemins et informations privées.

Le PDF est une synthèse : il affiche les compteurs, les limites et un aperçu de 20 alertes prioritaires. Le fichier JSON du même nom, dans le même dossier, conserve les données détaillées fournies à l'export, notamment toutes les alertes du scan. Le journal exporté reste limité aux 200 événements récents. L'interface affiche au plus 200 alertes ; cela ne limite pas les résultats enregistrés dans le JSON. Ne publiez pas ces fichiers privés sur GitHub.

Le coffre chiffre les preuves et vérifie leur empreinte lors de la lecture. Les journaux restent lisibles et sont reliés par des empreintes. Ces mécanismes ne sont pas inviolables face à une personne qui maîtrise complètement le dossier et ne constituent pas une certification externe.

## Planification et fermeture

Choisir nom, type et horaire. L'API du planificateur accepte aussi jours ouvrés, fins de semaine et jour nommé. Les horaires suivent le fuseau du PC. Le programme doit rester lancé : aucun service Windows n'est installé.

Fermer la fenêtre arrête la surveillance, les rappels d'interface et le planificateur.

## Sauvegardes

Conserver ensemble security/keys, security/auth, security/vault et quarantine/vault. Une clé perdue ne peut pas être reconstituée à partir des sources. La migration d'une ancienne installation est documentée dans le guide Windows.
