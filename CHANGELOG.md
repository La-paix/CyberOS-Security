# Changements 2026.2.1

Base : commit public 429b6d6aeb250f0deb9e7e31e3aa54867fa656ec.

## Correctif du scanner Windows et des exports — 27 octobre 2026

- Corrige les faux positifs reproduits à partir du rapport Windows : les noms d'API courantes, les littéraux d'un programme de sécurité, une entropie élevée ou l'extension générique .enc ne prouvent pas une infection.
- Préserve la vérification de toutes les empreintes avant les heuristiques, y compris pour un fichier .enc, une bibliothèque ou un code source. Aucune liste blanche de noms de fichiers n'est ajoutée.
- Sépare correspondances de signatures et indices statiques à examiner. Ces derniers ne déclenchent ni quarantaine automatique, ni arrêt de processus, ni scénario automatique.
- Conserve le champ historique threats_found comme nombre d'alertes ; ajoute confirmed_threats et review_count. Le premier compte les correspondances de signatures, sans prouver une infection active.
- Limite le scan QUICK à deux niveaux de sous-dossiers et annonce la portée. FULL conserve la descente complète ; erreurs et fichiers inaccessibles restent visibles.
- Réutilise la base de règles du moteur et lit une seule fois l'échantillon heuristique, au lieu de recréer des modules et recharger les signatures pour chaque fichier.
- Limite l'aperçu d'interface à 200 alertes, le PDF à 20 alertes prioritaires, et conserve toutes les données dans un JSON joint du même nom. Les deux fichiers restent privés par défaut.
- Reproduit les défauts avant correction avec neuf nouveaux contrôles en échec/erreur ; ajoute ensuite les contrôles de non-exécution et d'interface. Validation : 149/149 sous Linux et 149/149 sur le PC Windows de l'utilisateur, dont 43 tests GUI. Le dernier journal Windows ne contient aucun test ignoré.

- Corrige les empreintes du moteur et les signatures personnalisées.
- Rend visibles erreurs/exclusions ; borne les travaux en attente et implémente l'annulation.
- Rend les identifiants de quarantaine uniques ; vérifie les données et interdit l'écrasement à la restauration.
- Remplace le secret AES constant par une clé aléatoire et supprime le repli XOR.
- Ajoute une migration avec préparation, sauvegarde et rollback.
- Crée le mot de passe au premier lancement ; utilise PBKDF2 salé et un verrouillage persistant ; refuse les réinitialisations sur corruption.
- Vérifie la liste des sources, normalise les chemins Windows et refuse les manifestes absents/corrompus.
- Sépare index des preuves et manifeste, protège les chemins et évite les collisions.
- Vérifie l'entrée initiale des journaux et conserve chaque écriture au redémarrage.
- Remplace les licences à secret partagé par des signatures Ed25519, avec émission séparée et échéance absolue.
- Complète les routes CLI et les actions forensic/PDF manquantes.
- Fournit le module PDF et conserve les sources de reports dans Git.
- Corrige callbacks Tkinter, navigation pendant un scan, fermeture et timers.
- Ajoute restauration et suppression à la page de quarantaine.
- Corrige poids des indicateurs booléens, noms de processus vides, adresses mémoire textuelles et jours du planificateur.
- Désactive les réponses automatiques et choisit le mode passif par défaut ; évite les faux succès pour les actions indisponibles.
- Rend l'API distante explicitement facultative, sans appel payant au démarrage.
- Signale les analyses URL incomplètes ; conserve les redirections et ne dilue plus un domaine malveillant connu dans une moyenne.
- Stabilise UTF-8 et les fins de ligne ; retire la référence FIM propre à la machine.
- Ajoute tests isolés, GUI et workflow Windows/Linux. Résultats : docs/VALIDATION.md.

Les fonctions SIEM, multi-postes, mises à jour automatiques, authentification vocale et certification de protection ne sont pas implémentées.


## Correctif de tests Windows — 27 octobre 2026

- Prend en charge le cas EICAR inaccessible avec errno 22, limité à Windows et au chemin du fichier de test.
- Vérifie d'abord le fonctionnement d'une lecture/écriture ordinaire ; conserve les autres erreurs.
- Rapporte explicitement un test disque non validé, sans affirmer que l'antivirus est la cause.
- Ajoute le contrôle du moteur par un flux EICAR en mémoire et deux contrôles de régression de gestion d'erreur.
- Préserve les 48 sources applicatives, le manifeste et les données privées. Validation Linux : 135/135.
- Utilise py -3 dans les commandes d'installation pour ne pas imposer Python 3.12 absent.
