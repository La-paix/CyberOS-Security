# Validation de la livraison corrigée

Version 2026.2.1, issue du commit public 429b6d6aeb250f0deb9e7e31e3aa54867fa656ec. Travaux initiaux réalisés le 24 octobre 2026 ; correctifs de tests et du scanner Windows le 27 octobre 2026.

## Résultats mesurés

**149 tests réussis, aucun échec, aucune erreur, aucun test ignoré** sous Linux et lors de l'exécution Windows transmise par l'utilisateur. Cela signifie que tous les cas de cette suite passent ; ce n'est ni une mesure de couverture exhaustive ni une fiabilité de 100 %.

- 106 tests de régression/intégration du cœur.
- 43 tests Tkinter avec serveur d'affichage Xvfb.
- Syntaxe compilée pour les 54 fichiers Python, et grammaire Python 3.10 vérifiée pour les 48 sources applicatives.
- Vérification statique Ruff des noms non définis et redéfinitions F821/F822/F823/F811 : aucune anomalie.
- Installation des dépendances dans un environnement virtuel neuf, puis pip check : aucune dépendance incohérente.

Les fichiers [test-results.json](test-results.json) et [windows-test-results.json](windows-test-results.json) contiennent les noms et résultats individuels Linux et Windows. La suite est incluse et peut être rejouée avec python tests/run_tests.py --gui. Les tests utilisent une copie temporaire ; les clés de test ne sont pas distribuées.

## Environnement observé

Linux, Python 3.12.14, Tcl/Tk 9.0.4 avec Xvfb, psutil 7.2.2, cryptography 50.0.2, reportlab 4.4.9, Pillow 12.3.0, cffi 2.1.1, pycparser 3.11 et charset-normalizer 3.5.2.

La validation initiale de 132 tests a passé dans un environnement virtuel neuf, avec les versions fixées par requirements-tested.txt. Le correctif EICAR a ensuite passé 135 contrôles, puis la révision du scanner a passé 149 contrôles sous Linux dans le runtime de validation. La suite a également passé sur le PC Windows de l'utilisateur. Le dernier journal ne réaffiche pas la version de Python ; l'installation précédente utilisait Python 3.13.11. La matrice Python 3.10/3.12/3.14 du workflow reste à exécuter : ce résultat local Windows ne remplace pas les jobs correspondants.

## Correctif des tests Windows du 27 octobre 2026

Le journal transmis par l'utilisateur montre Python 3.13.11, une installation complète, une vérification des sources réussie, puis **131 tests réussis sur 132**. Les 42 tests GUI ont réussi. L'unique erreur est OSError errno 22 à l'ouverture du fichier EICAR sur disque.

Ce code d'erreur ne prouve pas à lui seul une interception antivirus. Le correctif limite la gestion particulière au chemin exact du fichier EICAR sous Windows et à certains codes d'accès. Il vérifie ensuite qu'un fichier de contrôle ordinaire dans le même dossier peut être écrit et lu. Si ces conditions sont réunies, le test disque est marqué SKIP, avec une explication indiquant qu'il n'a pas été validé. Les erreurs d'autres chemins et les erreurs de disque générales ne sont pas masquées.

Un nouveau test alimente les fonctions réelles de hachage et de détection avec un flux EICAR en mémoire, sans écrire ce contenu sur disque. Deux autres contrôles vérifient la classification des erreurs et reproduisent l'errno 22 reçu. La reproduction contrôlée vérifie bien un statut non validé, jamais un faux succès de détection disque.

Le premier correctif EICAR comportait 135 tests. La suite actuelle en comporte 149. Sur un poste où le fichier EICAR reste inaccessible, le résultat peut être 148 réussites et 1 test ignoré ; cela ne valide pas le test disque. Le dernier journal Windows confirme maintenant 149 réussites, y compris EICAR sur disque, sans test ignoré. Le correctif EICAR ne change aucun réglage d'antivirus ni fichier chiffré. La révision du scanner décrite ci-dessous modifie les sources applicatives, pas les données privées.

## Essai réel Windows : faux positifs et rapport volumineux

Le second PDF transmis le 27 octobre montre un QUICK terminé sans annulation : 128 588 fichiers traités, 5 981 alertes, 62 erreurs et 36 fichiers ignorés, en 1 768,9 secondes. Le PDF contient 1 716 pages. Les 5 981 alertes se répartissent en 5 896 HIGH, 68 CRITICAL et 17 RANSOMWARE_EXTENSION ; aucune entrée KNOWN_MALWARE n'est présente. Ces nombres ne prouvent donc pas 5 981 infections.

Des API ordinaires, des littéraux de code de sécurité et d'anciens fichiers password.enc sont signalés. Neuf tests supplémentaires ont reproduit les défauts avant modification (5 échecs et 4 erreurs, dont des métadonnées non encore implémentées). Après correction, tous passent ; les contrôles ont été complétés jusqu'à 149, dont 43 GUI.

La révision distingue les correspondances de signatures et les indices statiques. Le champ historique threats_found reste un total d'alertes pour compatibilité ; confirmed_threats compte les correspondances de signatures et review_count les indices non confirmés. Toutes les empreintes restent contrôlées avant les heuristiques, sans liste blanche de noms. Les règles statiques ne certifient ni l'exécution d'une commande ni l'innocuité d'un fichier. L'analyse Python ne relève que certains appels de commande constants ; elle ne résout pas tous les alias ou constructions dynamiques.

Les noms d'API usuelles, la forte entropie et les extensions génériques .enc/.crypt/.encrypted/.vault ne suffisent plus à produire une alerte élevée. Les extensions plus spécifiques et certains motifs de commande sont soumis à examen, sans déclencher d'action automatique. Le scan rapide annonce une portée de deux niveaux de sous-dossiers ; le scan complet conserve la descente récursive. Les erreurs d'accès restent comptabilisées et visibles.

Le PDF présente 20 alertes prioritaires et crée un JSON joint contenant toutes les données du scan exporté. Un jeu synthétique de 5 981 alertes produit 4 pages et conserve les 5 981 entrées dans le JSON ; ce n'est pas un nouveau scan du PC. Les sources de règles sont réutilisées, au lieu d'être rechargées pour chaque fichier.

Résultat local de la révision : 149 réussites, 0 échec, 0 erreur, 0 test ignoré, en 33,748 secondes. Le correctif a ensuite passé les 149 tests sur le Windows de l'utilisateur en 124,825 secondes, comme détaillé ci-dessous.

## Validation automatique Windows reçue le 27 octobre 2026

Le dernier journal montre la sélection de l'archive par son empreinte SHA-256, une extraction dans un nouveau dossier, puis main.py --check réussi. Les 149 tests ont tous passé en 124,825 secondes : 106 contrôles du cœur et 43 GUI, sans échec, erreur ou test ignoré. EICAR sur disque et en mémoire passent, ainsi que les nouveaux contrôles des faux positifs, de la portée rapide, des actions automatiques et du PDF volumineux.

Le manifeste des 48 sources applicatives testées a pour SHA-256 1d545ee47b3f417718eb16ad5d3826d43e1717f343a30c7468fa1827c6e59eee. La mise à jour de livraison qui consigne ce résultat ne change ni les sources applicatives, ni les tests, ni les dépendances. Les résultats sont transcrits du journal reçu ; aucun nouveau test n'a été exécuté à distance sur le PC par l'assistant.

Cette validation porte sur les cas de la suite, avec les substituts documentés ci-dessous. Le scan de vrais dossiers après correction, les commandes natives actives et une mesure représentative de l'efficacité de détection demeurent des vérifications distinctes.

## Régressions du premier audit

| Défaut constaté | Correction et test associé |
| --- | --- |
| EICAR manqué par le moteur SHA3 | Contrôles MD5/SHA-256/SHA3 ; fichier EICAR réel inoffensif détecté, test 33 |
| Signature personnalisée cassant les scans | Normalisation des schémas chaîne/dictionnaire ; tests 34 à 36 |
| Deux fichiers remplacés en quarantaine | Identifiants UUID, absence d'écrasement ; tests 25 à 31, 84 et 85 |
| Mot de passe corrompu réinitialisé au défaut | Refus de connexion et données conservées ; tests 1 à 7 |
| Clé AES reconstruite depuis un secret fixe et le sel | Secret aléatoire local, clé perdue/corrompue refusée ; tests 8 à 14 |
| Manifeste Windows ignoré sous Linux | Chemins normalisés et liste complète ; tests 15 à 21 |
| Manifeste corrompu réappris comme fiable | Absence/corruption refusée ; tests 20 et 21 |
| Première entrée du journal non vérifiée | Vérification depuis l'ancre initiale et persistance ; tests 46 à 48 |
| Option CLI de scan complet inopérante | Routage complet et démarrage séparé ; tests 75, 76 et 83 |
| Module PDF absent | Module fourni et actions de l'interface implémentées ; tests 58, 59 et tests GUI |

Deux changements d'attente sont volontaires : une installation neuve doit créer son mot de passe, et le client n'émet plus de licences. Les tests valident ces nouveaux comportements, ainsi que les licences signées par l'utilitaire du propriétaire.

## Corrections trouvées lors des nouveaux essais

La première nouvelle série comptait 82 tests ; 7 échouaient à cause de dossiers de données non recréés en utilisation répétée. Ces défauts ont été corrigés et les 82 tests ont ensuite réussi.

Les essais GUI ont révélé des callbacks restant actifs après fermeture. Ils ont été corrigés, puis des contrôles de timers et de navigation ont été ajoutés. Les suites ont été étendues successivement jusqu'aux 132 cas de cette livraison.

La vérification porte aussi sur l'arrêt du scan, la reprise après erreur, les fichiers déjà présents à la restauration, les opérations de quarantaine concurrentes, les erreurs de disque simulées, les licences modifiées/expirées, la migration avec rollback, les contrôles d'intégrité et les exports.

## Nature des tests

- EICAR et les autres fixtures sont inoffensifs. Aucun vrai malware n'est exécuté.
- Les tests du moteur utilisent réellement les fichiers de la copie temporaire.
- Le test HTTP utilise un serveur loopback contrôlé ; les tests d'indisponibilité du réseau sont simulés.
- Les tests d'authentification, AES, RSA et Ed25519 utilisent les primitives réelles.
- Les tests des exports créent de vrais JSON et PDF, avec des observations synthétiques pour éviter d'exporter des informations privées de l'hôte.
- Les tests GUI créent de vraies fenêtres et activent les actions ; les dialogues bloquants sont remplacés par des réponses contrôlées.
- Les commandes actives de pare-feu/processus sont simulées pour vérifier les arguments et statuts sans modifier l'hôte.
- Les réponses de l'API payante sont simulées ; aucun appel réel facturable n'a été effectué.

## Ce qui reste à valider avant une vente

**Intégration native Windows**, notamment droits et comportement réel des commandes actives de pare-feu/processus, visibilité de la mémoire et cycle de mise à jour. La suite automatique et ses 43 tests GUI ont passé sur un vrai PC Windows, mais les commandes actives y restent remplacées par des substituts contrôlés.

**Intégration Anthropic avec un compte de test autorisé**, un modèle disponible et une enveloppe de coût choisie par le propriétaire. Les erreurs et le repli local sont testés, mais pas une facturation réelle.

**Efficacité de détection**, faux positifs et performances sur des corpus représentatifs. Cette suite de développement ne constitue pas une évaluation antivirale indépendante. Les outils restent des heuristiques et une base locale limitée.

**Migration des vraies données de votre PC**, avec sauvegarde. Des fixtures représentatives sont testées ; aucun fichier privé Windows de l'utilisateur n'était accessible ici.

**Configuration du vendeur**, clé publique de licence, conditions de distribution, droits sur les sources/dépendances, prix, support et mécanisme de paiement. Aucun achat ou acceptation de plateforme n'est garanti.

## Vérifier et publier

Suivre INSTALLATION_WINDOWS.md. Extraire dans un nouveau dossier, installer les versions testées, exécuter --check, la suite GUI, puis vérifier manuellement les principaux parcours.

Le contrôle de manifeste est un mécanisme local de cohérence, pas une signature d'éditeur. Ne pas utiliser un nouveau manifeste pour approuver un changement dont l'origine est inconnue.

La version corrigée est livrée en archive ; aucun changement n'a été poussé automatiquement sur GitHub.
