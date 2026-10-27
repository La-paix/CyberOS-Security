# Licences du propriétaire

Le client vérifie une signature Ed25519 avec une clé publique. Aucune clé privée d'émission ne figure dans cette archive.

## Initialisation unique

Depuis le dossier CyberOS, choisir un chemin **extérieur au dépôt** :

~~~powershell
.\.venv\Scripts\python.exe vendor_tools/license_issuer.py init --private "$env:USERPROFILE\CyberOS_licences_privees\issuer.pem" --public security/license_public_key.pub
~~~

Un mot de passe d'au moins 12 caractères protège la clé privée. Sauvegarder la clé et son mot de passe en privé. L'outil refuse de remplacer une clé existante.

Distribuer seulement security/license_public_key.pub avec l'application. Ce fichier public de 32 octets peut être versionné.

## Émission

~~~powershell
.\.venv\Scripts\python.exe vendor_tools/license_issuer.py issue --private "$env:USERPROFILE\CyberOS_licences_privees\issuer.pem" --tier ENTERPRISE --days 30
~~~

Saisir le mot de passe ; copier la licence affichée dans Paramètres > Licences > Activer. Redémarrer l'application pour lancer les modules correspondant au niveau.

La durée correspond à une échéance signée absolue. Réactiver ne la prolonge pas. Le paramètre --machine-id peut restreindre la licence au fingerprint affiché dans les informations ; ce fingerprint n'est pas une preuve matérielle inviolable.

Les licences historiques à secret partagé doivent être réémises.

## Vente

Cette livraison ne crée ni boutique, ni paiement, ni tarif. Les outils manuels restent accessibles en FREE ; PRO/ENTERPRISE commandent notamment la surveillance des processus, connexions et leurres en arrière-plan.

SIEM, multi-postes et mises à jour automatiques ne sont pas disponibles. Les conditions de support et de licence sont à définir par le propriétaire. Une distribution en source reste modifiable et ses contrôles locaux de licence peuvent être contournés.

Avant vente, valider Windows et les droits sur les sources et dépendances.
