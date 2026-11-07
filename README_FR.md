# EVAT Continuum 4.9.1 : correctif et installation

## Ce qui change
- Le micro et la caméra gardent leurs erreurs de permission propres.
- Les erreurs de création/négociation WebRTC ne sont plus présentées comme un échec du micro : le message indique maintenant la piste réseau/TURN.
- Le test ICE précise qu’un relais TURN annoncé mais sans candidat obtenu peut venir de la configuration du relais ou d’un port/protocole bloqué.
- Le cache PWA est versionné pour charger la nouvelle version; les fichiers d’icône et le manifeste sont inclus.

Ce correctif améliore le diagnostic, mais **ne configure pas le service TURN** et ne garantit pas qu’un appel passera. Le test précédent montrait qu’aucun relais n’était obtenu; il faut toujours vérifier les URLs, identifiants et ports TURN dans l’hébergement du serveur. N’ajoutez jamais ces secrets au ZIP ou au code client.

## Installation Android en un clic depuis Chrome
EVAT est déjà une PWA : la bannière « Installer EVAT Continuum » et son bouton sont présents dans l’interface. Déployez les fichiers web sous HTTPS, ouvrez le site dans Chrome, puis utilisez **Installer l’application** dans la bannière ou **⋮ → Installer l’application / Ajouter à l’écran d’accueil**.

## À propos du fichier .pkg / APK
Un fichier **`.pkg` est un installateur macOS**, pas un format Android. Pour Android, l’installateur natif est un **`.apk`** (ou `.aab` pour Google Play). Ce ZIP contient les sources web et serveur, **pas un APK compilé/signé**. Créer un APK exige un projet Android/TWA, un identifiant d’application, une clé de signature et une association de domaine; aucun de ces éléments n’est fourni ici.

## Déploiement du projet
- Garder les fichiers web ensemble à la racine : `index.html`, `app.js`, `style.css`, `sw.js`, `manifest.webmanifest` et les icônes.
- Le serveur Node utilise `server.js` et `package.json`; lancer avec `npm start` sur Node 18+.
- Les secrets du serveur (TURN, push, stockage, IA) doivent rester dans les variables d’environnement de l’hébergement, jamais dans le ZIP.
- Après déploiement, vider/actualiser le cache du navigateur si l’ancienne version reste affichée, puis relancer « Tester ma connexion d’appel ».
