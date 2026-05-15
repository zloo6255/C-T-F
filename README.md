# HACKR00MS — CTF Platform

## Déploiement sur Railway

### 1. Push sur GitHub
```bash
git init
git add .
git commit -m "init ctf"
git remote add origin https://github.com/TONPSEUDO/hackrooms.git
git push -u origin main
```

### 2. Connecter à Railway
1. Va sur railway.com → New Project → Deploy from GitHub
2. Sélectionne ton repo
3. Railway détecte automatiquement Node.js

### 3. Variables d'environnement (IMPORTANT)
Dans Railway → Variables, ajoute :
```
FLAG_SECRET=mets_une_phrase_longue_et_random_ici
PORT=3000
```

Le FLAG_SECRET est crucial — il génère les flags uniques de chaque joueur.
Change-le avant de lancer, et ne le partage JAMAIS.

## Protections intégrées

- Helmet.js (headers sécurité : CSP, HSTS, X-Frame-Options...)
- Rate limiting global (60 req/min) + API (10 req/min)
- Anti-bruteforce progressif (5 strikes = 1min ban, 10 = 10min, 20 = 1h, 50 = 24h)
- Blocage scanners connus (sqlmap, nikto, nmap, gobuster...)
- Validation et sanitization de tous les inputs (express-validator)
- Flags HMAC-SHA256 uniques par joueur — impossible à deviner
- Honeypots sur /admin, /.env, /wp-admin, /phpmyadmin... (logge + ban)
- IP hashée avant tout stockage (aucune IP en clair)
- Body limité à 10kb (anti flood)
- Headers serveur masqués

## Structure
```
ctf-server/
├── server.js        ← backend Node.js
├── package.json
├── railway.toml
└── public/
    └── index.html   ← frontend
```
