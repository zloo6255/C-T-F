const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// ─── IN-MEMORY STORES ────────────────────────────────────────────────────────
const players = {};       // { pseudo: { score, solved[], createdAt } }
const banList = {};       // { ip_hash: { until, strikes } }
const honeypotLogs = [];  // tentatives sur faux panels
const attemptLog = {};    // { ip_hash+roomId: [timestamps] }

// ─── ROOMS ───────────────────────────────────────────────────────────────────
const ROOMS = [
  { id: 'r01', title: 'FIRST_BLOOD',  diff: 'EASY',    points: 100,  secret: 'headers_reveal' },
  { id: 'r02', title: 'B64_SHADOWS',  diff: 'EASY',    points: 150,  secret: 'b64_not_crypto' },
  { id: 'r03', title: 'SQL_INJECT',   diff: 'MEDIUM',  points: 350,  secret: 'sqli_classic'   },
  { id: 'r04', title: 'R3VERSE_ME',   diff: 'MEDIUM',  points: 400,  secret: 'reverse_art'    },
  { id: 'r05', title: 'STEG0_4RT',    diff: 'HARD',    points: 600,  secret: 'steg_binwalk'   },
  { id: 'r06', title: 'ROOT_OR_DIE',  diff: 'EXTREME', points: 1000, secret: 'suid_privesc'   },
];

// ─── UTILS ───────────────────────────────────────────────────────────────────
function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + SECRET).digest('hex').slice(0, 16);
}

function generateFlag(pseudo, roomSecret) {
  const hmac = crypto.createHmac('sha256', SECRET);
  hmac.update(`${pseudo}:${roomSecret}`);
  return `FLAG{${hmac.digest('hex').slice(0, 24)}}`;
}

function isBanned(ipHash) {
  const ban = banList[ipHash];
  if (!ban) return false;
  if (Date.now() > ban.until) { delete banList[ipHash]; return false; }
  return true;
}

function addStrike(ipHash) {
  if (!banList[ipHash]) banList[ipHash] = { strikes: 0, until: 0 };
  banList[ipHash].strikes++;
  const s = banList[ipHash].strikes;
  // progressif : 5 strikes = 1min, 10 = 10min, 20 = 1h, 50 = 24h
  if (s >= 50) banList[ipHash].until = Date.now() + 86400000;
  else if (s >= 20) banList[ipHash].until = Date.now() + 3600000;
  else if (s >= 10) banList[ipHash].until = Date.now() + 600000;
  else if (s >= 5)  banList[ipHash].until = Date.now() + 60000;
}

// ─── MIDDLEWARES ─────────────────────────────────────────────────────────────

// Helmet : tous les headers de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "https://api.anthropic.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Cache-Control
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  next();
});

// CORS strict
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '10kb' })); // limite taille body
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Rate limit global
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requêtes. Attends 1 minute.' },
});
app.use(globalLimiter);

// Rate limit API strict
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Rate limit API dépassé.' },
});

// Middleware anti-ban + log
app.use((req, res, next) => {
  const ipHash = hashIP(req.ip);
  if (isBanned(ipHash)) {
    return res.status(429).json({ error: 'IP temporairement bannie. Trop de tentatives.' });
  }
  next();
});

// Bloquer les scanners connus
app.use((req, res, next) => {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const blocked = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'nuclei', 'dirbuster', 'gobuster', 'wfuzz', 'hydra'];
  if (blocked.some(b => ua.includes(b))) {
    const ipHash = hashIP(req.ip);
    addStrike(ipHash);
    addStrike(ipHash); // double strike pour les scanners
    return res.status(403).json({ error: 'Accès refusé.' });
  }
  next();
});

// Serve frontend
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── HONEYPOTS ───────────────────────────────────────────────────────────────
const fakePaths = ['/admin', '/admin/', '/wp-admin', '/login', '/.env', '/config', '/api/v1/secret', '/backup', '/phpmyadmin', '/shell', '/cmd'];

fakePaths.forEach(p => {
  app.all(p, (req, res) => {
    const ipHash = hashIP(req.ip);
    honeypotLogs.push({ ipHash, path: p, ua: req.headers['user-agent'], ts: Date.now() });
    addStrike(ipHash);
    addStrike(ipHash);
    // Réponse fausse pour les faire croire qu'ils ont trouvé quelque chose
    if (p === '/.env') {
      return res.type('text').send('DB_PASSWORD=hunter2\nSECRET_KEY=not_the_real_one\n');
    }
    if (p === '/admin' || p === '/admin/') {
      return res.status(200).send('<html><body><h2>Admin Panel</h2><form><input name="user"/><input name="pass" type="password"/><button>Login</button></form></body></html>');
    }
    res.status(404).json({ error: 'Not found' });
  });
});

// ─── API ROOMS ────────────────────────────────────────────────────────────────
app.get('/api/rooms', (req, res) => {
  const safe = ROOMS.map(r => ({
    id: r.id, title: r.title, diff: r.diff, points: r.points,
  }));
  res.json(safe);
});

// ─── REGISTER ────────────────────────────────────────────────────────────────
app.post('/api/register',
  apiLimiter,
  body('pseudo')
    .trim()
    .isLength({ min: 2, max: 24 })
    .matches(/^[a-zA-Z0-9_\-]+$/)
    .withMessage('Pseudo invalide (2-24 chars, lettres/chiffres/_/-)'),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const { pseudo } = req.body;
    if (players[pseudo]) return res.status(409).json({ error: 'Pseudo déjà pris.' });
    players[pseudo] = { score: 0, solved: [], createdAt: Date.now() };
    res.json({ ok: true, pseudo });
  }
);

// ─── GET FLAG (pour affichage dans le challenge) ──────────────────────────────
app.get('/api/flag/:roomId',
  apiLimiter,
  (req, res) => {
    const ipHash = hashIP(req.ip);
    const pseudo = req.query.pseudo;
    if (!pseudo || !players[pseudo]) return res.status(401).json({ error: 'Pseudo inconnu.' });

    const room = ROOMS.find(r => r.id === req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Room inconnue.' });

    const flag = generateFlag(pseudo, room.secret);
    res.json({ flag });
  }
);

// ─── SUBMIT FLAG ──────────────────────────────────────────────────────────────
app.post('/api/submit',
  apiLimiter,
  body('pseudo').trim().isLength({ min: 2, max: 24 }).matches(/^[a-zA-Z0-9_\-]+$/),
  body('roomId').trim().isLength({ min: 1, max: 10 }).matches(/^[a-z0-9]+$/),
  body('flag').trim().isLength({ min: 1, max: 200 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Input invalide.' });

    const { pseudo, roomId, flag } = req.body;
    const ipHash = hashIP(req.ip);

    // Anti-bruteforce par IP+room
    const key = `${ipHash}:${roomId}`;
    if (!attemptLog[key]) attemptLog[key] = [];
    const now = Date.now();
    attemptLog[key] = attemptLog[key].filter(t => now - t < 60000);

    if (attemptLog[key].length >= 5) {
      addStrike(ipHash);
      return res.status(429).json({ error: 'Rate limit : 5 essais/min max par room.', wait: 60 });
    }
    attemptLog[key].push(now);

    if (!players[pseudo]) return res.status(401).json({ error: 'Pseudo inconnu.' });

    const room = ROOMS.find(r => r.id === roomId);
    if (!room) return res.status(404).json({ error: 'Room inconnue.' });

    const expected = generateFlag(pseudo, room.secret);

    if (flag !== expected) {
      addStrike(ipHash);
      const remaining = 5 - attemptLog[key].length;
      return res.status(400).json({ error: `Flag incorrect. ${remaining} essai(s) restant(s) avant cooldown.` });
    }

    // Correct !
    if (!players[pseudo].solved.includes(roomId)) {
      players[pseudo].solved.push(roomId);
      players[pseudo].score += room.points;
    }

    res.json({ ok: true, points: room.points, totalScore: players[pseudo].score });
  }
);

// ─── SCOREBOARD ───────────────────────────────────────────────────────────────
app.get('/api/scores', (req, res) => {
  const scores = Object.entries(players)
    .map(([pseudo, data]) => ({ pseudo, score: data.score, solved: data.solved.length }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 20);
  res.json(scores);
});

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  const ipHash = hashIP(req.ip);
  addStrike(ipHash);
  res.status(404).json({ error: 'Not found.' });
});

// ─── START ────────────────────────────────────────────────────────────────────
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => console.log(`CTF server running on port ${port}`));
