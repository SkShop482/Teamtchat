const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = process.env.JWT_SECRET || 'teamchat_dev_secret_change_me';
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI manquant !');
  process.exit(1);
}

let users, messages;

const onlineUsers = new Map();

function broadcastOnline() {
  const list = [...onlineUsers.keys()];
  const msg = JSON.stringify({ type: 'online', users: list });
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
}

function canAccess(user, conv) {
  if (user.role === 'admin') return true;
  if (conv === 'global') return true;
  const parts = conv.split('__');
  return parts.length === 2 && parts.includes(user.username);
}

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  const user = await users.findOne({ username: username.trim().toLowerCase() });
  if (!user) return res.status(401).json({ error: 'Utilisateur introuvable' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Mot de passe incorrect' });
  const token = jwt.sign({ id: user._id.toString(), username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('tc_token', token, { httpOnly: true, maxAge: 7 * 86400000, sameSite: 'strict' });
  res.json({ username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('tc_token');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ username: req.user.username, role: req.user.role }));

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  const [u, m] = await Promise.all([
    users.countDocuments({ role: 'user' }),
    messages.countDocuments({})
  ]);
  const online = [...onlineUsers.keys()].filter(u => u !== 'admin').length;
  res.json({ users: u, msgs: m, online });
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const list = await users.find({ role: 'user' }).sort({ createdAt: -1 }).toArray();
  res.json(list.map(u => ({ ...u, password: undefined, online: onlineUsers.has(u.username) })));
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  const u = username.trim().toLowerCase();
  if (!/^[a-z0-9_]{2,20}$/.test(u)) return res.status(400).json({ error: 'Pseudo invalide (2-20 chars, lettres/chiffres/_)' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court (min 6)' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    await users.insertOne({ username: u, password: hash, role: 'user', createdAt: Date.now() });
    const msg = { conv: 'global', from_user: 'Admin', text: `👋 Bienvenue à ${u} !`, createdAt: Date.now() };
    await messages.insertOne(msg);
    wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(JSON.stringify({ type: 'message', ...msg, at: msg.createdAt })); });
    res.json({ ok: true, username: u });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Ce pseudo est déjà pris' });
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/admin/users/:username', auth, adminOnly, async (req, res) => {
  const u = req.params.username;
  if (u === 'admin') return res.status(400).json({ error: 'Impossible' });
  await users.deleteOne({ username: u });
  await messages.deleteMany({ from_user: u });
  onlineUsers.get(u)?.forEach(ws => ws.close());
  onlineUsers.delete(u);
  broadcastOnline();
  res.json({ ok: true });
});

app.get('/api/admin/messages', auth, adminOnly, async (req, res) => {
  const { user } = req.query;
  const q = user ? { $or: [{ from_user: user }, { conv: { $regex: user } }] } : {};
  const msgs = await messages.find(q).sort({ createdAt: -1 }).limit(100).toArray();
  res.json(msgs);
});

app.get('/api/users', auth, async (req, res) => {
  const list = await users.find({ role: 'user', username: { $ne: req.user.username } }).sort({ username: 1 }).toArray();
  res.json(list.map(u => ({ username: u.username, createdAt: u.createdAt, online: onlineUsers.has(u.username) })));
});

app.get('/api/messages/:conv', auth, async (req, res) => {
  const conv = req.params.conv;
  if (!canAccess(req.user, conv)) return res.status(403).json({ error: 'Accès refusé' });
  const msgs = await messages.find({ conv }).sort({ createdAt: 1 }).toArray();
  res.json(msgs);
});

wss.on('connection', (ws, req) => {
  const cookies = parseCookies(req.headers.cookie || '');
  let user;
  try { user = jwt.verify(cookies.tc_token || '', JWT_SECRET); }
  catch { ws.close(1008, 'Unauthorized'); return; }

  ws.username = user.username;
  ws.role = user.role;
  if (!onlineUsers.has(user.username)) onlineUsers.set(user.username, new Set());
  onlineUsers.get(user.username).add(ws);
  broadcastOnline();

  ws.on('message', async raw => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    if (data.type === 'message') {
      const { conv, text } = data;
      if (!text?.trim() || !conv || !canAccess(user, conv)) return;
      const t = text.trim().slice(0, 2000);
      const doc = { conv, from_user: user.username, text: t, createdAt: Date.now() };
      await messages.insertOne(doc);
      const payload = JSON.stringify({ type: 'message', ...doc, from: user.username, at: doc.createdAt });
      wss.clients.forEach(c => {
        if (c.readyState === WebSocket.OPEN && canAccess({ username: c.username, role: c.role }, conv))
          c.send(payload);
      });
    }

    if (data.type === 'typing') {
      wss.clients.forEach(c => {
        if (c.readyState === WebSocket.OPEN && c !== ws && canAccess({ username: c.username, role: c.role }, data.conv))
          c.send(JSON.stringify({ type: 'typing', conv: data.conv, from: user.username }));
      });
    }
  });

  ws.on('close', () => {
    onlineUsers.get(user.username)?.delete(ws);
    if (!onlineUsers.get(user.username)?.size) onlineUsers.delete(user.username);
    broadcastOnline();
  });

  ws.on('error', () => {});
});

function auth(req, res, next) {
  const token = req.cookies.tc_token;
  if (!token) return res.status(401).json({ error: 'Non authentifié' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  next();
}

function parseCookies(str) {
  const obj = {};
  str.split(';').forEach(p => { const [k, ...v] = p.trim().split('='); if (k) obj[k.trim()] = decodeURIComponent(v.join('=')); });
  return obj;
}

(async () => {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log('✅ MongoDB connecté');

    const db = client.db();
    users = db.collection('users');
    messages = db.collection('messages');

    await users.createIndex({ username: 1 }, { unique: true });
    await messages.createIndex({ conv: 1 });

    const admin = await users.findOne({ username: 'admin' });
    if (!admin) {
      const hash = bcrypt.hashSync('admin123', 10);
      await users.insertOne({ username: 'admin', password: hash, role: 'admin', createdAt: Date.now() });
      console.log('✅ Admin créé: admin / admin123');
    }

    server.listen(PORT, () => console.log(`✅ TeamChat on port ${PORT}`));
  } catch (err) {
    console.error('❌ Erreur démarrage:', err);
    process.exit(1);
  }
})();
