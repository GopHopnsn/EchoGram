const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

const PORT = process.env.PORT || 3000;
const db = new Database('data.db');

// ===== БАЗА ДАННЫХ =====
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT DEFAULT 'Пользователь',
    phone TEXT DEFAULT '',
    stars INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    verified TEXT DEFAULT NULL,
    extra_usernames TEXT DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER,
    to_id INTEGER,
    text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1 INTEGER,
    user2 INTEGER,
    last_message TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Создаём админа, если его нет
const admin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!admin) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(`INSERT INTO users (username, password, name, stars, is_admin) 
              VALUES (?, ?, ?, ?, ?)`).run('admin', hash, 'Админ', 100000, 1);
  console.log('Админ создан: admin / admin123');
}

// ===== MIDDLEWARE =====
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'change-this-secret-key-12345',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

// ===== API =====

// Регистрация
app.post('/api/register', (req, res) => {
  const { username, password, name } = req.body;
  if (!username || !password || username.length < 3) {
    return res.status(400).json({ error: 'Логин минимум 3 символа' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(
      'INSERT INTO users (username, password, name) VALUES (?, ?, ?)'
    ).run(username.toLowerCase(), hash, name || username);
    
    req.session.userId = result.lastInsertRowid;
    req.session.username = username.toLowerCase();
    res.json({ success: true, userId: result.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: 'Такой логин уже занят' });
  }
});

// Вход
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: 'Неверный логин или пароль' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ success: true, userId: user.id });
});

// Выход
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Текущий пользователь
app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare(`
    SELECT id, username, name, phone, stars, is_admin, verified, extra_usernames 
    FROM users WHERE id = ?
  `).get(req.session.userId);
  user.extra_usernames = JSON.parse(user.extra_usernames || '[]');
  res.json(user);
});

// Список всех пользователей (для чатов)
app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, name, stars, verified 
    FROM users WHERE id != ?
  `).all(req.session.userId);
  res.json(users);
});

// Отправить сообщение
app.post('/api/message', requireAuth, (req, res) => {
  const { to_id, text } = req.body;
  if (!text || !to_id) return res.status(400).json({ error: 'Нет данных' });

  db.prepare('INSERT INTO messages (from_id, to_id, text) VALUES (?, ?, ?)').run(
    req.session.userId, to_id, text
  );

  // Обновляем/создаём чат
  const existing = db.prepare(`
    SELECT id FROM chats 
    WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)
  `).get(req.session.userId, to_id, to_id, req.session.userId);

  if (existing) {
    db.prepare('UPDATE chats SET last_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(text, existing.id);
  } else {
    db.prepare('INSERT INTO chats (user1, user2, last_message) VALUES (?, ?, ?)')
      .run(req.session.userId, to_id, text);
  }

  // Отправляем через сокет
  io.to('user_' + to_id).emit('new_message', {
    from_id: req.session.userId,
    text,
    time: new Date().toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' })
  });

  res.json({ success: true });
});

// Получить сообщения с пользователем
app.get('/api/messages/:userId', requireAuth, (req, res) => {
  const otherId = parseInt(req.params.userId);
  const messages = db.prepare(`
    SELECT * FROM messages 
    WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
    ORDER BY id ASC
  `).all(req.session.userId, otherId, otherId, req.session.userId);
  res.json(messages);
});

// ===== АДМИН: Выдача звёзд =====
app.post('/api/admin/give-stars', requireAuth, (req, res) => {
  const me = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.userId);
  if (!me || !me.is_admin) return res.status(403).json({ error: 'Нет прав' });

  const { user_id, amount } = req.body;
  db.prepare('UPDATE users SET stars = stars + ? WHERE id = ?').run(amount, user_id);
  
  const user = db.prepare('SELECT username, stars FROM users WHERE id = ?').get(user_id);
  res.json({ success: true, username: user.username, new_balance: user.stars });
});

// Выдать себе звёзды (только админ)
app.post('/api/admin/give-me-stars', requireAuth, (req, res) => {
  const me = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.userId);
  if (!me || !me.is_admin) return res.status(403).json({ error: 'Нет прав' });

  const { amount } = req.body;
  db.prepare('UPDATE users SET stars = stars + ? WHERE id = ?').run(amount, req.session.userId);
  const user = db.prepare('SELECT stars FROM users WHERE id = ?').get(req.session.userId);
  res.json({ success: true, stars: user.stars });
});

// ===== SOCKET.IO =====
io.on('connection', (socket) => {
  socket.on('join', (userId) => {
    socket.join('user_' + userId);
  });
});

// ===== СТАРТ =====
server.listen(PORT, () => {
  console.log('Сервер запущен на порту', PORT);
});
