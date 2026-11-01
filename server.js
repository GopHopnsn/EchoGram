const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// База данных
const db = new Database('messenger.db');

// Создаём таблицы, если их ещё нет
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Создаём первого админа, если его нет
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password, balance, is_admin) VALUES (?, ?, ?, ?)').run('admin', hash, 10000, 1);
  console.log('Создан админ: логин admin / пароль admin123');
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  secret: 'super-secret-key-change-me-later',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 дней
}));

// Проверка, залогинен ли пользователь
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  next();
}

// === Страницы ===
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// === Регистрация ===
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password || username.length < 3 || password.length < 4) {
    return res.status(400).send('Логин минимум 3 символа, пароль минимум 4');
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hash);
    
    req.session.userId = result.lastInsertRowid;
    req.session.username = username;
    res.redirect('/');
  } catch (err) {
    res.status(400).send('Такой логин уже занят');
  }
});

// === Вход ===
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).send('Неверный логин или пароль');
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.redirect('/');
});

// === Выход ===
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// === Информация о текущем пользователе ===
app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare('SELECT id, username, balance, is_admin FROM users WHERE id = ?').get(req.session.userId);
  res.json(user);
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
