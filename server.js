// server.js (con soporte de DATA_DIR para DB y uploads)

const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const { nanoid } = require('nanoid');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Ruta de datos configurable ----------
const DATA_DIR = process.env.DATA_DIR || __dirname;
// Asegura carpetas en DATA_DIR
fs.mkdirSync(path.join(DATA_DIR, 'uploads'), { recursive: true });

// --- Archivos / uploads ---
const uploadsDir = path.join(DATA_DIR, 'uploads');
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => cb(null, `${Date.now()}-${nanoid(8)}.webm`),
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// --- Base de datos SQLite en DATA_DIR ---
const dbPath = path.join(DATA_DIR, 'secrets.db');
const db = new sqlite3.Database(dbPath);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,               -- 'text' | 'audio'
    text TEXT,
    audio_path TEXT,
    created_at INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    claimed INTEGER DEFAULT 0,
    claimed_by TEXT
  )`);
});

// ---------- Middlewares ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Servir uploads desde DATA_DIR y el frontend estático desde /public
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

// Sesión anónima simple por cookie
app.use((req, res, next) => {
  if (!req.cookies.sid) {
    res.cookie('sid', nanoid(16), { httpOnly: false, sameSite: 'lax' });
  }
  next();
});

// ---------- Moderación muy básica (placeholder) ----------
const banned = [
  /porn\w*/i, /violaci[oó]n/i, /abuso\s*infantil/i, /terrorismo/i, /incesto/i
];
function violatesPolicy(text = '') {
  return banned.some((re) => re.test(text));
}

// ---------- Utilidades ----------
function getAvailableSecret(sid) {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT * FROM secrets
       WHERE claimed = 0 AND session_id != ?
       ORDER BY RANDOM() LIMIT 1`,
      [sid],
      (err, row) => {
        if (err) return reject(err);
        if (!row) return resolve(null);
        db.run(
          `UPDATE secrets SET claimed = 1, claimed_by = ? WHERE id = ?`,
          [sid, row.id],
          (err2) => {
            if (err2) return reject(err2);
            resolve(row);
          }
        );
      }
    );
  });
}

function formatSecret(row, req) {
  if (!row) return null;
  if (row.type === 'audio') {
    return { type: 'audio', url: `${req.protocol}://${req.get('host')}/uploads/${path.basename(row.audio_path)}` };
  }
  return { type: 'text', text: row.text };
}

// ---------- Rutas ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/secrets/text', async (req, res) => {
  try {
    const sid = req.cookies.sid;
    let { text } = req.body || {};
    text = (text || '').toString().trim();

    if (!text || text.length < 5 || text.length > 1000) {
      return res.status(400).json({ error: 'El secreto debe tener entre 5 y 1000 caracteres.' });
    }
    if (violatesPolicy(text)) {
      return res.status(400).json({ error: 'Contenido no permitido por políticas.' });
    }

    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO secrets (type, text, created_at, session_id) VALUES (?, ?, ?, ?)`,
        ['text', text, Date.now(), sid],
        function (err) { if (err) reject(err); else resolve(); }
      );
    });

    const other = await getAvailableSecret(sid);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

app.post('/api/secrets/audio', upload.single('audio'), async (req, res) => {
  try {
    const sid = req.cookies.sid;
    if (!req.file) return res.status(400).json({ error: 'Falta archivo de audio.' });

    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO secrets (type, audio_path, created_at, session_id) VALUES (?, ?, ?, ?)`,
        ['audio', req.file.path, Date.now(), sid],
        function (err) { if (err) reject(err); else resolve(); }
      );
    });

    const other = await getAvailableSecret(sid);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Intentar conseguir un secreto en cualquier momento
app.get('/api/secrets/one', async (req, res) => {
  try {
    const sid = req.cookies.sid;
    const other = await getAvailableSecret(sid);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Servidor en http://localhost:${PORT}`);
  console.log(`📁 DATA_DIR: ${DATA_DIR}`);
  console.log(`💾 DB: ${dbPath}`);
  console.log(`📂 Uploads: ${uploadsDir}`);
});
