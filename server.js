// server.js — intercambio por IP (con fallback), voz real del usuario

const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const { nanoid } = require('nanoid');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Ruta de datos ----------
const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(path.join(DATA_DIR, 'uploads'), { recursive: true });

// --- Archivos / uploads ---
const uploadsDir = path.join(DATA_DIR, 'uploads');
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => cb(null, `${Date.now()}-${nanoid(8)}.webm`),
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// --- Base de datos SQLite ---
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

  // Migración ligera: añadir ip_hash si no existe
  db.get(`PRAGMA table_info(secrets)`, (err) => {
    if (err) return console.error('PRAGMA error', err);
    db.all(`PRAGMA table_info(secrets)`, (e, rows) => {
      if (e) return console.error(e);
      const hasIpHash = rows.some(r => r.name === 'ip_hash');
      if (!hasIpHash) {
        db.run(`ALTER TABLE secrets ADD COLUMN ip_hash TEXT`, (e2) => {
          if (e2) console.error('ALTER TABLE ip_hash falló (puede existir ya):', e2?.message);
        });
      }
    });
  });
});

// ---------- Helpers ----------
app.set('trust proxy', true); // importante en Render para leer X-Forwarded-For

function getClientIp(req) {
  // Render/Proxies: usa el primer IP de X-Forwarded-For si existe
  const xfwd = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim();
  const ip = xfwd || req.ip || req.connection?.remoteAddress || '';
  return ip;
}
function hashIp(ip) {
  try { return crypto.createHash('sha256').update(ip).digest('hex'); }
  catch { return ''; }
}

function violatesPolicy(text = '') {
  const banned = [/porn\w*/i, /violaci[oó]n/i, /abuso\s*infantil/i, /terrorismo/i, /incesto/i];
  return banned.some((re) => re.test(text));
}

// Selecciona un secreto disponible con esta prioridad:
// 1) De OTRA IP, no reclamado, lo más antiguo.
// 2) Si no hay, de la MISMA IP pero que NO sea el id que acabamos de insertar.
//    (Esto permite que varias personas desde la misma IP intercambien sin bloqueo.)
function getAvailableSecretByIp(ipHash, excludeId) {
  return new Promise((resolve, reject) => {
    // Primero, otra IP
    db.get(
      `SELECT * FROM secrets
       WHERE claimed = 0 AND COALESCE(ip_hash,'') != ?
       ORDER BY created_at ASC
       LIMIT 1`,
      [ipHash],
      (err, row) => {
        if (err) return reject(err);
        if (row) {
          return db.run(
            `UPDATE secrets SET claimed = 1, claimed_by = ? WHERE id = ?`,
            [ipHash, row.id],
            (err2) => (err2 ? reject(err2) : resolve(row))
          );
        }
        // Fallback: misma IP, evitando el recién insertado
        db.get(
          `SELECT * FROM secrets
           WHERE claimed = 0
             AND (COALESCE(ip_hash,'') = ?)
             AND id != ?
           ORDER BY created_at ASC
           LIMIT 1`,
          [ipHash, excludeId || -1],
          (err3, row2) => {
            if (err3) return reject(err3);
            if (!row2) return resolve(null);
            db.run(
              `UPDATE secrets SET claimed = 1, claimed_by = ? WHERE id = ?`,
              [ipHash, row2.id],
              (err4) => (err4 ? reject(err4) : resolve(row2))
            );
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

// ---------- Middlewares ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

// Sesión anónima (seguimos poniéndola, aunque ya no bloquea el intercambio)
app.use((req, res, next) => {
  if (!req.cookies.sid) {
    res.cookie('sid', nanoid(16), { httpOnly: false, sameSite: 'lax' });
  }
  next();
});

// ---------- Rutas ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/secrets/text', async (req, res) => {
  try {
    const sid = req.cookies.sid;
    const ipHash = hashIp(getClientIp(req));
    let { text } = req.body || {};
    text = (text || '').toString().trim();

    if (!text || text.length < 5 || text.length > 1000) {
      return res.status(400).json({ error: 'El secreto debe tener entre 5 y 1000 caracteres.' });
    }
    if (violatesPolicy(text)) {
      return res.status(400).json({ error: 'Contenido no permitido por políticas.' });
    }

    const insertedId = await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO secrets (type, text, created_at, session_id, ip_hash)
         VALUES (?, ?, ?, ?, ?)`,
        ['text', text, Date.now(), sid, ipHash],
        function (err) { if (err) reject(err); else resolve(this.lastID); }
      );
    });

    const other = await getAvailableSecretByIp(ipHash, insertedId);
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
    const ipHash = hashIp(getClientIp(req));
    if (!req.file) return res.status(400).json({ error: 'Falta archivo de audio.' });

    const text = (req.body?.text || '').toString().trim() || null;

    const insertedId = await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO secrets (type, text, audio_path, created_at, session_id, ip_hash)
         VALUES (?, ?, ?, ?, ?, ?)`,
        ['audio', text, req.file.path, Date.now(), sid, ipHash],
        function (err) { if (err) reject(err); else resolve(this.lastID); }
      );
    });

    // Intercambio inmediato por cada envío
    const other = await getAvailableSecretByIp(ipHash, insertedId);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Pedir uno en cualquier momento (misma política por IP)
app.get('/api/secrets/one', async (req, res) => {
  try {
    const ipHash = hashIp(getClientIp(req));
    const other = await getAvailableSecretByIp(ipHash, /*excludeId*/ -1);
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
