// server.js — Intercambio 1×1 por envío, sin bloquear por misma IP/sesión.
// Regla: tras insertar, intenta devolver otro secreto distinto.
// 1) Prioriza de OTRA sesión (más “justo”).
// 2) Si no hay, permite de la MISMA sesión (pero nunca el recién insertado).

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
});

// ---------- Middlewares ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Estáticos
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

// Sesión anónima simple por cookie (no bloquea el intercambio)
app.use((req, res, next) => {
  if (!req.cookies.sid) {
    res.cookie('sid', nanoid(16), { httpOnly: false, sameSite: 'lax' });
  }
  next();
});

// ---------- Utilidades ----------
function violatesPolicy(text = '') {
  const banned = [/porn\w*/i, /violaci[oó]n/i, /abuso\s*infantil/i, /terrorismo/i, /incesto/i];
  return banned.some((re) => re.test(text));
}

// Intenta obtener un secreto no reclamado distinto al recien insertado.
// Paso 1: otra sesión, FIFO. Paso 2: misma sesión (evitando el recién insertado), FIFO.
function getExchangeSecret(excludeSessionId, excludeId) {
  return new Promise((resolve, reject) => {
    // 1) Otra sesión
    db.get(
      `SELECT * FROM secrets
       WHERE claimed = 0
         AND id != ?
         AND session_id != ?
       ORDER BY created_at ASC
       LIMIT 1`,
      [excludeId, excludeSessionId],
      (err, row) => {
        if (err) return reject(err);
        if (row) {
          return db.run(
            `UPDATE secrets SET claimed = 1, claimed_by = ? WHERE id = ?`,
            [excludeSessionId, row.id],
            (err2) => (err2 ? reject(err2) : resolve(row))
          );
        }
        // 2) Misma sesión (evita devolver el mismo recién insertado)
        db.get(
          `SELECT * FROM secrets
           WHERE claimed = 0
             AND id != ?
           ORDER BY created_at ASC
           LIMIT 1`,
          [excludeId],
          (err3, row2) => {
            if (err3) return reject(err3);
            if (!row2) return resolve(null);
            db.run(
              `UPDATE secrets SET claimed = 1, claimed_by = ? WHERE id = ?`,
              [excludeSessionId, row2.id],
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

// ---------- Rutas ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Crear secreto de texto y devolver otro a cambio (si hay)
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

    const insertedId = await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO secrets (type, text, created_at, session_id)
         VALUES (?, ?, ?, ?)`,
        ['text', text, Date.now(), sid],
        function (err) { if (err) reject(err); else resolve(this.lastID); }
      );
    });

    const other = await getExchangeSecret(sid, insertedId);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Crear secreto de audio (voz real) y devolver otro a cambio (si hay)
app.post('/api/secrets/audio', upload.single('audio'), async (req, res) => {
  try {
    const sid = req.cookies.sid;
    if (!req.file) return res.status(400).json({ error: 'Falta archivo de audio.' });
    const text = (req.body?.text || '').toString().trim() || null; // opcionalmente guardamos texto asociado

    const insertedId = await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO secrets (type, text, audio_path, created_at, session_id)
         VALUES (?, ?, ?, ?, ?)`,
        ['audio', text, req.file.path, Date.now(), sid],
        function (err) { if (err) reject(err); else resolve(this.lastID); }
      );
    });

    const other = await getExchangeSecret(sid, insertedId);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Pedir uno en cualquier momento (misma política)
app.get('/api/secrets/one', async (req, res) => {
  try {
    const sid = req.cookies.sid || 'anon';
    const other = await getExchangeSecret(sid, -1);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Contador de secretos disponibles
app.get('/api/stats', (req, res) => {
  const sid = req.cookies.sid || 'anon';

  // disponibles para ti (de otra sesión)
  const qOther = `SELECT COUNT(*) AS c FROM secrets WHERE claimed = 0 AND session_id != ?`;
  // disponibles totales sin reclamar
  const qTotal = `SELECT COUNT(*) AS c FROM secrets WHERE claimed = 0`;

  db.get(qOther, [sid], (e1, rowOther) => {
    if (e1) {
      console.error(e1);
      return res.status(500).json({ error: 'stats other failed' });
    }
    db.get(qTotal, [], (e2, rowTotal) => {
      if (e2) {
        console.error(e2);
        return res.status(500).json({ error: 'stats total failed' });
      }
      res.json({
        available_for_you: rowOther?.c ?? 0,
        available_total: rowTotal?.c ?? 0
      });
    });
  });
});

app.listen(PORT, () => {
  console.log(`✅ Servidor en http://localhost:${PORT}`);
  console.log(`📁 DATA_DIR: ${DATA_DIR}`);
  console.log(`💾 DB: ${dbPath}`);
  console.log(`📂 Uploads: ${uploadsDir}`);
});

