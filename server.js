// server.js — Modelo permanente con exclusión robusta del propio autor
// - Guarda textos y AUDIOS en Postgres (BYTEA)
// - Al entregar, NO “consume” secretos: siguen disponibles para todos
// - Nunca devuelve secretos del mismo autor (cookie + IP/UA hash)
// - Endpoints: /api/secrets/text, /api/secrets/audio, /api/secrets/one
//              /api/audio/:id, /api/stats, /api/health

const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const { nanoid } = require('nanoid');
const { Pool } = require('pg');
const url = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

// === DB ===
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('❌ Falta DATABASE_URL. Añádela en Render → Environment (cadena de Neon con ?sslmode=require).');
  process.exit(1);
}

app.set('trust proxy', 1); // cookies "secure" detrás de Render

try {
  const parsed = new url.URL(DATABASE_URL);
  console.log(`🔌 Postgres host: ${parsed.hostname}`);
} catch {
  console.warn('⚠️ DATABASE_URL no parece válida.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// === Esquema (auto-migración ligera) ===
async function ensureSchema() {
  // Crea tabla si no existe
  await pool.query(`
    CREATE TABLE IF NOT EXISTS secrets (
      id           BIGSERIAL PRIMARY KEY,
      type         TEXT NOT NULL,        -- 'text' | 'audio'
      text_content TEXT,
      audio_data   BYTEA,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      session_id   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets (created_at);
    CREATE INDEX IF NOT EXISTS idx_secrets_session_id ON secrets (session_id);
  `);

  // Añade columna author_hash si no existe (para exclusión por autor)
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'secrets' AND column_name = 'author_hash'
      ) THEN
        ALTER TABLE secrets ADD COLUMN author_hash TEXT;
        CREATE INDEX IF NOT EXISTS idx_secrets_author_hash ON secrets (author_hash);
      END IF;
    END$$;
  `);

  console.log('✅ Esquema verificado / migrado.');
}

ensureSchema().catch((e) => {
  console.error('❌ ensureSchema:', e);
  process.exit(1);
});

// === Middlewares ===
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Sesión anónima persistente (1 año) ANTES de estáticos y rutas
app.use((req, res, next) => {
  let sid = req.cookies.sid;
  if (!sid) {
    sid = nanoid(16);
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    req.cookies.sid = sid; // disponible ya
    res.cookie('sid', sid, {
      httpOnly: false,
      sameSite: 'lax',
      secure: isSecure,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 año
    });
  }
  next();
});

app.use(express.static('public'));

// Multer en memoria
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// === Utilidades ===
function violatesPolicy(text = '') {
  const banned = [/abuso\s*infantil/i, /violaci[oó]n/i, /incesto/i, /terrorismo/i];
  return banned.some((re) => re.test(text));
}

// Huella anónima del autor: IP + UA + salt del servidor
function authorFingerprint(req) {
  const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString();
  const ua = (req.headers['user-agent'] || '').toString();
  const salt = process.env.AUTHOR_SALT || 'default_salt_change_me';
  const raw = `${ip}|${ua}|${salt}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// Busca un secreto de OTRA persona (excluye id propio, autor propio y muy recientes)
async function getExchangeSecret({ excludeSessionId, excludeId, authorHash }) {
  const q = `
    SELECT *
    FROM secrets
    WHERE id <> $1
      AND session_id <> $2
      AND (author_hash IS DISTINCT FROM $3)            -- excluye mismos autor_hash
      AND created_at < NOW() - INTERVAL '3 seconds'    -- evita carreras
    ORDER BY created_at ASC
    LIMIT 1
  `;
  const r = await pool.query(q, [excludeId, excludeSessionId, authorHash]);
  return r.rows[0] || null;
}

function formatSecret(row, req) {
  if (!row) return null;
  if (row.type === 'audio') {
    return { type: 'audio', url: `${req.protocol}://${req.get('host')}/api/audio/${row.id}` };
  }
  return { type: 'text', text: row.text_content };
}

// === Rutas ===
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Texto
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

    const author = authorFingerprint(req);

    const ins = await pool.query(
      `INSERT INTO secrets (type, text_content, session_id, author_hash)
       VALUES ('text', $1, $2, $3)
       RETURNING id`,
      [text, sid, author]
    );
    const insertedId = Number(ins.rows[0].id);

    const other = await getExchangeSecret({
      excludeSessionId: sid,
      excludeId: insertedId,
      authorHash: author
    });
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error('❌ /api/secrets/text:', e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Audio
app.post('/api/secrets/audio', upload.single('audio'), async (req, res) => {
  try {
    const sid = req.cookies.sid;
    if (!req.file) return res.status(400).json({ error: 'Falta archivo de audio.' });

    const text = (req.body?.text || '').toString().trim() || null;
    const buffer = req.file.buffer;
    const author = authorFingerprint(req);

    const ins = await pool.query(
      `INSERT INTO secrets (type, text_content, audio_data, session_id, author_hash)
       VALUES ('audio', $1, $2, $3, $4)
       RETURNING id`,
      [text, buffer, sid, author]
    );
    const insertedId = Number(ins.rows[0].id);

    const other = await getExchangeSecret({
      excludeSessionId: sid,
      excludeId: insertedId,
      authorHash: author
    });
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error('❌ /api/secrets/audio:', e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Obtener uno (no consume; excluye autor propio)
app.get('/api/secrets/one', async (req, res) => {
  try {
    const sid = req.cookies.sid || 'anon';
    const author = authorFingerprint(req);
    const q = `
      SELECT *
      FROM secrets
      WHERE session_id <> $1
        AND (author_hash IS DISTINCT FROM $2)
        AND created_at < NOW() - INTERVAL '3 seconds'
      ORDER BY created_at ASC
      LIMIT 1
    `;
    const r = await pool.query(q, [sid, author]);
    if (!r.rows.length) return res.status(204).end();
    res.json(formatSecret(r.rows[0], req));
  } catch (e) {
    console.error('❌ /api/secrets/one:', e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Servir audio
app.get('/api/audio/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('bad id');
    const r = await pool.query(
      `SELECT audio_data FROM secrets WHERE id = $1 AND type = 'audio'`,
      [id]
    );
    if (!r.rows.length || !r.rows[0].audio_data) return res.status(404).send('not found');
    const buf = r.rows[0].audio_data;
    res.setHeader('Content-Type', 'audio/webm');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.send(buf);
  } catch (e) {
    console.error('❌ /api/audio/:id:', e);
    res.status(500).send('server error');
  }
});

// Stats (ahora: totales y ajenos a ti; ya no hay "claimed")
app.get('/api/stats', async (req, res) => {
  try {
    const sid = req.cookies.sid || 'anon';
    const author = authorFingerprint(req);

    const rTotal = await pool.query(`SELECT COUNT(*)::int AS c FROM secrets`);
    const rOther = await pool.query(
      `SELECT COUNT(*)::int AS c
       FROM secrets
       WHERE session_id <> $1
         AND (author_hash IS DISTINCT FROM $2)`,
      [sid, author]
    );

    res.json({
      available_for_you: rOther.rows[0].c,
      available_total: rTotal.rows[0].c
    });
  } catch (e) {
    console.error('❌ /api/stats:', e);
    res.status(500).json({ error: 'stats failed' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Servidor en http://localhost:${PORT}`);
});
