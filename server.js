// server.js — Persistencia sin disco (Render Free) con PostgreSQL (Neon/Supabase/Railway)
// - Guarda textos y AUDIOS (voz real) dentro de Postgres (BYTEA)
// - Intercambio permanente: cada secreto insertado se guarda y sigue disponible para todos (no se marca como consumido)
// - Endpoints: /api/secrets/text, /api/secrets/audio, /api/secrets/one
//              /api/audio/:id, /api/stats, /api/health

const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { nanoid } = require('nanoid');
const { Pool } = require('pg');
const url = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

/* =======================
   DB: conexión a Postgres
   ======================= */
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL no está definida. Ve a Render → Environment y añádela con la cadena de Neon (termina en ?sslmode=require).');
  process.exit(1);
}

// si estás detrás de Render/proxy para cookies secure
app.set('trust proxy', 1);

try {
  const parsed = new url.URL(DATABASE_URL);
  console.log(`🔌 Conectando a Postgres en host: ${parsed.hostname}`);
} catch {
  console.warn('⚠️ DATABASE_URL no parece válida. Asegúrate de pegar la conexión tal cual de Neon.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Crear esquema si no existe (sin columnas claimed)
async function ensureSchema() {
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
  console.log('✅ Esquema verificado/creado en Postgres.');
}

ensureSchema().catch((e) => {
  console.error('❌ Error ensureSchema:', e);
  process.exit(1);
});

/* ===============
   Middlewares
   =============== */
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// sesión anónima ANTES de estáticos y rutas
app.use((req, res, next) => {
  let sid = req.cookies.sid;
  if (!sid) {
    sid = nanoid(16);
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    req.cookies.sid = sid; // disponible ya en esta request
    res.cookie('sid', sid, { httpOnly: false, sameSite: 'lax', secure: isSecure });
  }
  next();
});

app.use(express.static('public')); // sirve tu index.html

// Multer en memoria (sin disco)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10 MB
});

/* ===============
   Utilidades
   =============== */
function violatesPolicy(text = '') {
  const banned = [/abuso\s*infantil/i, /violaci[oó]n/i, /incesto/i, /terrorismo/i];
  return banned.some((re) => re.test(text));
}

// Selecciona un secreto distinto al recién insertado (y de otra sesión) — no lo marca, permanece disponible
async function getExchangeSecret(excludeSessionId, excludeId) {
  const q = `
    SELECT *
    FROM secrets
    WHERE id <> $1
      AND session_id <> $2
    ORDER BY created_at ASC
    LIMIT 1
  `;
  const r = await pool.query(q, [excludeId, excludeSessionId]);
  return r.rows[0] || null;
}

function formatSecret(row, req) {
  if (!row) return null;
  if (row.type === 'audio') {
    return { type: 'audio', url: `${req.protocol}://${req.get('host')}/api/audio/${row.id}` };
  }
  return { type: 'text', text: row.text_content };
}

/* ===============
   Rutas
   =============== */
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

    const ins = await pool.query(
      `INSERT INTO secrets (type, text_content, session_id)
       VALUES ('text', $1, $2)
       RETURNING id`,
      [text, sid]
    );
    const insertedId = Number(ins.rows[0].id);

    const other = await getExchangeSecret(sid, insertedId);
    if (!other) return res.status(204).end(); // no hay otro aún
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error('❌ /api/secrets/text error:', e);
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

    const ins = await pool.query(
      `INSERT INTO secrets (type, text_content, audio_data, session_id)
       VALUES ('audio', $1, $2, $3)
       RETURNING id`,
      [text, buffer, sid]
    );
    const insertedId = Number(ins.rows[0].id);

    const other = await getExchangeSecret(sid, insertedId);
    if (!other) return res.status(204).end();
    res.json(formatSecret(other, req));
  } catch (e) {
    console.error('❌ /api/secrets/audio error:', e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Obtener uno cualquiera (de otra sesión), sin consumirlo
app.get('/api/secrets/one', async (req, res) => {
  try {
    const sid = req.cookies.sid || 'anon';
    const q = `
      SELECT *
      FROM secrets
      WHERE session_id <> $1
      ORDER BY created_at ASC
      LIMIT 1
    `;
    const r = await pool.query(q, [sid]);
    if (!r.rows.length) return res.status(204).end();
    res.json(formatSecret(r.rows[0], req));
  } catch (e) {
    console.error('❌ /api/secrets/one error:', e);
    res.status(500).json({ error: 'Error de servidor' });
  }
});

// Servir audio desde la base (BYTEA → audio/webm)
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
    console.error('❌ /api/audio/:id error:', e);
    res.status(500).send('server error');
  }
});

// Stats (modelo permanente)
app.get('/api/stats', async (req, res) => {
  try {
    const sid = req.cookies.sid || 'anon';

    // Total de secretos guardados (siempre disponibles)
    const rTotal = await pool.query(
      `SELECT COUNT(*)::int AS c FROM secrets`
    );

    // Secretos “disponibles para ti” = todos los que no son tuyos
    const rOther = await pool.query(
      `SELECT COUNT(*)::int AS c FROM secrets WHERE session_id <> $1`,
      [sid]
    );

    res.json({
      available_for_you: rOther.rows[0].c,
      available_total: rTotal.rows[0].c
    });
  } catch (e) {
    console.error('❌ /api/stats error:', e);
    res.status(500).json({ error: 'stats failed' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Servidor en http://localhost:${PORT}`);
});
