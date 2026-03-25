// ─── PassGuard API Server ──────────────────────────────────────────────────────
const express  = require('express');
const mongoose = require('mongoose');
const cors     = require('cors');
const dotenv   = require('dotenv');
const path     = require('path');

// Load .env from the project root (same directory as package.json)
dotenv.config({ path: path.join(__dirname, '..', '.env') });

// ── Validate required env vars before anything else ───────────────────────────
const REQUIRED = ['MONGO_URI', 'JWT_SECRET', 'CRYPTO_KEY'];
const missing  = REQUIRED.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`❌  Missing required env vars: ${missing.join(', ')}`);
  console.error('    Copy .env.template to .env and fill in the values.');
  process.exit(1);
}

const app = express();

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Serve the static frontend (HTML, CSS, JS) from the project root
app.use(express.static(path.join(__dirname, '..')));

// ── API Routes ────────────────────────────────────────────────────────────────
app.use('/api/auth',  require('./routes/auth'));
app.use('/api/vault', require('./routes/vault'));

// ── Fallback: serve index.html for any unknown route ─────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// ── Connect to MongoDB then start listening ───────────────────────────────────
const PORT = process.env.PORT || 5001;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅  MongoDB connected');
    app.listen(PORT, () => {
      console.log(`🚀  Server running  →  http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌  MongoDB connection error:', err.message);
    process.exit(1);
  });
