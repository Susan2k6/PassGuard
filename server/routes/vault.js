// ─── Vault Routes: /api/vault ──────────────────────────────────────────────────
// All routes require a valid JWT (enforced by authMiddleware mounted in server.js).
const express = require('express');
const crypto = require('crypto');
const PasswordEntry = require('../models/PasswordEntry');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();
const ALGORITHM = 'aes-256-cbc';

// ── Encryption helpers ────────────────────────────────────────────────────────

/**
 * Returns the 32-byte AES key derived from the CRYPTO_KEY env var.
 * CRYPTO_KEY must be a 64-character hex string.
 */
function getKey() {
  const hex = process.env.CRYPTO_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('CRYPTO_KEY must be set to a 64-character hex string in .env');
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypts a plain-text string with AES-256-CBC.
 * Returns { encryptedPassword (hex), iv (hex) }.
 */
function encrypt(plainText) {
  const iv = crypto.randomBytes(16);                          // unique IV per entry
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  let enc = cipher.update(plainText, 'utf8', 'hex');
  enc += cipher.final('hex');
  return { encryptedPassword: enc, iv: iv.toString('hex') };
}

/**
 * Decrypts an AES-256-CBC ciphertext back to plain-text.
 */
function decrypt(encryptedPassword, ivHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  let dec = decipher.update(encryptedPassword, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

/**
 * Converts a PasswordEntry document into the shape the frontend expects.
 * The decrypted password is returned; encryptedPassword / iv are never sent.
 */
function formatEntry(doc) {
  return {
    id: doc._id.toString(),
    app: doc.app,
    username: doc.username,
    url: doc.url || '',
    password: decrypt(doc.encryptedPassword, doc.iv),
    strength: doc.strength,
    createdAt: doc.createdAt,
  };
}

// ── Apply JWT middleware to every vault route ─────────────────────────────────
router.use(authMiddleware);

// ── GET /api/vault ────────────────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const entries = await PasswordEntry
      .find({ userId: req.userId })
      .sort({ createdAt: -1 });

    res.json(entries.map(formatEntry));
  } catch (err) {
    console.error('[GET /api/vault]', err.message);
    res.status(500).json({ error: 'Failed to fetch vault entries.' });
  }
});

// ── POST /api/vault ───────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const { app, username, password, strength, url } = req.body;

    if (!app || !app.trim()) {
      return res.status(400).json({ error: 'Application name is required.' });
    }
    if (!password) {
      return res.status(400).json({ error: 'Password is required.' });
    }
    if (!['weak', 'medium', 'strong'].includes(strength)) {
      return res.status(400).json({ error: 'Strength must be weak, medium, or strong.' });
    }

    const { encryptedPassword, iv } = encrypt(password);

    const entry = await PasswordEntry.create({
      userId: req.userId,
      app: app.trim(),
      username: username ? username.trim() : '',
      url: url ? url.trim() : '',
      encryptedPassword,
      iv,
      strength,
    });

    res.status(201).json(formatEntry(entry));
  } catch (err) {
    console.error('[POST /api/vault]', err.message);
    res.status(500).json({ error: 'Failed to save password.' });
  }
});

// ── PUT /api/vault/:id ────────────────────────────────────────────────────────
router.put('/:id', async (req, res) => {
  try {
    const entry = await PasswordEntry.findOne({
      _id: req.params.id,
      userId: req.userId,         // ownership check
    });

    if (!entry) {
      return res.status(404).json({ error: 'Entry not found.' });
    }

    const { app, username, password, strength, url } = req.body;

    if (app !== undefined) entry.app = app.trim();
    if (username !== undefined) entry.username = username.trim();
    if (url !== undefined) entry.url = url.trim();
    if (strength !== undefined) entry.strength = strength;

    // Re-encrypt only when a new password value is provided
    if (password) {
      const { encryptedPassword, iv } = encrypt(password);
      entry.encryptedPassword = encryptedPassword;
      entry.iv = iv;
    }

    await entry.save();
    res.json(formatEntry(entry));
  } catch (err) {
    console.error('[PUT /api/vault/:id]', err.message);
    res.status(500).json({ error: 'Failed to update entry.' });
  }
});

// ── DELETE /api/vault/:id ─────────────────────────────────────────────────────
router.delete('/:id', async (req, res) => {
  try {
    const result = await PasswordEntry.findOneAndDelete({
      _id: req.params.id,
      userId: req.userId,         // ownership check
    });

    if (!result) {
      return res.status(404).json({ error: 'Entry not found.' });
    }

    res.json({ message: 'Password deleted successfully.' });
  } catch (err) {
    console.error('[DELETE /api/vault/:id]', err.message);
    res.status(500).json({ error: 'Failed to delete entry.' });
  }
});

module.exports = router;
