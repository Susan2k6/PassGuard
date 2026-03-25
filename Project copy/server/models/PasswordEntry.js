const mongoose = require('mongoose');

const passwordEntrySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  app: {
    type: String,
    required: [true, 'Application name is required.'],
    trim: true,
  },
  username: {
    type: String,
    default: '',
    trim: true,
  },
  url: {
    type: String,
    default: '',
    trim: true,
  },
  // AES-256-CBC ciphertext (hex-encoded). Plain-text is never stored.
  encryptedPassword: {
    type: String,
    required: true,
  },
  // AES initialisation vector (hex-encoded, 16 bytes → 32 hex chars)
  iv: {
    type: String,
    required: true,
  },
  strength: {
    type: String,
    enum: ['weak', 'medium', 'strong'],
    default: 'medium',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('PasswordEntry', passwordEntrySchema);
