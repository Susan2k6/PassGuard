// ─── Auth Routes: /api/auth ────────────────────────────────────────────────────
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/authMiddleware');
const { sendOtpEmail } = require('../utils/mailer');

const router = express.Router();

// ── Helpers ───────────────────────────────────────────────────────────────────

function issueToken(userId) {
  return jwt.sign({ userId: userId.toString() }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── POST /api/auth/register ───────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // ── Validate input ──
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are all required.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    // ── Check for existing account ──
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    // ── Hash password & create user ──
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ name: name.trim(), email, password: hashed });

    const token = issueToken(user._id);
    return res.status(201).json({ token, name: user.name, email: user.email });

  } catch (err) {
    console.error('[POST /api/auth/register]', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      // Generic message to prevent user enumeration
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = issueToken(user._id);
    return res.json({ token, name: user.name, email: user.email });

  } catch (err) {
    console.error('[POST /api/auth/login]', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ── POST /api/auth/send-otp ───────────────────────────────────────────────────
// Requires JWT. Generates a 6-digit OTP, stores bcrypt hash + 10-min expiry,
// and emails it to the authenticated user.
router.post('/send-otp', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Rate-limit: block resend if the last OTP is less than 60 seconds old.
    // otpExpiry is set to now+10min at send time, so "sent <60s ago" means
    // otpExpiry is still more than 9m 0s away (i.e. > Date.now() + 9*60*1000).
    const RESEND_WINDOW_MS = 60 * 1000;
    const OTP_TTL_MS = 10 * 60 * 1000;
    if (user.otpExpiry) {
      const sentAt = user.otpExpiry.getTime() - OTP_TTL_MS;
      const secondsAgo = (Date.now() - sentAt) / 1000;
      if (secondsAgo < 60) {
        const wait = Math.ceil(60 - secondsAgo);
        return res.status(429).json({
          error: `Please wait ${wait}s before requesting another OTP.`,
        });
      }
    }

    const otp = generateOtp();
    const hash = await bcrypt.hash(otp, 10);
    const expiry = new Date(Date.now() + OTP_TTL_MS); // 10 minutes

    user.otpHash = hash;
    user.otpExpiry = expiry;
    user.otpAttempts = 0;   // reset failed-attempt counter on fresh send
    await user.save();

    await sendOtpEmail(user.email, otp);

    // Mask email for response: su***@gmail.com
    const [localPart, domain] = user.email.split('@');
    const masked = localPart.slice(0, 2) + '***@' + domain;

    return res.json({ message: `OTP sent to ${masked}`, maskedEmail: masked });
  } catch (err) {
    console.error('[POST /api/auth/send-otp]', err.message);
    return res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

// ── POST /api/auth/verify-otp ─────────────────────────────────────────────────
// Requires JWT + the 6-digit OTP. Returns { verified: true } on success.
// Brute-force protection: OTP is invalidated after 5 consecutive wrong attempts.
const MAX_OTP_ATTEMPTS = 5;

router.post('/verify-otp', authMiddleware, async (req, res) => {
  try {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ error: 'OTP is required.' });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    if (!user.otpHash || !user.otpExpiry) {
      return res.status(400).json({ error: 'No OTP requested. Please request one first.' });
    }

    if (new Date() > user.otpExpiry) {
      // Clear stale OTP
      user.otpHash = null; user.otpExpiry = null; user.otpAttempts = 0;
      await user.save();
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }

    // Brute-force guard
    if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
      user.otpHash = null; user.otpExpiry = null; user.otpAttempts = 0;
      await user.save();
      return res.status(429).json({
        error: 'Too many incorrect attempts. Please request a new OTP.',
      });
    }

    const match = await bcrypt.compare(String(otp), user.otpHash);
    if (!match) {
      user.otpAttempts += 1;
      await user.save();
      const remaining = MAX_OTP_ATTEMPTS - user.otpAttempts;
      return res.status(401).json({
        error: remaining > 0
          ? `Incorrect OTP. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
          : 'Too many incorrect attempts. Please request a new OTP.',
      });
    }

    // ✅ Success — clear OTP so it can't be reused
    user.otpHash = null; user.otpExpiry = null; user.otpAttempts = 0;
    await user.save();

    return res.json({ verified: true });
  } catch (err) {
    console.error('[POST /api/auth/verify-otp]', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

module.exports = router;

