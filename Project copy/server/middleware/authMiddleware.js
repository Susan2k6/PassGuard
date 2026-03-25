// ─── JWT Auth Middleware ──────────────────────────────────────────────────────
const jwt = require('jsonwebtoken');

/**
 * Verifies the Bearer token in the Authorization header.
 * On success, attaches req.userId (MongoDB ObjectId string) and calls next().
 * On failure, responds 401.
 */
module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. No token provided.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token. Please log in again.' });
  }
};
