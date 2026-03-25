// ─── PassGuard Mailer ─────────────────────────────────────────────────────────
// Auto-selects transport:
//   • Gmail  — when EMAIL_USER and EMAIL_PASS are set in .env
//   • Ethereal — otherwise (logs preview URL to console, no real email sent)
const nodemailer = require('nodemailer');

let _transporter = null;
let _from = '';

async function getTransporter() {
    if (_transporter) return _transporter;

    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        // ── Real Gmail transport ──────────────────────────────────────────────────
        _transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,   // use a Gmail App Password
            },
        });
        _from = `"PassGuard" <${process.env.EMAIL_USER}>`;
        console.log('📧  Mailer: using Gmail SMTP');
    } else {
        // ── Ethereal test transport (no real email) ───────────────────────────────
        const testAccount = await nodemailer.createTestAccount();
        _transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false,
            auth: { user: testAccount.user, pass: testAccount.pass },
        });
        _from = '"PassGuard" <passguard@ethereal.email>';
        console.log('📧  Mailer: using Ethereal (test mode) — OTP preview links will be logged below.');
    }

    return _transporter;
}

/**
 * Sends a vault OTP email to the given address.
 * @param {string} toEmail
 * @param {string} otp        6-digit code
 */
async function sendOtpEmail(toEmail, otp) {
    const transport = await getTransporter();

    const info = await transport.sendMail({
        from: _from,
        to: toEmail,
        subject: '🔐 PassGuard Vault OTP',
        html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;
                  border-radius:16px;border:1px solid #e5e7eb;background:#fff;">
        <h2 style="color:#6366f1;margin-bottom:8px;">PassGuard Vault Access</h2>
        <p style="color:#374151;">Use the code below to unlock your password vault.
           It expires in <strong>10 minutes</strong>.</p>
        <div style="font-size:2.4rem;font-weight:800;letter-spacing:.35em;
                    color:#0f172a;background:#f1f5f9;border-radius:12px;
                    padding:20px;text-align:center;margin:24px 0;">
          ${otp}
        </div>
        <p style="color:#6b7280;font-size:0.85rem;">
          If you did not request this, someone may be trying to access your vault.
          You can safely ignore this email.
        </p>
      </div>
    `,
    });

    // In Ethereal mode, log the preview link so the developer can inspect it
    const previewUrl = nodemailer.getTestMessageUrl(info);
    if (previewUrl) {
        console.log(`\n📬  OTP email preview → ${previewUrl}\n`);
    }
}

module.exports = { sendOtpEmail };
