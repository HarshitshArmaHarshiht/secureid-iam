const { authenticator } = require("otplib");
const QRCode = require("qrcode");

const ISSUER = "SecureID";

/** Generate a fresh base32 TOTP secret for a user. */
function generateSecret() {
  return authenticator.generateSecret();
}

/** Build the otpauth:// URI an authenticator app scans from the QR code. */
function buildOtpAuthUri(accountLabel, secret) {
  return authenticator.keyuri(accountLabel, ISSUER, secret);
}

/** Render the otpauth URI as a QR code data: URL (PNG, base64). */
async function generateQrDataUrl(otpauthUri) {
  return QRCode.toDataURL(otpauthUri, {
    width: 260,
    margin: 1,
    color: { dark: "#1e3a8a", light: "#ffffff" },
  });
}

function verifyToken(token, secret) {
  try {
    return authenticator.check(token, secret);
  } catch {
    return false;
  }
}

module.exports = { generateSecret, buildOtpAuthUri, generateQrDataUrl, verifyToken, ISSUER };
