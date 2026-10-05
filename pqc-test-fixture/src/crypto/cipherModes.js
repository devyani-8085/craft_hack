/**
 * Deliberately exercises 3 distinct AES cipher modes via Node's crypto.createCipheriv
 * so the JS AST analyzer (scanner/js_analyzer.py::_check_cipheriv) populates the
 * `mode` field with three different values, parsed from the openssl algo string.
 * Expected Mode values: CBC, ECB, GCM (one per function below).
 * Expected Algorithm = AES in all three; Expected key size = 256/128 per string.
 */
const crypto = require("crypto");

function encryptLegacyCbc(key, iv, data) {
  // Expected Mode = CBC
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function encryptWeakEcb(key, data) {
  // Expected Mode = ECB
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function encryptModernGcm(key, iv, data) {
  // Expected Mode = GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

module.exports = { encryptLegacyCbc, encryptWeakEcb, encryptModernGcm };
