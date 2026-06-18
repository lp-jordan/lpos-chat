'use strict';

const crypto = require('crypto');

// Produce "<saltHex>:<hashHex>" using scrypt with a 16-byte random salt.
function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, 64);
  return salt.toString('hex') + ':' + hash.toString('hex');
}

// Verify a plaintext password against a stored "<saltHex>:<hashHex>" value.
// Returns false on any malformed input; never throws.
function verifyPassword(plain, stored) {
  try {
    if (typeof stored !== 'string' || stored.indexOf(':') === -1) return false;
    const [saltHex, hashHex] = stored.split(':');
    if (!saltHex || !hashHex) return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    if (salt.length !== 16 || expected.length !== 64) return false;
    const actual = crypto.scryptSync(String(plain), salt, 64);
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { hashPassword, verifyPassword, randomToken };
