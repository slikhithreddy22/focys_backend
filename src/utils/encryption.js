import 'dotenv/config';
import crypto from 'crypto';

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

const getKey = () => {
  const envKey = process.env.ENCRYPTION_KEY;

  // Preferred: 64 hex chars => 32 bytes key
  if (envKey && /^[0-9a-fA-F]{64}$/.test(envKey)) {
    return Buffer.from(envKey, 'hex');
  }

  // Accept other strings, but derive a stable 32-byte key from them
  if (envKey && envKey.length > 0) {
    return crypto.createHash('sha256').update(envKey, 'utf8').digest();
  }

  // Fallback (dev only): derive from JWT_SECRET so the key is stable across restarts.
  // This prevents decrypt failures for previously-stored messages when ENCRYPTION_KEY is missing.
  if (process.env.JWT_SECRET) {
    console.warn('⚠️  ENCRYPTION_KEY not set. Deriving key from JWT_SECRET (development fallback).');
    return crypto.createHash('sha256').update(process.env.JWT_SECRET, 'utf8').digest();
  }

  throw new Error('Missing ENCRYPTION_KEY (and JWT_SECRET fallback unavailable).');
};

// Legacy derivation (older versions treated hex ENCRYPTION_KEY as UTF-8 and truncated to 32 bytes)
const getLegacyUtf8KeyIfAny = () => {
  const envKey = process.env.ENCRYPTION_KEY;
  if (!envKey) return null;

  const buf = Buffer.from(envKey, 'utf8');
  if (buf.length >= 32) return buf.subarray(0, 32);

  // pad with zeros if needed
  const padded = Buffer.alloc(32);
  buf.copy(padded);
  return padded;
};

const KEY = getKey();
const LEGACY_KEY = getLegacyUtf8KeyIfAny();

// Generate key pair for RSA (asymmetric encryption)
export const generateKeyPair = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  
  return { publicKey, privateKey };
};

// Encrypt data using AES-256-CBC
export const encrypt = (text) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    encryptedData: encrypted,
    iv: iv.toString('hex')
  };
};

// Decrypt data using AES-256-CBC
export const decrypt = (encryptedData, ivHex) => {
  const iv = Buffer.from(ivHex, 'hex');
  if (iv.length !== IV_LENGTH) {
    throw new Error(`Invalid IV length: expected ${IV_LENGTH}, got ${iv.length}`);
  }

  const tryDecryptWithKey = (key) => {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  };

  try {
    return tryDecryptWithKey(KEY);
  } catch (err) {
    // Backward compatibility: try legacy key derivation used by older versions
    if (err?.code === 'ERR_OSSL_BAD_DECRYPT' && LEGACY_KEY) {
      try {
        return tryDecryptWithKey(LEGACY_KEY);
      } catch {
        // fall through to clearer error below
      }
    }

    const msg = err?.code === 'ERR_OSSL_BAD_DECRYPT'
      ? 'Decryption failed (bad decrypt). This message was encrypted with a different key (older run or older key derivation).'
      : `Decryption failed: ${err?.message || err}`;
    const e = new Error(msg);
    e.cause = err;
    throw e;
  }
};

// Hybrid encryption: Encrypt with AES, then encrypt AES key with RSA
export const hybridEncrypt = (data, publicKey) => {
  // Generate random AES key for this session
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // Encrypt data with AES
  const cipher = crypto.createCipheriv(ALGORITHM, aesKey, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Encrypt AES key with RSA public key
  const encryptedKey = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    aesKey
  );
  
  return {
    encryptedData: encrypted,
    encryptedKey: encryptedKey.toString('base64'),
    iv: iv.toString('hex')
  };
};

// Hybrid decryption
export const hybridDecrypt = (encryptedData, encryptedKey, ivHex, privateKey) => {
  // Decrypt AES key with RSA private key
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(encryptedKey, 'base64')
  );
  
  // Decrypt data with AES key
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, aesKey, iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};