import bcrypt from 'bcrypt';
import crypto from 'crypto';

// Generate random salt
export const generateSalt = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Hash password with salt using bcrypt
export const hashPassword = async (password, salt) => {
  const saltedPassword = password + salt;
  const hash = await bcrypt.hash(saltedPassword, 12);
  return hash;
};

// Verify password
export const verifyPassword = async (password, salt, hash) => {
  const saltedPassword = password + salt;
  return await bcrypt.compare(saltedPassword, hash);
};

// Create SHA-256 hash for data integrity
export const createHash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Create HMAC for message authentication
export const createHMAC = (data, key) => {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
};