import crypto from 'crypto';
import { createHash } from './hashing.js';

// Create digital signature using private key
export const createDigitalSignature = (data, privateKey) => {
  // First, create hash of the data
  const hash = createHash(data);
  
  // Sign the hash with private key
  const sign = crypto.createSign('SHA256');
  sign.update(hash);
  sign.end();
  
  const signature = sign.sign(privateKey, 'base64');
  return { signature, hash };
};

// Verify digital signature using public key
export const verifyDigitalSignature = (data, signature, publicKey, originalHash) => {
  // Create hash of the data
  const hash = createHash(data);
  
  // Check if hash matches original hash (data integrity)
  if (hash !== originalHash) {
    return false;
  }
  
  // Verify signature
  const verify = crypto.createVerify('SHA256');
  verify.update(hash);
  verify.end();
  
  return verify.verify(publicKey, signature, 'base64');
};

// Simple signature for demonstration (using HMAC)
export const createSimpleSignature = (data, secret) => {
  const hash = createHash(data);
  const signature = crypto.createHmac('sha256', secret)
    .update(hash)
    .digest('base64');
  
  return { signature, hash };
};

// Verify simple signature
export const verifySimpleSignature = (data, signature, secret, originalHash) => {
  const hash = createHash(data);
  
  if (hash !== originalHash) {
    return false;
  }
  
  const expectedSignature = crypto.createHmac('sha256', secret)
    .update(hash)
    .digest('base64');
  
  return signature === expectedSignature;
};