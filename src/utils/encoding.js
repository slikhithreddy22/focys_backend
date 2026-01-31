import QRCode from 'qrcode';

// Base64 encoding
export const encodeBase64 = (data) => {
  return Buffer.from(data).toString('base64');
};

// Base64 decoding
export const decodeBase64 = (encodedData) => {
  return Buffer.from(encodedData, 'base64').toString('utf8');
};

// Generate QR code
export const generateQRCode = async (data) => {
  try {
    const qrCodeDataURL = await QRCode.toDataURL(data, {
      errorCorrectionLevel: 'H',
      type: 'image/png',
      quality: 0.92,
      margin: 1,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    });
    return qrCodeDataURL;
  } catch (error) {
    console.error('Error generating QR code:', error);
    throw error;
  }
};

// URL-safe encoding
export const urlSafeEncode = (data) => {
  return Buffer.from(data)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

// URL-safe decoding
export const urlSafeDecode = (encodedData) => {
  const base64 = encodedData
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  const padding = '='.repeat((4 - base64.length % 4) % 4);
  return Buffer.from(base64 + padding, 'base64').toString('utf8');
};

// Hex encoding
export const encodeHex = (data) => {
  return Buffer.from(data).toString('hex');
};

// Hex decoding
export const decodeHex = (hexData) => {
  return Buffer.from(hexData, 'hex').toString('utf8');
};