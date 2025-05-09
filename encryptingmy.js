const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Variable to store the encryption key
let ENCRYPTION_KEY = crypto.randomBytes(32); // 256 bit key
const IV_LENGTH = 16;

// Store the key in a file for reuse across server restarts
const KEY_FILE = path.join(__dirname, 'keys', 'encryption_key.bin');

// Initialize encryption key
function initializeEncryptionKey() {
  try {
    // Create directory if it doesn't exist
    const dir = path.dirname(KEY_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    // Check if key file exists, otherwise create it
    if (!fs.existsSync(KEY_FILE)) {
      fs.writeFileSync(KEY_FILE, ENCRYPTION_KEY);
      console.log('Generated new encryption key');
    } else {
      // Read existing key
      ENCRYPTION_KEY = fs.readFileSync(KEY_FILE);
      console.log('Loaded existing encryption key');
    }
  } catch (err) {
    console.error('Error initializing encryption key:', err);
    // Continue with the generated key as fallback
  }
}

// Encrypt data
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Decrypt data
function decrypt(text) {
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = Buffer.from(textParts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
}

module.exports = {
  initializeEncryptionKey,
  encrypt,
  decrypt
};