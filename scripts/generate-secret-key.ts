import * as crypto from 'crypto';

/**
 * Generate a cryptographically secure random key
 * @param length Length of the key in bytes (default: 32)
 * @returns Base64-encoded random key
 */
function generateSecretKey(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64');
}

// Generate and display a secure key
const secretKey = generateSecretKey();
console.log('\nGenerated Encryption Secret Key:');
console.log('--------------------------------');
console.log(secretKey);
console.log('--------------------------------');
console.log('\nAdd this key to your .env file as ENCRYPTION_SECRET_KEY');
console.log('Make sure to use different keys for development and production environments.');
console.log('NEVER commit your production keys to version control!\n');
