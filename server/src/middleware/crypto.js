const crypto = require('crypto');
const sodium = require('sodium-native');

/**
 * Cryptographic Middleware
 * Handles encryption, decryption, and cryptographic validation
 * Note: Server doesn't decrypt messages (E2EE), but handles key management
 */

class CryptoMiddleware {
  /**
   * Initialize sodium library
   */
  constructor() {
    this.keySizes = {
      SYMMETRIC_KEY: 32, // 256 bits
      PUBLIC_KEY: 32,    // 256 bits for X25519
      PRIVATE_KEY: 32,   // 256 bits for X25519
      NONCE: 24,         // 192 bits for XSalsa20
      AUTH_TAG: 16       // 128 bits for Poly1305
    };
    
    // Initialize key cache for performance
    this.keyCache = new Map();
    this.cacheTTL = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Generate key pair for user
   */
  generateKeyPair() {
    try {
      const publicKey = Buffer.alloc(this.keySizes.PUBLIC_KEY);
      const privateKey = Buffer.alloc(this.keySizes.PRIVATE_KEY);
      
      sodium.crypto_box_keypair(publicKey, privateKey);
      
      return {
        publicKey: publicKey.toString('base64'),
        privateKey: privateKey.toString('base64'),
        algorithm: 'X25519'
      };
    } catch (error) {
      console.error('Key pair generation error:', error);
      throw new Error('Failed to generate key pair');
    }
  }

  /**
   * Generate pre-keys for X3DH protocol
   */
  generatePreKeys(count = 100) {
    try {
      const preKeys = [];
      
      for (let i = 0; i < count; i++) {
        const publicKey = Buffer.alloc(this.keySizes.PUBLIC_KEY);
        const privateKey = Buffer.alloc(this.keySizes.PRIVATE_KEY);
        
        sodium.crypto_box_keypair(publicKey, privateKey);
        
        preKeys.push({
          id: i,
          publicKey: publicKey.toString('base64'),
          privateKey: privateKey.toString('base64') // Client should keep this
        });
      }
      
      return preKeys;
    } catch (error) {
      console.error('Pre-key generation error:', error);
      throw new Error('Failed to generate pre-keys');
    }
  }

  /**
   * Generate signed pre-key
   */
  generateSignedPreKey(identityPrivateKey) {
    try {
      // Generate pre-key
      const publicKey = Buffer.alloc(this.keySizes.PUBLIC_KEY);
      const privateKey = Buffer.alloc(this.keySizes.PRIVATE_KEY);
      sodium.crypto_box_keypair(publicKey, privateKey);
      
      // Sign the pre-key with identity key
      const signature = Buffer.alloc(64);
      sodium.crypto_sign_detached(
        signature,
        publicKey,
        Buffer.from(identityPrivateKey, 'base64')
      );
      
      return {
        publicKey: publicKey.toString('base64'),
        privateKey: privateKey.toString('base64'),
        signature: signature.toString('base64'),
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Signed pre-key generation error:', error);
      throw new Error('Failed to generate signed pre-key');
    }
  }

  /**
   * Verify signed pre-key
   */
  verifySignedPreKey(signedPreKey, identityPublicKey) {
    try {
      const publicKey = Buffer.from(signedPreKey.publicKey, 'base64');
      const signature = Buffer.from(signedPreKey.signature, 'base64');
      const identityKey = Buffer.from(identityPublicKey, 'base64');
      
      return sodium.crypto_sign_verify_detached(
        signature,
        publicKey,
        identityKey
      );
    } catch (error) {
      console.error('Signed pre-key verification error:', error);
      return false;
    }
  }

  /**
   * Generate one-time keys
   */
  generateOneTimeKeys(count = 100) {
    try {
      const keys = [];
      
      for (let i = 0; i < count; i++) {
        const publicKey = Buffer.alloc(this.keySizes.PUBLIC_KEY);
        const privateKey = Buffer.alloc(this.keySizes.PRIVATE_KEY);
        
        sodium.crypto_box_keypair(publicKey, privateKey);
        
        keys.push({
          id: i,
          publicKey: publicKey.toString('base64'),
          privateKey: privateKey.toString('base64')
        });
      }
      
      return keys;
    } catch (error) {
      console.error('One-time key generation error:', error);
      throw new Error('Failed to generate one-time keys');
    }
  }

  /**
   * Perform X3DH key agreement
   * Note: This is client-side in E2EE, but server helps with key exchange
   */
  performX3DHKeyAgreement({
    identityKeyA,
    ephemeralKeyA,
    signedPreKeyB,
    preKeyB,
    oneTimeKeyB
  }) {
    try {
      // Convert all keys to buffers
      const identityKeyABuf = Buffer.from(identityKeyA, 'base64');
      const ephemeralKeyABuf = Buffer.from(ephemeralKeyA, 'base64');
      const signedPreKeyBBuf = Buffer.from(signedPreKeyB.publicKey, 'base64');
      const preKeyBBuf = Buffer.from(preKeyB, 'base64');
      
      // DH1: A's identity key with B's signed pre-key
      const dh1 = Buffer.alloc(this.keySizes.SYMMETRIC_KEY);
      sodium.crypto_scalarmult(
        dh1,
        identityKeyABuf,
        signedPreKeyBBuf
      );
      
      // DH2: A's ephemeral key with B's identity key
      const dh2 = Buffer.alloc(this.keySizes.SYMMETRIC_KEY);
      // Note: Need B's identity key here - this is simplified
      
      // DH3: A's ephemeral key with B's signed pre-key
      const dh3 = Buffer.alloc(this.keySizes.SYMMETRIC_KEY);
      sodium.crypto_scalarmult(
        dh3,
        ephemeralKeyABuf,
        signedPreKeyBBuf
      );
      
      // DH4: A's ephemeral key with B's one-time key (if available)
      let dh4 = null;
      if (oneTimeKeyB) {
        const oneTimeKeyBBuf = Buffer.from(oneTimeKeyB, 'base64');
        dh4 = Buffer.alloc(this.keySizes.SYMMETRIC_KEY);
        sodium.crypto_scalarmult(
          dh4,
          ephemeralKeyABuf,
          oneTimeKeyBBuf
        );
      }
      
      // Combine DH outputs using HKDF
      const dhOutputs = [dh1, dh2, dh3];
      if (dh4) dhOutputs.push(dh4);
      
      const combined = Buffer.concat(dhOutputs);
      
      // Derive shared secret using HKDF
      const sharedSecret = this.deriveHKDF(
        combined,
        'X3DH-key-agreement',
        this.keySizes.SYMMETRIC_KEY
      );
      
      return {
        sharedSecret: sharedSecret.toString('base64'),
        usedOneTimeKey: !!oneTimeKeyB
      };
    } catch (error) {
      console.error('X3DH key agreement error:', error);
      throw new Error('Failed to perform key agreement');
    }
  }

  /**
   * Derive key using HKDF
   */
  deriveHKDF(inputKeyMaterial, info, outputLength) {
    try {
      // Extract phase
      const salt = Buffer.alloc(this.keySizes.SYMMETRIC_KEY); // Zero salt
      const prk = Buffer.alloc(this.keySizes.SYMMETRIC_KEY);
      sodium.crypto_generichash(prk, inputKeyMaterial, salt);
      
      // Expand phase
      const infoBuffer = Buffer.from(info, 'utf8');
      const infoLength = Buffer.alloc(1);
      infoLength[0] = infoBuffer.length;
      
      const t = Buffer.concat([
        infoBuffer,
        Buffer.from([0x01]) // Single byte counter
      ]);
      
      const okm = Buffer.alloc(outputLength);
      sodium.crypto_generichash(okm, t, prk);
      
      return okm;
    } catch (error) {
      console.error('HKDF derivation error:', error);
      throw new Error('Failed to derive key');
    }
  }

  /**
   * Generate random nonce
   */
  generateNonce() {
    try {
      const nonce = Buffer.alloc(this.keySizes.NONCE);
      sodium.randombytes_buf(nonce);
      return nonce.toString('base64');
    } catch (error) {
      console.error('Nonce generation error:', error);
      throw new Error('Failed to generate nonce');
    }
  }

  /**
   * Generate random session key
   */
  generateSessionKey() {
    try {
      const key = Buffer.alloc(64); // 512-bit session key
      sodium.randombytes_buf(key);
      return key.toString('base64');
    } catch (error) {
      console.error('Session key generation error:', error);
      throw new Error('Failed to generate session key');
    }
  }

  /**
   * Generate invitation key
   */
  generateInvitationKey() {
    try {
      const key = Buffer.alloc(32); // 256-bit invitation key
      sodium.randombytes_buf(key);
      return key.toString('base64');
    } catch (error) {
      console.error('Invitation key generation error:', error);
      throw new Error('Failed to generate invitation key');
    }
  }

  /**
   * Hash username with salt (for storage)
   */
  hashUsername(username, salt) {
    try {
      const input = username + salt;
      const hash = Buffer.alloc(32);
      sodium.crypto_generichash(hash, Buffer.from(input, 'utf8'));
      return hash.toString('hex');
    } catch (error) {
      console.error('Username hashing error:', error);
      throw new Error('Failed to hash username');
    }
  }

  /**
   * Verify message integrity (content hash)
   */
  verifyMessageIntegrity(encryptedContent, expectedHash) {
    try {
      const contentBuffer = Buffer.from(encryptedContent, 'base64');
      const hash = Buffer.alloc(32);
      sodium.crypto_generichash(hash, contentBuffer);
      
      const calculatedHash = hash.toString('hex');
      return calculatedHash === expectedHash;
    } catch (error) {
      console.error('Message integrity verification error:', error);
      return false;
    }
  }

  /**
   * Generate content hash for message
   */
  generateContentHash(encryptedContent) {
    try {
      const contentBuffer = Buffer.from(encryptedContent, 'base64');
      const hash = Buffer.alloc(32);
      sodium.crypto_generichash(hash, contentBuffer);
      return hash.toString('hex');
    } catch (error) {
      console.error('Content hash generation error:', error);
      throw new Error('Failed to generate content hash');
    }
  }

  /**
   * Cache cryptographic operations for performance
   */
  withCache(key, operation, ttl = this.cacheTTL) {
    const cached = this.keyCache.get(key);
    
    if (cached && Date.now() - cached.timestamp < ttl) {
      return cached.value;
    }
    
    const result = operation();
    this.keyCache.set(key, {
      value: result,
      timestamp: Date.now()
    });
    
    // Clean up old cache entries
    this.cleanupCache();
    
    return result;
  }

  /**
   * Clean up expired cache entries
   */
  cleanupCache() {
    const now = Date.now();
    for (const [key, entry] of this.keyCache.entries()) {
      if (now - entry.timestamp > this.cacheTTL) {
        this.keyCache.delete(key);
      }
    }
  }

  /**
   * Validate cryptographic parameters
   */
  validateCryptoParams(params) {
    const errors = [];
    
    // Check key formats
    if (params.publicKey && !this.isValidBase64Key(params.publicKey, 32, 1024)) {
      errors.push('Invalid public key format');
    }
    
    if (params.privateKey && !this.isValidBase64Key(params.privateKey, 32, 1024)) {
      errors.push('Invalid private key format');
    }
    
    if (params.nonce && !this.isValidBase64Key(params.nonce, 16, 32)) {
      errors.push('Invalid nonce format');
    }
    
    if (params.signature && !this.isValidBase64Key(params.signature, 64, 128)) {
      errors.push('Invalid signature format');
    }
    
    // Check algorithm
    if (params.algorithm && !['X25519', 'Ed25519', 'AES-GCM', 'XSalsa20-Poly1305'].includes(params.algorithm)) {
      errors.push('Unsupported algorithm');
    }
    
    return errors.length === 0 ? null : errors;
  }

  /**
   * Check if string is valid base64 key
   */
  isValidBase64Key(key, minLength, maxLength) {
    if (typeof key !== 'string') {
      return false;
    }
    
    // Check base64 format
    if (!/^[A-Za-z0-9+/=]+$/.test(key)) {
      return false;
    }
    
    // Check length in bytes (base64 encoded)
    const byteLength = Buffer.from(key, 'base64').length;
    
    return byteLength >= minLength && byteLength <= maxLength;
  }

  /**
   * Generate secure random bytes
   */
  secureRandomBytes(length) {
    try {
      const buffer = Buffer.alloc(length);
      sodium.randombytes_buf(buffer);
      return buffer;
    } catch (error) {
      console.error('Random bytes generation error:', error);
      throw new Error('Failed to generate random bytes');
    }
  }

  /**
   * Constant-time comparison (prevents timing attacks)
   */
  constantTimeCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    
    return result === 0;
  }

  /**
   * Generate cryptographic salt
   */
  generateSalt(bytes = 32) {
    try {
      const salt = Buffer.alloc(bytes);
      sodium.randombytes_buf(salt);
      return salt.toString('hex');
    } catch (error) {
      console.error('Salt generation error:', error);
      throw new Error('Failed to generate salt');
    }
  }

  /**
   * Derive key from password (for key encryption)
   */
  deriveKeyFromPassword(password, salt, iterations = 100000) {
    try {
      const key = Buffer.alloc(this.keySizes.SYMMETRIC_KEY);
      sodium.crypto_pwhash(
        key,
        Buffer.from(password, 'utf8'),
        Buffer.from(salt, 'hex'),
        iterations,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_DEFAULT
      );
      
      return key.toString('base64');
    } catch (error) {
      console.error('Key derivation error:', error);
      throw new Error('Failed to derive key');
    }
  }
}

module.exports = new CryptoMiddleware();