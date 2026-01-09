const crypto = require('crypto');
const sodium = require('sodium-native');
const { CRYPTO_CONSTANTS, X3DH_PARAMS, DOUBLE_RATCHET_PARAMS } = require('../../../shared/cryptoConstants');

/**
 * Encryption Service
 * Handles server-side cryptographic operations for key management
 * Note: Server does NOT decrypt message content (E2EE)
 */

class EncryptionService {
  constructor() {
    this.keyCache = new Map();
    this.cacheTTL = 5 * 60 * 1000; // 5 minutes
    
    // Initialize key sizes
    this.KEY_SIZES = CRYPTO_CONSTANTS.KEY_SIZES;
  }

  /**
   * Generate X25519 key pair for user
   */
  generateKeyPair() {
    try {
      const publicKey = Buffer.alloc(this.KEY_SIZES.X25519_PUBLIC);
      const privateKey = Buffer.alloc(this.KEY_SIZES.X25519_PRIVATE);
      
      sodium.crypto_box_keypair(publicKey, privateKey);
      
      return {
        publicKey: publicKey.toString('base64'),
        privateKey: privateKey.toString('base64'),
        algorithm: 'X25519',
        generatedAt: new Date().toISOString()
      };
    } catch (error) {
      console.error('Key pair generation error:', error);
      throw new Error('Failed to generate key pair');
    }
  }

  /**
   * Generate Ed25519 key pair for authentication
   */
  generateAuthKeyPair() {
    try {
      const publicKey = Buffer.alloc(this.KEY_SIZES.ED25519_PUBLIC);
      const privateKey = Buffer.alloc(this.KEY_SIZES.ED25519_PRIVATE);
      
      sodium.crypto_sign_keypair(publicKey, privateKey);
      
      return {
        publicKey: publicKey.toString('base64'),
        privateKey: privateKey.toString('base64'),
        algorithm: 'Ed25519',
        generatedAt: new Date().toISOString()
      };
    } catch (error) {
      console.error('Auth key pair generation error:', error);
      throw new Error('Failed to generate authentication key pair');
    }
  }

  /**
   * Generate pre-keys for X3DH protocol
   */
  generatePreKeys(count = X3DH_PARAMS.INITIAL_MESSAGE_KEYS) {
    try {
      const preKeys = [];
      
      for (let i = 0; i < count; i++) {
        const keyPair = this.generateKeyPair();
        preKeys.push({
          id: i,
          publicKey: keyPair.publicKey,
          privateKey: keyPair.privateKey,
          algorithm: keyPair.algorithm,
          generatedAt: keyPair.generatedAt
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
      const keyPair = this.generateKeyPair();
      
      // Sign the pre-key with identity key
      const signature = this.signData(
        Buffer.from(keyPair.publicKey, 'base64'),
        Buffer.from(identityPrivateKey, 'base64')
      );
      
      return {
        keyId: Date.now(), // Use timestamp as ID
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        signature: signature.toString('base64'),
        algorithm: 'X25519',
        signedWith: 'Ed25519',
        generatedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
      };
    } catch (error) {
      console.error('Signed pre-key generation error:', error);
      throw new Error('Failed to generate signed pre-key');
    }
  }

  /**
   * Generate one-time pre-keys
   */
  generateOneTimePreKeys(count = 100) {
    try {
      const keys = [];
      
      for (let i = 0; i < count; i++) {
        const keyPair = this.generateKeyPair();
        keys.push({
          id: i,
          publicKey: keyPair.publicKey,
          privateKey: keyPair.privateKey,
          algorithm: 'X25519',
          generatedAt: keyPair.generatedAt,
          used: false
        });
      }
      
      return keys;
    } catch (error) {
      console.error('One-time pre-key generation error:', error);
      throw new Error('Failed to generate one-time pre-keys');
    }
  }

  /**
   * Sign data with private key
   */
  signData(data, privateKey) {
    try {
      const signature = Buffer.alloc(64); // Ed25519 signature size
      sodium.crypto_sign_detached(signature, data, privateKey);
      return signature;
    } catch (error) {
      console.error('Signing error:', error);
      throw new Error('Failed to sign data');
    }
  }

  /**
   * Verify signature with public key
   */
  verifySignature(data, signature, publicKey) {
    try {
      return sodium.crypto_sign_verify_detached(
        Buffer.from(signature, 'base64'),
        Buffer.from(data, 'base64'),
        Buffer.from(publicKey, 'base64')
      );
    } catch (error) {
      console.error('Signature verification error:', error);
      return false;
    }
  }

  /**
   * Generate X3DH shared secret (client-side operation, but server helps)
   */
  calculateX3DHSharedSecret({
    identityKeyA,
    ephemeralKeyA,
    signedPreKeyB,
    preKeyB,
    oneTimeKeyB = null
  }) {
    try {
      // Convert keys to buffers
      const identityKeyABuf = Buffer.from(identityKeyA, 'base64');
      const ephemeralKeyABuf = Buffer.from(ephemeralKeyA, 'base64');
      const signedPreKeyBBuf = Buffer.from(signedPreKeyB.publicKey, 'base64');
      const preKeyBBuf = Buffer.from(preKeyB, 'base64');
      
      // DH1: A's identity key with B's signed pre-key
      const dh1 = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY);
      sodium.crypto_scalarmult(dh1, identityKeyABuf, signedPreKeyBBuf);
      
      // DH2: A's ephemeral key with B's identity key
      // Note: Need B's identity key - this is simplified
      const dh2 = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY);
      
      // DH3: A's ephemeral key with B's signed pre-key
      const dh3 = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY);
      sodium.crypto_scalarmult(dh3, ephemeralKeyABuf, signedPreKeyBBuf);
      
      // DH4: A's ephemeral key with B's one-time key (if available)
      let dh4 = null;
      if (oneTimeKeyB) {
        const oneTimeKeyBBuf = Buffer.from(oneTimeKeyB, 'base64');
        dh4 = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY);
        sodium.crypto_scalarmult(dh4, ephemeralKeyABuf, oneTimeKeyBBuf);
      }
      
      // Combine DH outputs
      const dhOutputs = [dh1, dh2, dh3];
      if (dh4) dhOutputs.push(dh4);
      
      const combined = Buffer.concat(dhOutputs);
      
      // Derive shared secret using HKDF
      const sharedSecret = this.deriveHKDF(
        combined,
        X3DH_PARAMS.INFO_STRING,
        this.KEY_SIZES.SYMMETRIC_KEY
      );
      
      return {
        sharedSecret: sharedSecret.toString('base64'),
        usedOneTimeKey: !!oneTimeKeyB,
        algorithm: 'X25519-X3DH',
        derivedAt: new Date().toISOString()
      };
    } catch (error) {
      console.error('X3DH calculation error:', error);
      throw new Error('Failed to calculate X3DH shared secret');
    }
  }

  /**
   * Derive symmetric keys using HKDF
   */
  deriveHKDF(inputKeyMaterial, info, outputLength) {
    try {
      // Extract phase
      const salt = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY); // Zero salt
      const prk = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY);
      sodium.crypto_generichash(prk, inputKeyMaterial, salt);
      
      // Expand phase
      const infoBuffer = Buffer.from(info, 'utf8');
      const t = Buffer.concat([
        infoBuffer,
        Buffer.from([0x01]) // Single byte counter
      ]);
      
      const okm = Buffer.alloc(outputLength);
      sodium.crypto_generichash(okm, t, prk);
      
      return okm;
    } catch (error) {
      console.error('HKDF derivation error:', error);
      throw new Error('Failed to derive keys');
    }
  }

  /**
   * Generate Double Ratchet state (client-side, but server stores public info)
   */
  initializeDoubleRatchet({
    rootKey,
    sendingChainKey,
    receivingChainKey,
    sendingRatchetKey,
    receivingRatchetKey
  }) {
    try {
      const state = {
        rootKey,
        sendingChain: {
          chainKey: sendingChainKey,
          ratchetKey: sendingRatchetKey,
          messageNumber: 0,
          skippedMessageKeys: new Map()
        },
        receivingChain: {
          chainKey: receivingChainKey,
          ratchetKey: receivingRatchetKey,
          messageNumber: 0,
          skippedMessageKeys: new Map()
        },
        previousSendingChainLength: 0,
        previousReceivingChainLength: 0,
        initializedAt: new Date().toISOString(),
        lastRatchetTime: Date.now()
      };
      
      return state;
    } catch (error) {
      console.error('Double Ratchet initialization error:', error);
      throw new Error('Failed to initialize Double Ratchet');
    }
  }

  /**
   * Perform Double Ratchet step
   */
  performRatchetStep(state, isSending = true) {
    try {
      const chain = isSending ? state.sendingChain : state.receivingChain;
      
      // Generate new ratchet key pair
      const newRatchetKeyPair = this.generateKeyPair();
      
      // Calculate new root key and chain key
      const dhResult = this.calculateDH(
        Buffer.from(chain.ratchetKey, 'base64'),
        Buffer.from(newRatchetKeyPair.privateKey, 'base64')
      );
      
      const newRootKey = this.deriveHKDF(
        dhResult,
        DOUBLE_RATCHET_PARAMS.ROOT_KEY_INFO,
        this.KEY_SIZES.SYMMETRIC_KEY
      );
      
      const newChainKey = this.deriveHKDF(
        Buffer.concat([dhResult, Buffer.from([0x01])]),
        DOUBLE_RATCHET_PARAMS.CHAIN_KEY_INFO,
        this.KEY_SIZES.SYMMETRIC_KEY
      );
      
      // Update state
      if (isSending) {
        state.sendingChain = {
          chainKey: newChainKey.toString('base64'),
          ratchetKey: newRatchetKeyPair.publicKey,
          messageNumber: 0,
          skippedMessageKeys: new Map()
        };
      } else {
        state.receivingChain = {
          chainKey: newChainKey.toString('base64'),
          ratchetKey: newRatchetKeyPair.publicKey,
          messageNumber: 0,
          skippedMessageKeys: new Map()
        };
      }
      
      state.rootKey = newRootKey.toString('base64');
      state.lastRatchetTime = Date.now();
      
      return state;
    } catch (error) {
      console.error('Ratchet step error:', error);
      throw new Error('Failed to perform ratchet step');
    }
  }

  /**
   * Calculate Diffie-Hellman shared secret
   */
  calculateDH(publicKey, privateKey) {
    try {
      const sharedSecret = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY);
      sodium.crypto_scalarmult(sharedSecret, privateKey, publicKey);
      return sharedSecret;
    } catch (error) {
      console.error('DH calculation error:', error);
      throw new Error('Failed to calculate DH shared secret');
    }
  }

  /**
   * Generate message key from chain key
   */
  generateMessageKey(chainKey) {
    try {
      const messageKey = this.deriveHKDF(
        Buffer.from(chainKey, 'base64'),
        DOUBLE_RATCHET_PARAMS.MESSAGE_KEY_INFO,
        this.KEY_SIZES.SYMMETRIC_KEY
      );
      
      return messageKey.toString('base64');
    } catch (error) {
      console.error('Message key generation error:', error);
      throw new Error('Failed to generate message key');
    }
  }

  /**
   * Advance chain key
   */
  advanceChainKey(chainKey) {
    try {
      const hash = Buffer.alloc(this.KEY_SIZES.SYMMETRIC_KEY);
      sodium.crypto_generichash(
        hash,
        Buffer.from(chainKey, 'base64')
      );
      
      return hash.toString('base64');
    } catch (error) {
      console.error('Chain key advance error:', error);
      throw new Error('Failed to advance chain key');
    }
  }

  /**
   * Generate secure random bytes
   */
  generateRandomBytes(length) {
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
   * Generate nonce for encryption
   */
  generateNonce() {
    try {
      const nonce = Buffer.alloc(this.KEY_SIZES.NONCE_SIZE);
      sodium.randombytes_buf(nonce);
      return nonce.toString('base64');
    } catch (error) {
      console.error('Nonce generation error:', error);
      throw new Error('Failed to generate nonce');
    }
  }

  /**
   * Hash data for integrity checking
   */
  hashData(data, algorithm = 'sha256') {
    try {
      const hash = Buffer.alloc(32); // SHA-256 output size
      
      if (algorithm === 'sha256') {
        sodium.crypto_hash_sha256(hash, Buffer.from(data));
      } else if (algorithm === 'blake2b') {
        sodium.crypto_generichash(hash, Buffer.from(data));
      } else {
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
      }
      
      return hash.toString('hex');
    } catch (error) {
      console.error('Hashing error:', error);
      throw new Error('Failed to hash data');
    }
  }

  /**
   * Generate invitation key
   */
  generateInvitationKey() {
    try {
      const key = this.generateRandomBytes(32);
      return key.toString('base64');
    } catch (error) {
      console.error('Invitation key generation error:', error);
      throw new Error('Failed to generate invitation key');
    }
  }

  /**
   * Generate session key
   */
  generateSessionKey() {
    try {
      const key = this.generateRandomBytes(64); // 512-bit session key
      return key.toString('base64');
    } catch (error) {
      console.error('Session key generation error:', error);
      throw new Error('Failed to generate session key');
    }
  }

  /**
   * Generate ephemeral key for forward secrecy
   */
  generateEphemeralKey() {
    try {
      const keyPair = this.generateKeyPair();
      return {
        ...keyPair,
        ephemeral: true,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
      };
    } catch (error) {
      console.error('Ephemeral key generation error:', error);
      throw new Error('Failed to generate ephemeral key');
    }
  }

  /**
   * Validate key format and parameters
   */
  validateKey(key, expectedType = 'public') {
    const errors = [];
    
    if (!key || typeof key !== 'string') {
      errors.push('Key must be a string');
      return errors;
    }
    
    // Check base64 format
    if (!/^[A-Za-z0-9+/=]+$/.test(key)) {
      errors.push('Key must be base64 encoded');
      return errors;
    }
    
    // Check key length
    const keyBytes = Buffer.from(key, 'base64');
    
    switch (expectedType) {
      case 'public':
        if (keyBytes.length !== this.KEY_SIZES.X25519_PUBLIC && 
            keyBytes.length !== this.KEY_SIZES.ED25519_PUBLIC) {
          errors.push(`Invalid public key length: ${keyBytes.length} bytes`);
        }
        break;
      
      case 'private':
        if (keyBytes.length !== this.KEY_SIZES.X25519_PRIVATE && 
            keyBytes.length !== this.KEY_SIZES.ED25519_PRIVATE) {
          errors.push(`Invalid private key length: ${keyBytes.length} bytes`);
        }
        break;
      
      case 'symmetric':
        if (keyBytes.length !== this.KEY_SIZES.SYMMETRIC_KEY) {
          errors.push(`Invalid symmetric key length: ${keyBytes.length} bytes`);
        }
        break;
    }
    
    return errors.length === 0 ? null : errors;
  }

  /**
   * Clean up expired keys from cache
   */
  cleanupKeyCache() {
    const now = Date.now();
    
    for (const [key, entry] of this.keyCache.entries()) {
      if (now - entry.timestamp > this.cacheTTL) {
        this.keyCache.delete(key);
      }
    }
  }

  /**
   * Get service statistics
   */
  getStats() {
    return {
      keyCacheSize: this.keyCache.size,
      cacheTTL: this.cacheTTL,
      keySizes: this.KEY_SIZES,
      supportedAlgorithms: ['X25519', 'Ed25519', 'X3DH', 'Double-Ratchet', 'AES-GCM', 'XSalsa20-Poly1305'],
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = new EncryptionService();