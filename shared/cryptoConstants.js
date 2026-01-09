// Shared cryptographic constants and protocols

const CRYPTO_CONSTANTS = {
  // Algorithm identifiers
  ENCRYPTION_VERSION: '1.0.0',
  
  // Key types and sizes
  KEY_TYPES: {
    AUTH: 'ed25519',      // For authentication
    ECDH: 'x25519',       // For key exchange
    SYMMETRIC: 'xsalsa20-poly1305' // For message encryption
  },
  
  // Key sizes (in bytes)
  KEY_SIZES: {
    ED25519_PUBLIC: 32,
    ED25519_PRIVATE: 64,
    X25519_PUBLIC: 32,
    X25519_PRIVATE: 32,
    SYMMETRIC_KEY: 32,
    NONCE_SIZE: 24,
    AUTH_TAG_SIZE: 16
  },
  
  // Protocol constants
  PROTOCOLS: {
    X3DH: 'x3dh',
    DOUBLE_RATCHET: 'double-ratchet',
    PRE_KEYS: 100 // Number of pre-keys to generate
  },
  
  // Message types
  MESSAGE_TYPES: {
    TEXT: 'text',
    SYSTEM: 'system',
    KEY_EXCHANGE: 'key_exchange',
    PRESENCE: 'presence',
    INVITATION: 'invitation'
  },
  
  // Hash algorithms
  HASH_ALGORITHMS: {
    USERNAME: 'sha256',
    SESSION: 'sha512',
    INTEGRITY: 'blake2b'
  },
  
  // Encoding
  ENCODING: {
    BASE64: 'base64',
    HEX: 'hex',
    UTF8: 'utf8'
  },
  
  // Performance/security tradeoffs
  LIMITS: {
    MAX_MESSAGE_SIZE: 10 * 1024, // 10KB
    MAX_KEYS_PER_USER: 1000,
    KEY_ROTATION_INTERVAL: 24 * 60 * 60 * 1000, // 24 hours
    SESSION_TIMEOUT: 60 * 60 * 1000 // 1 hour
  }
};

// X3DH protocol parameters
const X3DH_PARAMS = {
  INITIAL_MESSAGE_KEYS: 1000,
  MAX_SKIP: 1000,
  MAX_MESSAGE_KEYS: 2000,
  INFO_STRING: 'SecureAnonymousChat-X3DH-v1'
};

// Double Ratchet protocol parameters
const DOUBLE_RATCHET_PARAMS = {
  CHAIN_KEY_INFO: 'SecureAnonymousChat-ChainKey',
  MESSAGE_KEY_INFO: 'SecureAnonymousChat-MessageKey',
  ROOT_KEY_INFO: 'SecureAnonymousChat-RootKey',
  MAX_SKIP: 1000
};

module.exports = {
  CRYPTO_CONSTANTS,
  X3DH_PARAMS,
  DOUBLE_RATCHET_PARAMS
};