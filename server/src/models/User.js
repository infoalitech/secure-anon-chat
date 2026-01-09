const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { query } = require('../config/database');

class User {
  /**
   * User model for anonymous chat system
   * Note: No PII is stored - only cryptographic identifiers
   */

  /**
   * Create a new anonymous user
   * @param {string} username - Plaintext username (hashed before storage)
   * @param {string} publicKey - User's public key for encryption
   * @param {boolean} isEphemeral - Whether this is a temporary user
   * @returns {Promise<Object>} Created user object
   */
  static async create(username, publicKey, isEphemeral = true) {
    try {
      // Generate unique salts for username hashing
      const usernameSalt = crypto.randomBytes(32).toString('hex');
      const hashedUsername = this.hashUsername(username, usernameSalt);
      
      // Generate identity key
      const identityKey = crypto.randomBytes(32).toString('hex');
      
      const userId = uuidv4();
      const now = new Date();
      
      const result = await query(
        `INSERT INTO users (
          user_id, username_hash, username_salt, public_key, 
          identity_key, is_ephemeral, created_at, last_seen
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *`,
        [
          userId,
          hashedUsername,
          usernameSalt,
          publicKey,
          identityKey,
          isEphemeral,
          now,
          now
        ]
      );
      
      return result.rows[0];
    } catch (error) {
      // Handle unique constraint violation
      if (error.code === '23505') { // unique_violation
        throw new Error('Username already exists');
      }
      throw error;
    }
  }

  /**
   * Find user by username (hashed)
   * @param {string} username - Plaintext username
   * @param {string} salt - Salt used for hashing
   * @returns {Promise<Object|null>} User object or null
   */
  static async findByUsername(username, salt) {
    const hashedUsername = this.hashUsername(username, salt);
    
    const result = await query(
      `SELECT * FROM users 
       WHERE username_hash = $1 
       AND (is_ephemeral = FALSE OR last_seen > NOW() - INTERVAL '24 hours')`,
      [hashedUsername]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Find user by ID
   * @param {string} userId - UUID
   * @returns {Promise<Object|null>} User object or null
   */
  static async findById(userId) {
    const result = await query(
      `SELECT * FROM users 
       WHERE user_id = $1 
       AND (is_ephemeral = FALSE OR last_seen > NOW() - INTERVAL '24 hours')`,
      [userId]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Find user by username hash
   * @param {string} usernameHash - Hashed username
   * @returns {Promise<Object|null>} User object or null
   */
  static async findByUsernameHash(usernameHash) {
    const result = await query(
      `SELECT * FROM users WHERE username_hash = $1`,
      [usernameHash]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Update user's last seen timestamp
   * @param {string} userId - UUID
   * @returns {Promise<boolean>} Success status
   */
  static async updateLastSeen(userId) {
    const result = await query(
      `UPDATE users SET last_seen = NOW() WHERE user_id = $1`,
      [userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Update user's public key
   * @param {string} userId - UUID
   * @param {string} publicKey - New public key
   * @returns {Promise<boolean>} Success status
   */
  static async updatePublicKey(userId, publicKey) {
    const result = await query(
      `UPDATE users SET public_key = $1 WHERE user_id = $2`,
      [publicKey, userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Add pre-keys for X3DH protocol
   * @param {string} userId - UUID
   * @param {Array<string>} preKeys - Array of pre-keys
   * @returns {Promise<boolean>} Success status
   */
  static async addPreKeys(userId, preKeys) {
    const result = await query(
      `UPDATE users SET pre_keys = array_cat(pre_keys, $1) WHERE user_id = $2`,
      [preKeys, userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Get and remove a pre-key for key exchange
   * @param {string} userId - UUID
   * @returns {Promise<string|null>} Pre-key or null
   */
  static async consumePreKey(userId) {
    // Use a transaction to ensure atomic operation
    const client = await query.getClient();
    
    try {
      await client.query('BEGIN');
      
      // Get the first pre-key
      const result = await client.query(
        `SELECT pre_keys[1] as pre_key FROM users WHERE user_id = $1 FOR UPDATE`,
        [userId]
      );
      
      if (!result.rows[0]?.pre_key) {
        await client.query('ROLLBACK');
        return null;
      }
      
      const preKey = result.rows[0].pre_key;
      
      // Remove the used pre-key
      await client.query(
        `UPDATE users SET pre_keys = pre_keys[2:] WHERE user_id = $1`,
        [userId]
      );
      
      await client.query('COMMIT');
      return preKey;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Add one-time keys
   * @param {string} userId - UUID
   * @param {Array<string>} oneTimeKeys - Array of one-time keys
   * @returns {Promise<boolean>} Success status
   */
  static async addOneTimeKeys(userId, oneTimeKeys) {
    const result = await query(
      `UPDATE users SET one_time_keys = array_cat(one_time_keys, $1) WHERE user_id = $2`,
      [oneTimeKeys, userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Get and remove a one-time key
   * @param {string} userId - UUID
   * @returns {Promise<string|null>} One-time key or null
   */
  static async consumeOneTimeKey(userId) {
    const client = await query.getClient();
    
    try {
      await client.query('BEGIN');
      
      const result = await client.query(
        `SELECT one_time_keys[1] as one_time_key FROM users WHERE user_id = $1 FOR UPDATE`,
        [userId]
      );
      
      if (!result.rows[0]?.one_time_key) {
        await client.query('ROLLBACK');
        return null;
      }
      
      const oneTimeKey = result.rows[0].one_time_key;
      
      await client.query(
        `UPDATE users SET one_time_keys = one_time_keys[2:] WHERE user_id = $1`,
        [userId]
      );
      
      await client.query('COMMIT');
      return oneTimeKey;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get user's signed pre-key
   * @param {string} userId - UUID
   * @returns {Promise<string|null>} Signed pre-key or null
   */
  static async getSignedPreKey(userId) {
    const result = await query(
      `SELECT signed_pre_key FROM users WHERE user_id = $1`,
      [userId]
    );
    
    return result.rows[0]?.signed_pre_key || null;
  }

  /**
   * Update signed pre-key
   * @param {string} userId - UUID
   * @param {string} signedPreKey - Signed pre-key
   * @returns {Promise<boolean>} Success status
   */
  static async updateSignedPreKey(userId, signedPreKey) {
    const result = await query(
      `UPDATE users SET signed_pre_key = $1 WHERE user_id = $2`,
      [signedPreKey, userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Delete ephemeral users older than threshold
   * @param {number} hoursThreshold - Hours threshold
   * @returns {Promise<number>} Number of deleted users
   */
  static async cleanupEphemeralUsers(hoursThreshold = 24) {
    const result = await query(
      `DELETE FROM users 
       WHERE is_ephemeral = TRUE 
       AND last_seen < NOW() - INTERVAL '${hoursThreshold} hours'
       RETURNING user_id`,
      []
    );
    
    return result.rowCount;
  }

  /**
   * Hash username with salt
   * @param {string} username - Plaintext username
   * @param {string} salt - Salt for hashing
   * @returns {string} Hashed username
   */
  static hashUsername(username, salt) {
    return crypto.createHash('sha256')
      .update(username + salt)
      .digest('hex');
  }

  /**
   * Generate cryptographic salt
   * @param {number} bytes - Number of bytes
   * @returns {string} Hex encoded salt
   */
  static generateSalt(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
  }

  /**
   * Verify user exists and is active
   * @param {string} userId - UUID
   * @returns {Promise<boolean>} Whether user exists and is active
   */
  static async verifyActive(userId) {
    const result = await query(
      `SELECT 1 FROM users 
       WHERE user_id = $1 
       AND (is_ephemeral = FALSE OR last_seen > NOW() - INTERVAL '24 hours')`,
      [userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Get user's public key
   * @param {string} userId - UUID
   * @returns {Promise<string|null>} Public key or null
   */
  static async getPublicKey(userId) {
    const result = await query(
      `SELECT public_key FROM users WHERE user_id = $1`,
      [userId]
    );
    
    return result.rows[0]?.public_key || null;
  }

  /**
   * Get user's identity key
   * @param {string} userId - UUID
   * @returns {Promise<string|null>} Identity key or null
   */
  static async getIdentityKey(userId) {
    const result = await query(
      `SELECT identity_key FROM users WHERE user_id = $1`,
      [userId]
    );
    
    return result.rows[0]?.identity_key || null;
  }

  /**
   * Get all active users in a room
   * @param {string} roomId - Room UUID
   * @returns {Promise<Array<Object>>} Array of users
   */
  static async getActiveUsersInRoom(roomId) {
    const result = await query(
      `SELECT u.user_id, u.username_hash, u.public_key
       FROM users u
       INNER JOIN room_members rm ON u.user_id = rm.user_id
       WHERE rm.room_id = $1 
       AND rm.is_active = TRUE
       AND rm.left_at IS NULL
       AND (u.is_ephemeral = FALSE OR u.last_seen > NOW() - INTERVAL '1 hour')
       ORDER BY rm.joined_at`,
      [roomId]
    );
    
    return result.rows;
  }

  /**
   * Search for users by username prefix (hashed)
   * Note: This is a privacy-preserving search
   * @param {string} prefixHash - Hashed username prefix
   * @returns {Promise<Array<Object>>} Matching users
   */
  static async searchByUsernamePrefix(prefixHash) {
    const result = await query(
      `SELECT user_id, username_hash, public_key
       FROM users 
       WHERE username_hash LIKE $1 || '%'
       AND (is_ephemeral = FALSE OR last_seen > NOW() - INTERVAL '1 hour')
       LIMIT 10`,
      [prefixHash]
    );
    
    return result.rows;
  }
}

module.exports = User;