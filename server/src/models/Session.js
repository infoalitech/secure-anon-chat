const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { query } = require('../config/database');

class Session {
  /**
   * Session model for user sessions
   * Note: Sessions are ephemeral and contain minimal identifying information
   */

  /**
   * Create a new session
   * @param {Object} sessionData - Session data
   * @param {string} sessionData.userId - User UUID
   * @param {string} sessionData.sessionKey - Raw session key (hashed before storage)
   * @param {string} sessionData.ip - User IP address (hashed before storage)
   * @param {string} sessionData.userAgent - User agent string (hashed before storage)
   * @param {string} sessionData.websocketId - WebSocket connection ID
   * @param {number} sessionData.ttlSeconds - Session TTL in seconds
   * @returns {Promise<Object>} Created session object
   */
  static async create({
    userId,
    sessionKey,
    ip = null,
    userAgent = null,
    websocketId = null,
    ttlSeconds = 24 * 60 * 60 // Default: 24 hours
  }) {
    try {
      // Hash sensitive data before storage
      const sessionKeyHash = this.hashSessionKey(sessionKey);
      const ipHash = ip ? this.hashIP(ip) : null;
      const userAgentHash = userAgent ? this.hashString(userAgent) : null;
      
      const sessionId = uuidv4();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + (ttlSeconds * 1000));
      
      const result = await query(
        `INSERT INTO sessions (
          session_id, user_id, session_key_hash, websocket_id,
          ip_hash, user_agent_hash, created_at, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *`,
        [
          sessionId,
          userId,
          sessionKeyHash,
          websocketId,
          ipHash,
          userAgentHash,
          now,
          expiresAt
        ]
      );
      
      return result.rows[0];
    } catch (error) {
      console.error('Session creation error:', error);
      throw error;
    }
  }

  /**
   * Find session by session key
   * @param {string} sessionKey - Raw session key
   * @returns {Promise<Object|null>} Session object or null
   */
  static async findBySessionKey(sessionKey) {
    const sessionKeyHash = this.hashSessionKey(sessionKey);
    
    const result = await query(
      `SELECT s.*, u.username_hash, u.public_key, u.is_ephemeral
       FROM sessions s
       INNER JOIN users u ON s.user_id = u.user_id
       WHERE s.session_key_hash = $1 
       AND s.is_active = TRUE
       AND s.expires_at > NOW()`,
      [sessionKeyHash]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Find session by ID
   * @param {string} sessionId - Session UUID
   * @returns {Promise<Object|null>} Session object or null
   */
  static async findById(sessionId) {
    const result = await query(
      `SELECT s.*, u.username_hash, u.public_key, u.is_ephemeral
       FROM sessions s
       INNER JOIN users u ON s.user_id = u.user_id
       WHERE s.session_id = $1 
       AND s.is_active = TRUE
       AND s.expires_at > NOW()`,
      [sessionId]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Find active sessions for a user
   * @param {string} userId - User UUID
   * @returns {Promise<Array<Object>>} Array of active sessions
   */
  static async findByUser(userId) {
    const result = await query(
      `SELECT * FROM sessions 
       WHERE user_id = $1 
       AND is_active = TRUE
       AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [userId]
    );
    
    return result.rows;
  }

  /**
   * Update session's last activity timestamp
   * @param {string} sessionId - Session UUID
   * @returns {Promise<boolean>} Success status
   */
  static async updateLastActivity(sessionId) {
    const result = await query(
      `UPDATE sessions 
       SET last_activity = NOW()
       WHERE session_id = $1 
       AND is_active = TRUE
       AND expires_at > NOW()`,
      [sessionId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Update session's WebSocket ID
   * @param {string} sessionId - Session UUID
   * @param {string} websocketId - WebSocket connection ID
   * @returns {Promise<boolean>} Success status
   */
  static async updateWebSocketId(sessionId, websocketId) {
    const result = await query(
      'UPDATE sessions SET websocket_id = $1 WHERE session_id = $2',
      [websocketId, sessionId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Invalidate session (log out)
   * @param {string} sessionId - Session UUID
   * @returns {Promise<boolean>} Success status
   */
  static async invalidate(sessionId) {
    const result = await query(
      `UPDATE sessions 
       SET is_active = FALSE, expires_at = NOW()
       WHERE session_id = $1 AND is_active = TRUE`,
      [sessionId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Invalidate all sessions for a user
   * @param {string} userId - User UUID
   * @returns {Promise<number>} Number of sessions invalidated
   */
  static async invalidateAllForUser(userId) {
    const result = await query(
      `UPDATE sessions 
       SET is_active = FALSE, expires_at = NOW()
       WHERE user_id = $1 AND is_active = TRUE`,
      [userId]
    );
    
    return result.rowCount;
  }

  /**
   * Invalidate session by session key
   * @param {string} sessionKey - Raw session key
   * @returns {Promise<boolean>} Success status
   */
  static async invalidateBySessionKey(sessionKey) {
    const sessionKeyHash = this.hashSessionKey(sessionKey);
    
    const result = await query(
      `UPDATE sessions 
       SET is_active = FALSE, expires_at = NOW()
       WHERE session_key_hash = $1 AND is_active = TRUE`,
      [sessionKeyHash]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Extend session expiration
   * @param {string} sessionId - Session UUID
   * @param {number} additionalSeconds - Additional seconds to extend
   * @returns {Promise<boolean>} Success status
   */
  static async extend(sessionId, additionalSeconds) {
    const result = await query(
      `UPDATE sessions 
       SET expires_at = expires_at + INTERVAL '${additionalSeconds} seconds'
       WHERE session_id = $1 
       AND is_active = TRUE
       AND expires_at > NOW()`,
      [sessionId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Clean up expired sessions
   * @returns {Promise<number>} Number of sessions cleaned up
   */
  static async cleanupExpired() {
    const result = await query(
      `DELETE FROM sessions 
       WHERE expires_at < NOW() OR is_active = FALSE`,
      []
    );
    
    return result.rowCount;
  }

  /**
   * Get session statistics
   * @returns {Promise<Object>} Statistics object
   */
  static async getStatistics() {
    const result = await query(
      `SELECT 
         COUNT(*) as total_sessions,
         COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_sessions,
         COUNT(CASE WHEN expires_at > NOW() THEN 1 END) as valid_sessions,
         MIN(created_at) as oldest_session,
         MAX(created_at) as newest_session
       FROM sessions`,
      []
    );
    
    return result.rows[0] || {};
  }

  /**
   * Verify session is valid and active
   * @param {string} sessionId - Session UUID
   * @returns {Promise<boolean>} Whether session is valid
   */
  static async verify(sessionId) {
    const result = await query(
      `SELECT 1 FROM sessions 
       WHERE session_id = $1 
       AND is_active = TRUE
       AND expires_at > NOW()`,
      [sessionId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Get session by WebSocket ID
   * @param {string} websocketId - WebSocket connection ID
   * @returns {Promise<Object|null>} Session object or null
   */
  static async findByWebSocketId(websocketId) {
    const result = await query(
      `SELECT s.*, u.username_hash, u.public_key
       FROM sessions s
       INNER JOIN users u ON s.user_id = u.user_id
       WHERE s.websocket_id = $1 
       AND s.is_active = TRUE
       AND s.expires_at > NOW()`,
      [websocketId]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Hash session key
   * @param {string} sessionKey - Raw session key
   * @returns {string} Hashed session key
   */
  static hashSessionKey(sessionKey) {
    return crypto.createHash('sha512')
      .update(sessionKey + process.env.SESSION_SECRET)
      .digest('hex');
  }

  /**
   * Hash IP address
   * @param {string} ip - IP address
   * @returns {string} Hashed IP
   */
  static hashIP(ip) {
    return crypto.createHash('sha256')
      .update(ip + process.env.SESSION_SECRET)
      .digest('hex')
      .substring(0, 32);
  }

  /**
   * Hash string
   * @param {string} str - String to hash
   * @returns {string} Hashed string
   */
  static hashString(str) {
    return crypto.createHash('sha256')
      .update(str + process.env.SESSION_SECRET)
      .digest('hex')
      .substring(0, 32);
  }

  /**
   * Generate secure session key
   * @param {number} bytes - Number of random bytes
   * @returns {string} Base64 encoded session key
   */
  static generateSessionKey(bytes = 64) {
    return crypto.randomBytes(bytes).toString('base64');
  }

  /**
   * Check if session has been inactive for too long
   * @param {string} sessionId - Session UUID
   * @param {number} maxInactiveMinutes - Maximum inactive minutes
   * @returns {Promise<boolean>} Whether session is inactive too long
   */
  static async isInactiveTooLong(sessionId, maxInactiveMinutes = 30) {
    const result = await query(
      `SELECT 1 FROM sessions 
       WHERE session_id = $1 
       AND is_active = TRUE
       AND expires_at > NOW()
       AND last_activity < NOW() - INTERVAL '${maxInactiveMinutes} minutes'`,
      [sessionId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Get all active WebSocket sessions
   * @returns {Promise<Array<Object>>} Active WebSocket sessions
   */
  static async getActiveWebSocketSessions() {
    const result = await query(
      `SELECT s.*, u.username_hash
       FROM sessions s
       INNER JOIN users u ON s.user_id = u.user_id
       WHERE s.websocket_id IS NOT NULL
       AND s.is_active = TRUE
       AND s.expires_at > NOW()`,
      []
    );
    
    return result.rows;
  }
}

module.exports = Session;