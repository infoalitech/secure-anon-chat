const { v4: uuidv4 } = require('uuid');
const { query } = require('../config/database');
const crypto = require('crypto');

class Message {
  /**
   * Message model for encrypted chat messages
   * Note: All message content is encrypted end-to-end
   */

  /**
   * Create a new encrypted message
   * @param {Object} messageData - Message data
   * @param {string} messageData.roomId - Room UUID
   * @param {string} messageData.senderId - Sender UUID
   * @param {string} messageData.encryptedContent - Encrypted message content
   * @param {string} messageData.messageType - Type of message
   * @param {Object} messageData.metadata - Encrypted metadata
   * @param {number} messageData.sequenceNumber - Sequence number for ordering
   * @returns {Promise<Object>} Created message object
   */
  static async create({
    roomId,
    senderId,
    encryptedContent,
    messageType = 'text',
    metadata = {},
    sequenceNumber = null
  }) {
    try {
      // Generate content hash for integrity verification
      const contentHash = crypto.createHash('sha256')
        .update(encryptedContent)
        .digest('hex');
      
      const messageId = uuidv4();
      const now = new Date();
      
      // If sequence number not provided, get next in room
      if (sequenceNumber === null) {
        sequenceNumber = await this.getNextSequenceNumber(roomId);
      }
      
      const result = await query(
        `INSERT INTO messages (
          message_id, room_id, sender_id, encrypted_content,
          content_hash, metadata, message_type, sequence_number, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *`,
        [
          messageId,
          roomId,
          senderId,
          encryptedContent,
          contentHash,
          JSON.stringify(metadata),
          messageType,
          sequenceNumber,
          now
        ]
      );
      
      return result.rows[0];
    } catch (error) {
      console.error('Message creation error:', error);
      throw error;
    }
  }

  /**
   * Get next sequence number for a room
   * @param {string} roomId - Room UUID
   * @returns {Promise<number>} Next sequence number
   */
  static async getNextSequenceNumber(roomId) {
    const result = await query(
      `SELECT COALESCE(MAX(sequence_number), 0) + 1 as next_sequence
       FROM messages 
       WHERE room_id = $1`,
      [roomId]
    );
    
    return parseInt(result.rows[0].next_sequence);
  }

  /**
   * Find messages in a room with pagination
   * @param {string} roomId - Room UUID
   * @param {number} limit - Number of messages to return
   * @param {string} before - Message ID to start before (for pagination)
   * @returns {Promise<Array<Object>>} Array of messages
   */
  static async findByRoom(roomId, limit = 50, before = null) {
    let queryStr = `
      SELECT m.*, u.username_hash as sender_username
      FROM messages m
      LEFT JOIN users u ON m.sender_id = u.user_id
      WHERE m.room_id = $1 
      AND m.deleted_at IS NULL
    `;
    
    const params = [roomId];
    
    if (before) {
      // Get sequence number of the 'before' message
      const beforeResult = await query(
        'SELECT sequence_number FROM messages WHERE message_id = $1',
        [before]
      );
      
      if (beforeResult.rows[0]) {
        queryStr += ' AND m.sequence_number < $2';
        params.push(beforeResult.rows[0].sequence_number);
      }
    }
    
    queryStr += ' ORDER BY m.sequence_number DESC LIMIT $' + (params.length + 1);
    params.push(limit);
    
    const result = await query(queryStr, params);
    
    // Return in chronological order
    return result.rows.reverse();
  }

  /**
   * Find message by ID
   * @param {string} messageId - Message UUID
   * @returns {Promise<Object|null>} Message object or null
   */
  static async findById(messageId) {
    const result = await query(
      `SELECT m.*, u.username_hash as sender_username
       FROM messages m
       LEFT JOIN users u ON m.sender_id = u.user_id
       WHERE m.message_id = $1 AND m.deleted_at IS NULL`,
      [messageId]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Find messages by sender in a room
   * @param {string} senderId - Sender UUID
   * @param {string} roomId - Room UUID
   * @param {number} limit - Number of messages to return
   * @returns {Promise<Array<Object>>} Array of messages
   */
  static async findBySenderInRoom(senderId, roomId, limit = 100) {
    const result = await query(
      `SELECT * FROM messages 
       WHERE sender_id = $1 
       AND room_id = $2 
       AND deleted_at IS NULL
       ORDER BY created_at DESC 
       LIMIT $3`,
      [senderId, roomId, limit]
    );
    
    return result.rows;
  }

  /**
   * Mark message as deleted (soft delete)
   * @param {string} messageId - Message UUID
   * @param {string} deletedBy - User UUID who deleted the message
   * @returns {Promise<boolean>} Success status
   */
  static async softDelete(messageId, deletedBy) {
    const result = await query(
      `UPDATE messages 
       SET deleted_at = NOW(),
           metadata = jsonb_set(
             COALESCE(metadata, '{}'::jsonb),
             '{deletedBy}',
             to_jsonb($2::text)
           )
       WHERE message_id = $1 
       AND deleted_at IS NULL`,
      [messageId, deletedBy]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Permanently delete message
   * @param {string} messageId - Message UUID
   * @returns {Promise<boolean>} Success status
   */
  static async permanentDelete(messageId) {
    const result = await query(
      'DELETE FROM messages WHERE message_id = $1',
      [messageId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Update message content (for editing)
   * Note: Only the encrypted content is updated
   * @param {string} messageId - Message UUID
   * @param {string} encryptedContent - New encrypted content
   * @param {Object} metadata - Updated metadata
   * @returns {Promise<boolean>} Success status
   */
  static async update(messageId, encryptedContent, metadata = {}) {
    const contentHash = crypto.createHash('sha256')
      .update(encryptedContent)
      .digest('hex');
    
    const result = await query(
      `UPDATE messages 
       SET encrypted_content = $1,
           content_hash = $2,
           metadata = jsonb_set(
             COALESCE(metadata, '{}'::jsonb),
             '{editedAt}',
             to_jsonb(NOW()::text)
           )
       WHERE message_id = $3 
       AND deleted_at IS NULL`,
      [encryptedContent, contentHash, messageId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Verify message integrity
   * @param {string} messageId - Message UUID
   * @returns {Promise<boolean>} Whether message integrity is valid
   */
  static async verifyIntegrity(messageId) {
    const message = await this.findById(messageId);
    if (!message) return false;
    
    const calculatedHash = crypto.createHash('sha256')
      .update(message.encrypted_content)
      .digest('hex');
    
    return calculatedHash === message.content_hash;
  }

  /**
   * Get message count in a room
   * @param {string} roomId - Room UUID
   * @returns {Promise<number>} Message count
   */
  static async countByRoom(roomId) {
    const result = await query(
      `SELECT COUNT(*) as count 
       FROM messages 
       WHERE room_id = $1 AND deleted_at IS NULL`,
      [roomId]
    );
    
    return parseInt(result.rows[0].count);
  }

  /**
   * Get latest message in a room
   * @param {string} roomId - Room UUID
   * @returns {Promise<Object|null>} Latest message or null
   */
  static async getLatestInRoom(roomId) {
    const result = await query(
      `SELECT m.*, u.username_hash as sender_username
       FROM messages m
       LEFT JOIN users u ON m.sender_id = u.user_id
       WHERE m.room_id = $1 
       AND m.deleted_at IS NULL
       ORDER BY m.sequence_number DESC 
       LIMIT 1`,
      [roomId]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Clean up old messages (for ephemeral rooms)
   * @param {string} roomId - Room UUID
   * @param {number} daysThreshold - Days threshold
   * @returns {Promise<number>} Number of deleted messages
   */
  static async cleanupOldMessages(roomId, daysThreshold = 7) {
    const result = await query(
      `DELETE FROM messages 
       WHERE room_id = $1 
       AND created_at < NOW() - INTERVAL '${daysThreshold} days'
       RETURNING message_id`,
      [roomId]
    );
    
    return result.rowCount;
  }

  /**
   * Search messages by metadata (encrypted search)
   * Note: This only searches encrypted metadata, not message content
   * @param {string} roomId - Room UUID
   * @param {Object} metadataQuery - Metadata query object
   * @param {number} limit - Number of messages to return
   * @returns {Promise<Array<Object>>} Matching messages
   */
  static async searchByMetadata(roomId, metadataQuery = {}, limit = 50) {
    let queryStr = `
      SELECT * FROM messages 
      WHERE room_id = $1 
      AND deleted_at IS NULL
    `;
    
    const params = [roomId];
    let paramIndex = 2;
    
    // Build metadata query
    Object.entries(metadataQuery).forEach(([key, value], index) => {
      queryStr += ` AND metadata->>'${key}' = $${paramIndex}`;
      params.push(value);
      paramIndex++;
    });
    
    queryStr += ` ORDER BY created_at DESC LIMIT $${paramIndex}`;
    params.push(limit);
    
    const result = await query(queryStr, params);
    return result.rows;
  }

  /**
   * Get messages for synchronization (for new users joining)
   * @param {string} roomId - Room UUID
   * @param {number} lastSequenceNumber - Last known sequence number
   * @returns {Promise<Array<Object>>} Messages since last sequence
   */
  static async getSyncMessages(roomId, lastSequenceNumber = 0) {
    const result = await query(
      `SELECT m.*, u.username_hash as sender_username
       FROM messages m
       LEFT JOIN users u ON m.sender_id = u.user_id
       WHERE m.room_id = $1 
       AND m.sequence_number > $2
       AND m.deleted_at IS NULL
       ORDER BY m.sequence_number ASC
       LIMIT 100`,
      [roomId, lastSequenceNumber]
    );
    
    return result.rows;
  }

  /**
   * Get message statistics
   * @param {string} roomId - Room UUID
   * @returns {Promise<Object>} Statistics object
   */
  static async getStatistics(roomId) {
    const result = await query(
      `SELECT 
         COUNT(*) as total_messages,
         COUNT(DISTINCT sender_id) as unique_senders,
         MIN(created_at) as first_message_date,
         MAX(created_at) as last_message_date
       FROM messages 
       WHERE room_id = $1 
       AND deleted_at IS NULL`,
      [roomId]
    );
    
    return result.rows[0] || {};
  }
}

module.exports = Message;