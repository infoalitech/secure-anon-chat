const Message = require('../models/Message');
const Room = require('../models/Room');
const User = require('../models/User');
const { query } = require('../config/database');
const crypto = require('crypto');

/**
 * Message Controller
 * Handles encrypted message operations
 * Note: All message content is encrypted end-to-end
 */

class MessageController {
  /**
   * Send encrypted message to room
   */
  async sendMessage({
    roomId,
    senderId,
    encryptedContent,
    metadata = {},
    messageType = 'text',
    contentHash = null
  }) {
    try {
      // Verify room exists and user is member
      const isMember = await Room.isMember(roomId, senderId);
      if (!isMember) {
        throw new Error('Not a member of this room');
      }
      
      // Generate content hash if not provided
      if (!contentHash) {
        contentHash = crypto.createHash('sha256')
          .update(encryptedContent)
          .digest('hex');
      }
      
      // Check rate limiting (simplified)
      const recentMessages = await this.getRecentUserMessages(senderId, roomId);
      if (recentMessages.length >= 60) { // 60 messages per minute limit
        const oldestMessage = recentMessages[recentMessages.length - 1];
        const timeDiff = Date.now() - new Date(oldestMessage.created_at).getTime();
        if (timeDiff < 60000) {
          throw new Error('Rate limit exceeded');
        }
      }
      
      // Create message
      const message = await Message.create({
        roomId,
        senderId,
        encryptedContent,
        messageType,
        metadata
      });
      
      // Update room last activity
      await this.updateRoomActivity(roomId);
      
      return message;
    } catch (error) {
      console.error('Send message error:', error);
      throw error;
    }
  }

  /**
   * Get messages from room with pagination
   */
  async getMessages({
    roomId,
    userId,
    limit = 50,
    beforeMessageId = null
  }) {
    try {
      // Verify user has access to room
      const hasAccess = await Room.isMember(roomId, userId);
      if (!hasAccess) {
        throw new Error('Access denied');
      }
      
      // Get messages
      const messages = await Message.findByRoom(roomId, limit, beforeMessageId);
      
      return messages;
    } catch (error) {
      console.error('Get messages error:', error);
      throw error;
    }
  }

  /**
   * Get messages since a specific message (for synchronization)
   */
  async getMessagesSince({
    roomId,
    userId,
    sinceMessageId,
    limit = 100
  }) {
    try {
      // Verify user has access to room
      const hasAccess = await Room.isMember(roomId, userId);
      if (!hasAccess) {
        throw new Error('Access denied');
      }
      
      // Get the sequence number of the since message
      const sinceMessage = await Message.findById(sinceMessageId);
      if (!sinceMessage) {
        return [];
      }
      
      // Get messages with higher sequence number
      const result = await query(
        `SELECT m.*, u.username_hash as sender_username
         FROM messages m
         LEFT JOIN users u ON m.sender_id = u.user_id
         WHERE m.room_id = $1 
         AND m.sequence_number > $2
         AND m.deleted_at IS NULL
         ORDER BY m.sequence_number ASC
         LIMIT $3`,
        [roomId, sinceMessage.sequence_number, limit]
      );
      
      return result.rows;
    } catch (error) {
      console.error('Get messages since error:', error);
      throw error;
    }
  }

  /**
   * Synchronize messages from a sequence number
   */
  async syncMessages({
    roomId,
    lastSequenceNumber,
    userId
  }) {
    try {
      // Verify user has access to room
      const hasAccess = await Room.isMember(roomId, userId);
      if (!hasAccess) {
        throw new Error('Access denied');
      }
      
      const messages = await Message.getSyncMessages(roomId, lastSequenceNumber);
      return messages;
    } catch (error) {
      console.error('Sync messages error:', error);
      throw error;
    }
  }

  /**
   * Update message content (edit)
   */
  async updateMessage({
    messageId,
    encryptedContent,
    metadata = {}
  }) {
    try {
      const updated = await Message.update(messageId, encryptedContent, metadata);
      return updated;
    } catch (error) {
      console.error('Update message error:', error);
      throw error;
    }
  }

  /**
   * Delete message (soft delete)
   */
  async deleteMessage({ messageId, deletedBy }) {
    try {
      const deleted = await Message.softDelete(messageId, deletedBy);
      return deleted;
    } catch (error) {
      console.error('Delete message error:', error);
      throw error;
    }
  }

  /**
   * Get specific message
   */
  async getMessage(messageId) {
    try {
      const message = await Message.findById(messageId);
      return message;
    } catch (error) {
      console.error('Get message error:', error);
      throw error;
    }
  }

  /**
   * Get latest message in room
   */
  async getLatestMessage(roomId) {
    try {
      const message = await Message.getLatestInRoom(roomId);
      return message;
    } catch (error) {
      console.error('Get latest message error:', error);
      throw error;
    }
  }

  /**
   * Get message statistics for room
   */
  async getRoomStatistics(roomId) {
    try {
      const statistics = await Message.getStatistics(roomId);
      return statistics;
    } catch (error) {
      console.error('Get room statistics error:', error);
      throw error;
    }
  }

  /**
   * Verify message integrity
   */
  async verifyMessageIntegrity({ messageId, expectedHash, userId }) {
    try {
      const message = await Message.findById(messageId);
      if (!message) {
        return false;
      }
      
      // Verify user has access to room
      const hasAccess = await Room.isMember(message.room_id, userId);
      if (!hasAccess) {
        return false;
      }
      
      const isValid = await Message.verifyIntegrity(messageId);
      return isValid && message.content_hash === expectedHash;
    } catch (error) {
      console.error('Verify integrity error:', error);
      return false;
    }
  }

  /**
   * Verify user is message sender
   */
  async verifySender({ messageId, userId }) {
    try {
      const message = await Message.findById(messageId);
      if (!message) {
        return false;
      }
      
      return message.sender_id === userId;
    } catch (error) {
      console.error('Verify sender error:', error);
      return false;
    }
  }

  /**
   * Check if user is room admin
   */
  async isRoomAdmin({ userId, roomId }) {
    try {
      const isAdmin = await Room.isAdmin(roomId, userId);
      return isAdmin;
    } catch (error) {
      console.error('Check room admin error:', error);
      return false;
    }
  }

  /**
   * Verify user has access to room
   */
  async verifyRoomAccess({ userId, roomId }) {
    try {
      const hasAccess = await Room.isMember(roomId, userId);
      return hasAccess;
    } catch (error) {
      console.error('Verify room access error:', error);
      return false;
    }
  }

  /**
   * Get recent messages from user in room (for rate limiting)
   */
  async getRecentUserMessages(userId, roomId, minutes = 1) {
    try {
      const result = await query(
        `SELECT * FROM messages 
         WHERE sender_id = $1 
         AND room_id = $2
         AND created_at > NOW() - INTERVAL '${minutes} minutes'
         ORDER BY created_at DESC
         LIMIT 100`,
        [userId, roomId]
      );
      
      return result.rows;
    } catch (error) {
      console.error('Get recent user messages error:', error);
      return [];
    }
  }

  /**
   * Update room activity timestamp
   */
  async updateRoomActivity(roomId) {
    try {
      // This updates the room's metadata to track last activity
      await query(
        `UPDATE rooms 
         SET metadata = jsonb_set(
           COALESCE(metadata, '{}'::jsonb),
           '{lastActivity}',
           to_jsonb(NOW()::text)
         )
         WHERE room_id = $1`,
        [roomId]
      );
      
      return true;
    } catch (error) {
      console.error('Update room activity error:', error);
      return false;
    }
  }

  /**
   * Clean up old messages (for housekeeping)
   */
  async cleanupOldMessages(roomId, daysThreshold = 30) {
    try {
      const deletedCount = await Message.cleanupOldMessages(roomId, daysThreshold);
      return deletedCount;
    } catch (error) {
      console.error('Cleanup old messages error:', error);
      throw error;
    }
  }

  /**
   * Search messages by metadata
   */
  async searchMessages({ roomId, metadataQuery, userId, limit = 50 }) {
    try {
      // Verify user has access to room
      const hasAccess = await Room.isMember(roomId, userId);
      if (!hasAccess) {
        throw new Error('Access denied');
      }
      
      const messages = await Message.searchByMetadata(roomId, metadataQuery, limit);
      return messages;
    } catch (error) {
      console.error('Search messages error:', error);
      throw error;
    }
  }

  /**
   * Get message count for user in room
   */
  async getUserMessageCount(userId, roomId) {
    try {
      const result = await query(
        `SELECT COUNT(*) as count 
         FROM messages 
         WHERE sender_id = $1 
         AND room_id = $2
         AND deleted_at IS NULL`,
        [userId, roomId]
      );
      
      return parseInt(result.rows[0].count);
    } catch (error) {
      console.error('Get user message count error:', error);
      return 0;
    }
  }
}

module.exports = new MessageController();