const express = require('express');
const router = express.Router();
const { body, param, validationResult } = require('express-validator');
const messageController = require('../controllers/messageController');
const securityMiddleware = require('../middleware/security');
const validationMiddleware = require('../middleware/validation');

/**
 * Message routes for encrypted chat system
 * Note: All message content is encrypted end-to-end
 */

// Validation schemas
const messageValidation = {
  send: [
    body('roomId')
      .isUUID()
      .withMessage('Invalid room ID format'),
    body('encryptedContent')
      .isString()
      .isLength({ min: 1, max: 10240 }) // 10KB max
      .withMessage('Message content must be 1-10240 characters'),
    body('metadata')
      .optional()
      .isObject()
      .withMessage('Metadata must be object'),
    body('messageType')
      .optional()
      .isIn(['text', 'system', 'key_exchange', 'invitation', 'file'])
      .withMessage('Invalid message type'),
    body('contentHash')
      .optional()
      .isString()
      .withMessage('Content hash must be string')
  ],
  
  get: [
    param('roomId')
      .isUUID()
      .withMessage('Invalid room ID format'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be 1-100'),
    query('before')
      .optional()
      .isUUID()
      .withMessage('Invalid before message ID'),
    query('since')
      .optional()
      .isUUID()
      .withMessage('Invalid since message ID')
  ],
  
  update: [
    param('messageId')
      .isUUID()
      .withMessage('Invalid message ID format'),
    body('encryptedContent')
      .isString()
      .isLength({ min: 1, max: 10240 })
      .withMessage('Message content must be 1-10240 characters'),
    body('metadata')
      .optional()
      .isObject()
      .withMessage('Metadata must be object')
  ],
  
  delete: [
    param('messageId')
      .isUUID()
      .withMessage('Invalid message ID format')
  ],
  
  sync: [
    param('roomId')
      .isUUID()
      .withMessage('Invalid room ID format'),
    query('lastSequence')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Invalid last sequence number')
  ]
};

/**
 * @route   POST /api/messages/send
 * @desc    Send encrypted message to room
 * @access  Private
 * @security Message content is encrypted end-to-end
 */
router.post(
  '/send',
  securityMiddleware.authenticate,
  messageValidation.send,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      // Verify user has access to room
      const hasAccess = await messageController.verifyRoomAccess({
        userId: req.user.user_id,
        roomId: req.body.roomId
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      const message = await messageController.sendMessage({
        roomId: req.body.roomId,
        senderId: req.user.user_id,
        encryptedContent: req.body.encryptedContent,
        metadata: req.body.metadata || {},
        messageType: req.body.messageType || 'text',
        contentHash: req.body.contentHash
      });
      
      res.status(201).json({
        success: true,
        data: {
          messageId: message.message_id,
          roomId: message.room_id,
          senderId: message.sender_id,
          sequenceNumber: message.sequence_number,
          createdAt: message.created_at,
          contentHash: message.content_hash
        }
      });
    } catch (error) {
      console.error('Send message error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.body?.roomId
      });
      
      if (error.message === 'Rate limit exceeded') {
        return res.status(429).json({
          success: false,
          error: 'Message rate limit exceeded'
        });
      }
      
      res.status(500).json({
        success: false,
        error: 'Failed to send message'
      });
    }
  }
);

/**
 * @route   GET /api/messages/room/:roomId
 * @desc    Get messages from room with pagination
 * @access  Private
 * @security Verifies room access before returning messages
 */
router.get(
  '/room/:roomId',
  securityMiddleware.authenticate,
  messageValidation.get,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      const { limit = 50, before, since } = req.query;
      
      // Verify user has access to room
      const hasAccess = await messageController.verifyRoomAccess({
        userId: req.user.user_id,
        roomId: roomId
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      let messages;
      
      if (since) {
        // Get messages since a specific message (for synchronization)
        messages = await messageController.getMessagesSince({
          roomId,
          userId: req.user.user_id,
          sinceMessageId: since,
          limit: parseInt(limit)
        });
      } else {
        // Get messages with pagination
        messages = await messageController.getMessages({
          roomId,
          userId: req.user.user_id,
          limit: parseInt(limit),
          beforeMessageId: before
        });
      }
      
      res.json({
        success: true,
        data: {
          messages: messages.map(msg => ({
            messageId: msg.message_id,
            roomId: msg.room_id,
            senderId: msg.sender_id,
            senderUsernameHash: msg.sender_username,
            encryptedContent: msg.encrypted_content,
            contentHash: msg.content_hash,
            metadata: msg.metadata,
            messageType: msg.message_type,
            sequenceNumber: msg.sequence_number,
            createdAt: msg.created_at
          })),
          hasMore: messages.length >= limit
        }
      });
    } catch (error) {
      console.error('Get messages error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get messages'
      });
    }
  }
);

/**
 * @route   GET /api/messages/sync/:roomId
 * @desc    Synchronize messages from a sequence number
 * @access  Private
 * @security For catching up on missed messages
 */
router.get(
  '/sync/:roomId',
  securityMiddleware.authenticate,
  messageValidation.sync,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      const { lastSequence = 0 } = req.query;
      
      // Verify user has access to room
      const hasAccess = await messageController.verifyRoomAccess({
        userId: req.user.user_id,
        roomId: roomId
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      const messages = await messageController.syncMessages({
        roomId,
        lastSequenceNumber: parseInt(lastSequence),
        userId: req.user.user_id
      });
      
      res.json({
        success: true,
        data: {
          messages: messages.map(msg => ({
            messageId: msg.message_id,
            senderId: msg.sender_id,
            senderUsernameHash: msg.sender_username,
            encryptedContent: msg.encrypted_content,
            contentHash: msg.content_hash,
            metadata: msg.metadata,
            messageType: msg.message_type,
            sequenceNumber: msg.sequence_number,
            createdAt: msg.created_at
          })),
          latestSequence: messages.length > 0 
            ? Math.max(...messages.map(m => m.sequence_number))
            : lastSequence
        }
      });
    } catch (error) {
      console.error('Sync messages error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to synchronize messages'
      });
    }
  }
);

/**
 * @route   PUT /api/messages/:messageId
 * @desc    Update message content (edit)
 * @access  Private
 * @security Only sender can edit, content remains encrypted
 */
router.put(
  '/:messageId',
  securityMiddleware.authenticate,
  messageValidation.update,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { messageId } = req.params;
      
      // Verify user is the sender
      const isSender = await messageController.verifySender({
        messageId,
        userId: req.user.user_id
      });
      
      if (!isSender) {
        return res.status(403).json({
          success: false,
          error: 'Only message sender can edit'
        });
      }
      
      // Verify message hasn't been deleted
      const message = await messageController.getMessage(messageId);
      if (!message || message.deleted_at) {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }
      
      // Check if message is too old to edit (5 minutes)
      const messageAge = Date.now() - new Date(message.created_at).getTime();
      if (messageAge > 5 * 60 * 1000) {
        return res.status(400).json({
          success: false,
          error: 'Message is too old to edit'
        });
      }
      
      const updated = await messageController.updateMessage({
        messageId,
        encryptedContent: req.body.encryptedContent,
        metadata: req.body.metadata || {}
      });
      
      if (!updated) {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }
      
      res.json({
        success: true,
        data: {
          messageId,
          updatedAt: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('Update message error:', {
        error: error.message,
        userId: req.user?.user_id,
        messageId: req.params?.messageId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to update message'
      });
    }
  }
);

/**
 * @route   DELETE /api/messages/:messageId
 * @desc    Delete message (soft delete)
 * @access  Private
 * @security Only sender or room admin can delete
 */
router.delete(
  '/:messageId',
  securityMiddleware.authenticate,
  messageValidation.delete,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { messageId } = req.params;
      
      // Get message to check permissions
      const message = await messageController.getMessage(messageId);
      if (!message) {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }
      
      // Check if user is sender or room admin
      const isSender = message.sender_id === req.user.user_id;
      const isAdmin = await messageController.isRoomAdmin({
        userId: req.user.user_id,
        roomId: message.room_id
      });
      
      if (!isSender && !isAdmin) {
        return res.status(403).json({
          success: false,
          error: 'Not authorized to delete this message'
        });
      }
      
      const deleted = await messageController.deleteMessage({
        messageId,
        deletedBy: req.user.user_id
      });
      
      if (!deleted) {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }
      
      res.json({
        success: true,
        data: {
          messageId,
          deletedAt: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('Delete message error:', {
        error: error.message,
        userId: req.user?.user_id,
        messageId: req.params?.messageId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to delete message'
      });
    }
  }
);

/**
 * @route   GET /api/messages/:messageId
 * @desc    Get specific message
 * @access  Private
 * @security Verifies room access
 */
router.get(
  '/:messageId',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { messageId } = req.params;
      
      const message = await messageController.getMessage(messageId);
      if (!message) {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }
      
      // Verify user has access to room
      const hasAccess = await messageController.verifyRoomAccess({
        userId: req.user.user_id,
        roomId: message.room_id
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to message'
        });
      }
      
      res.json({
        success: true,
        data: {
          messageId: message.message_id,
          roomId: message.room_id,
          senderId: message.sender_id,
          senderUsernameHash: message.sender_username,
          encryptedContent: message.encrypted_content,
          contentHash: message.content_hash,
          metadata: message.metadata,
          messageType: message.message_type,
          sequenceNumber: message.sequence_number,
          createdAt: message.created_at,
          deletedAt: message.deleted_at
        }
      });
    } catch (error) {
      console.error('Get message error:', {
        error: error.message,
        userId: req.user?.user_id,
        messageId: req.params?.messageId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get message'
      });
    }
  }
);

/**
 * @route   GET /api/messages/room/:roomId/latest
 * @desc    Get latest message in room
 * @access  Private
 * @security Verifies room access
 */
router.get(
  '/room/:roomId/latest',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      
      // Verify user has access to room
      const hasAccess = await messageController.verifyRoomAccess({
        userId: req.user.user_id,
        roomId
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      const message = await messageController.getLatestMessage(roomId);
      
      res.json({
        success: true,
        data: message ? {
          messageId: message.message_id,
          senderId: message.sender_id,
          senderUsernameHash: message.sender_username,
          encryptedContent: message.encrypted_content,
          contentHash: message.content_hash,
          messageType: message.message_type,
          sequenceNumber: message.sequence_number,
          createdAt: message.created_at
        } : null
      });
    } catch (error) {
      console.error('Get latest message error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get latest message'
      });
    }
  }
);

/**
 * @route   GET /api/messages/room/:roomId/statistics
 * @desc    Get message statistics for room
 * @access  Private
 * @security Verifies room access
 */
router.get(
  '/room/:roomId/statistics',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      
      // Verify user has access to room
      const hasAccess = await messageController.verifyRoomAccess({
        userId: req.user.user_id,
        roomId
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      const statistics = await messageController.getRoomStatistics(roomId);
      
      res.json({
        success: true,
        data: statistics
      });
    } catch (error) {
      console.error('Get statistics error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get statistics'
      });
    }
  }
);

/**
 * @route   POST /api/messages/verify-integrity
 * @desc    Verify message integrity (for client verification)
 * @access  Private
 * @security Allows clients to verify server hasn't tampered with messages
 */
router.post(
  '/verify-integrity',
  securityMiddleware.authenticate,
  [
    body('messageId')
      .isUUID()
      .withMessage('Invalid message ID format'),
    body('contentHash')
      .isString()
      .withMessage('Content hash required')
  ],
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { messageId, contentHash } = req.body;
      
      const isValid = await messageController.verifyMessageIntegrity({
        messageId,
        expectedHash: contentHash,
        userId: req.user.user_id
      });
      
      res.json({
        success: true,
        data: {
          messageId,
          integrityValid: isValid
        }
      });
    } catch (error) {
      console.error('Verify integrity error:', {
        error: error.message,
        userId: req.user?.user_id,
        messageId: req.body?.messageId
      });
      
      res.status(400).json({
        success: false,
        error: 'Failed to verify integrity'
      });
    }
  }
);

module.exports = router;