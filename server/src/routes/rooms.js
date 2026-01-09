const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const roomController = require('../controllers/roomController');
const securityMiddleware = require('../middleware/security');
const validationMiddleware = require('../middleware/validation');

/**
 * Room management routes for chat system
 * Note: Room names are hashed for privacy
 */

// Validation schemas
const roomValidation = {
  create: [
    body('name')
      .trim()
      .isLength({ min: 1, max: 64 })
      .withMessage('Room name must be 1-64 characters')
      .matches(/^[a-zA-Z0-9 _-]+$/)
      .withMessage('Room name can only contain letters, numbers, spaces, underscores, and dashes'),
    body('isPrivate')
      .optional()
      .isBoolean()
      .withMessage('isPrivate must be boolean'),
    body('ephemeralKey')
      .optional()
      .isString()
      .withMessage('Ephemeral key must be string'),
    body('initialMembers')
      .optional()
      .isArray()
      .withMessage('Initial members must be array'),
    body('metadata')
      .optional()
      .isObject()
      .withMessage('Metadata must be object')
  ],
  
  join: [
    body('roomId')
      .isUUID()
      .withMessage('Invalid room ID format'),
    body('invitationKey')
      .optional()
      .isString()
      .withMessage('Invitation key must be string')
  ],
  
  invite: [
    body('roomId')
      .isUUID()
      .withMessage('Invalid room ID format'),
    body('username')
      .trim()
      .isLength({ min: 3, max: 32 })
      .withMessage('Username must be 3-32 characters'),
    body('invitationKey')
      .isString()
      .withMessage('Invitation key is required')
  ],
  
  update: [
    param('roomId')
      .isUUID()
      .withMessage('Invalid room ID format'),
    body('ephemeralKey')
      .optional()
      .isString()
      .withMessage('Ephemeral key must be string'),
    body('isPrivate')
      .optional()
      .isBoolean()
      .withMessage('isPrivate must be boolean'),
    body('metadata')
      .optional()
      .isObject()
      .withMessage('Metadata must be object')
  ],
  
  search: [
    query('query')
      .optional()
      .isString()
      .withMessage('Search query must be string'),
    query('publicOnly')
      .optional()
      .isBoolean()
      .withMessage('publicOnly must be boolean'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 50 })
      .withMessage('Limit must be 1-50'),
    query('offset')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Offset must be non-negative')
  ]
};

/**
 * @route   POST /api/rooms/create
 * @desc    Create a new chat room
 * @access  Private
 * @security Room names are hashed for privacy
 */
router.post(
  '/create',
  securityMiddleware.authenticate,
  roomValidation.create,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const room = await roomController.createRoom({
        name: req.body.name,
        createdBy: req.user.user_id,
        isPrivate: req.body.isPrivate || false,
        ephemeralKey: req.body.ephemeralKey,
        initialMembers: req.body.initialMembers || [],
        metadata: req.body.metadata || {}
      });
      
      res.status(201).json({
        success: true,
        data: {
          roomId: room.room_id,
          roomNameHash: room.room_name_hash,
          isPrivate: room.is_private,
          createdBy: room.created_by,
          createdAt: room.created_at,
          ephemeralKey: room.ephemeral_key,
          members: room.members,
          metadata: room.metadata
        }
      });
    } catch (error) {
      console.error('Create room error:', {
        error: error.message,
        userId: req.user?.user_id
      });
      
      if (error.message === 'Room name already exists') {
        return res.status(409).json({
          success: false,
          error: 'Room name already exists'
        });
      }
      
      res.status(500).json({
        success: false,
        error: 'Failed to create room'
      });
    }
  }
);

/**
 * @route   POST /api/rooms/join
 * @desc    Join an existing room
 * @access  Private
 * @security Verifies invitation for private rooms
 */
router.post(
  '/join',
  securityMiddleware.authenticate,
  roomValidation.join,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { roomId, invitationKey } = req.body;
      
      const result = await roomController.joinRoom({
        roomId,
        userId: req.user.user_id,
        invitationKey
      });
      
      if (!result.success) {
        return res.status(result.status || 403).json({
          success: false,
          error: result.message
        });
      }
      
      res.json({
        success: true,
        data: {
          roomId: result.room.room_id,
          roomNameHash: result.room.room_name_hash,
          isPrivate: result.room.is_private,
          joinedAt: result.joinedAt,
          role: result.role,
          ephemeralKey: result.room.ephemeral_key,
          members: result.room.members
        }
      });
    } catch (error) {
      console.error('Join room error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.body?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to join room'
      });
    }
  }
);

/**
 * @route   POST /api/rooms/leave
 * @desc    Leave a room
 * @access  Private
 * @security Soft removal from room
 */
router.post(
  '/leave',
  securityMiddleware.authenticate,
  [
    body('roomId')
      .isUUID()
      .withMessage('Invalid room ID format')
  ],
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { roomId } = req.body;
      
      const left = await roomController.leaveRoom({
        roomId,
        userId: req.user.user_id
      });
      
      if (!left) {
        return res.status(404).json({
          success: false,
          error: 'Not a member of this room'
        });
      }
      
      res.json({
        success: true,
        data: {
          roomId,
          leftAt: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('Leave room error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.body?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to leave room'
      });
    }
  }
);

/**
 * @route   POST /api/rooms/invite
 * @desc    Invite user to private room
 * @access  Private
 * @security Generates encrypted invitation
 */
router.post(
  '/invite',
  securityMiddleware.authenticate,
  roomValidation.invite,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { roomId, username, invitationKey } = req.body;
      
      // Verify user is admin of room
      const isAdmin = await roomController.isRoomAdmin({
        roomId,
        userId: req.user.user_id
      });
      
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          error: 'Only room admins can invite users'
        });
      }
      
      const invitation = await roomController.createInvitation({
        roomId,
        senderId: req.user.user_id,
        username,
        invitationKey
      });
      
      if (!invitation) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }
      
      res.json({
        success: true,
        data: {
          invitationId: invitation.invitation_id,
          roomId: invitation.room_id,
          expiresAt: invitation.expires_at,
          invitationKey: invitation.invitation_key // For client to share
        }
      });
    } catch (error) {
      console.error('Create invitation error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.body?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to create invitation'
      });
    }
  }
);

/**
 * @route   GET /api/rooms/public
 * @desc    Get list of public rooms
 * @access  Public (limited)
 * @security Returns only minimal room info
 */
router.get(
  '/public',
  securityMiddleware.rateLimit.api,
  roomValidation.search,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { query: searchQuery, limit = 20, offset = 0 } = req.query;
      
      let rooms;
      
      if (searchQuery) {
        // Search public rooms by name prefix (hashed)
        rooms = await roomController.searchPublicRooms({
          query: searchQuery,
          limit: parseInt(limit),
          offset: parseInt(offset)
        });
      } else {
        // Get recently active public rooms
        rooms = await roomController.getPublicRooms({
          limit: parseInt(limit),
          offset: parseInt(offset)
        });
      }
      
      res.json({
        success: true,
        data: {
          rooms: rooms.map(room => ({
            roomId: room.room_id,
            memberCount: room.member_count,
            lastActivity: room.last_activity,
            createdAt: room.created_at
            // Note: Room name hash not returned for privacy
          })),
          total: rooms.length,
          hasMore: rooms.length >= limit
        }
      });
    } catch (error) {
      console.error('Get public rooms error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to get public rooms'
      });
    }
  }
);

/**
 * @route   GET /api/rooms/my
 * @desc    Get rooms user is member of
 * @access  Private
 * @security Returns user's rooms with minimal info
 */
router.get(
  '/my',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const rooms = await roomController.getUserRooms(req.user.user_id);
      
      res.json({
        success: true,
        data: {
          rooms: rooms.map(room => ({
            roomId: room.room_id,
            roomNameHash: room.room_name_hash,
            isPrivate: room.is_private,
            joinedAt: room.joined_at,
            role: room.role,
            memberCount: room.member_count,
            lastActivity: room.last_activity,
            ephemeralKey: room.ephemeral_key
          })),
          total: rooms.length
        }
      });
    } catch (error) {
      console.error('Get user rooms error:', {
        error: error.message,
        userId: req.user?.user_id
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get rooms'
      });
    }
  }
);

/**
 * @route   GET /api/rooms/:roomId
 * @desc    Get room details
 * @access  Private
 * @security Verifies user has access to room
 */
router.get(
  '/:roomId',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      
      // Verify user has access to room
      const hasAccess = await roomController.verifyAccess({
        roomId,
        userId: req.user.user_id
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      const room = await roomController.getRoomDetails(roomId);
      
      if (!room) {
        return res.status(404).json({
          success: false,
          error: 'Room not found'
        });
      }
      
      res.json({
        success: true,
        data: {
          roomId: room.room_id,
          roomNameHash: room.room_name_hash,
          isPrivate: room.is_private,
          createdBy: room.created_by,
          createdAt: room.created_at,
          ephemeralKey: room.ephemeral_key,
          members: room.members,
          metadata: room.metadata
        }
      });
    } catch (error) {
      console.error('Get room details error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get room details'
      });
    }
  }
);

/**
 * @route   PUT /api/rooms/:roomId
 * @desc    Update room settings
 * @access  Private
 * @security Only room admins can update
 */
router.put(
  '/:roomId',
  securityMiddleware.authenticate,
  roomValidation.update,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      
      // Verify user is admin of room
      const isAdmin = await roomController.isRoomAdmin({
        roomId,
        userId: req.user.user_id
      });
      
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          error: 'Only room admins can update room'
        });
      }
      
      const updates = {};
      if (req.body.ephemeralKey !== undefined) updates.ephemeralKey = req.body.ephemeralKey;
      if (req.body.isPrivate !== undefined) updates.isPrivate = req.body.isPrivate;
      if (req.body.metadata !== undefined) updates.metadata = req.body.metadata;
      
      const updated = await roomController.updateRoom(roomId, updates);
      
      if (!updated) {
        return res.status(404).json({
          success: false,
          error: 'Room not found'
        });
      }
      
      res.json({
        success: true,
        data: {
          roomId,
          updated: Object.keys(updates)
        }
      });
    } catch (error) {
      console.error('Update room error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to update room'
      });
    }
  }
);

/**
 * @route   DELETE /api/rooms/:roomId
 * @desc    Archive room (soft delete)
 * @access  Private
 * @security Only room creator can archive
 */
router.delete(
  '/:roomId',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      
      // Verify user is room creator
      const isCreator = await roomController.isRoomCreator({
        roomId,
        userId: req.user.user_id
      });
      
      if (!isCreator) {
        return res.status(403).json({
          success: false,
          error: 'Only room creator can archive room'
        });
      }
      
      const archived = await roomController.archiveRoom({
        roomId,
        archivedBy: req.user.user_id
      });
      
      if (!archived) {
        return res.status(404).json({
          success: false,
          error: 'Room not found'
        });
      }
      
      res.json({
        success: true,
        data: {
          roomId,
          archivedAt: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('Archive room error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to archive room'
      });
    }
  }
);

/**
 * @route   GET /api/rooms/:roomId/members
 * @desc    Get room members
 * @access  Private
 * @security Verifies user has access to room
 */
router.get(
  '/:roomId/members',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      
      // Verify user has access to room
      const hasAccess = await roomController.verifyAccess({
        roomId,
        userId: req.user.user_id
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      const members = await roomController.getRoomMembers(roomId);
      
      res.json({
        success: true,
        data: {
          members: members.map(member => ({
            userId: member.user_id,
            usernameHash: member.username_hash,
            publicKey: member.public_key,
            joinedAt: member.joined_at,
            role: member.role,
            isActive: member.is_active
          })),
          total: members.length,
          active: members.filter(m => m.is_active).length
        }
      });
    } catch (error) {
      console.error('Get room members error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get room members'
      });
    }
  }
);

/**
 * @route   GET /api/rooms/:roomId/statistics
 * @desc    Get room statistics
 * @access  Private
 * @security Verifies user has access to room
 */
router.get(
  '/:roomId/statistics',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      
      // Verify user has access to room
      const hasAccess = await roomController.verifyAccess({
        roomId,
        userId: req.user.user_id
      });
      
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: 'Access denied to room'
        });
      }
      
      const statistics = await roomController.getRoomStatistics(roomId);
      
      res.json({
        success: true,
        data: statistics
      });
    } catch (error) {
      console.error('Get room statistics error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get room statistics'
      });
    }
  }
);

/**
 * @route   POST /api/rooms/:roomId/kick
 * @desc    Kick user from room
 * @access  Private
 * @security Only room admins can kick
 */
router.post(
  '/:roomId/kick',
  securityMiddleware.authenticate,
  [
    body('userId')
      .isUUID()
      .withMessage('Invalid user ID format')
  ],
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      const { userId: targetUserId } = req.body;
      
      // Verify user is admin of room
      const isAdmin = await roomController.isRoomAdmin({
        roomId,
        userId: req.user.user_id
      });
      
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          error: 'Only room admins can kick users'
        });
      }
      
      // Cannot kick self
      if (targetUserId === req.user.user_id) {
        return res.status(400).json({
          success: false,
          error: 'Cannot kick yourself'
        });
      }
      
      const kicked = await roomController.kickUser({
        roomId,
        targetUserId,
        kickedBy: req.user.user_id
      });
      
      if (!kicked) {
        return res.status(404).json({
          success: false,
          error: 'User not found in room'
        });
      }
      
      res.json({
        success: true,
        data: {
          roomId,
          userId: targetUserId,
          kickedAt: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('Kick user error:', {
        error: error.message,
        userId: req.user?.user_id,
        roomId: req.params?.roomId,
        targetUserId: req.body?.userId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to kick user'
      });
    }
  }
);

/**
 * @route   GET /api/rooms/invitation/:invitationId
 * @desc    Get invitation details
 * @access  Private
 * @security Verifies invitation belongs to user's room
 */
router.get(
  '/invitation/:invitationId',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const { invitationId } = req.params;
      
      const invitation = await roomController.getInvitation(invitationId);
      
      if (!invitation) {
        return res.status(404).json({
          success: false,
          error: 'Invitation not found'
        });
      }
      
      // Verify user is admin of the room
      const isAdmin = await roomController.isRoomAdmin({
        roomId: invitation.room_id,
        userId: req.user.user_id
      });
      
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          error: 'Not authorized to view this invitation'
        });
      }
      
      res.json({
        success: true,
        data: {
          invitationId: invitation.invitation_id,
          roomId: invitation.room_id,
          senderId: invitation.sender_id,
          recipientHash: invitation.recipient_hash,
          expiresAt: invitation.expires_at,
          usedAt: invitation.used_at,
          createdAt: invitation.created_at
        }
      });
    } catch (error) {
      console.error('Get invitation error:', {
        error: error.message,
        userId: req.user?.user_id,
        invitationId: req.params?.invitationId
      });
      
      res.status(500).json({
        success: false,
        error: 'Failed to get invitation'
      });
    }
  }
);

module.exports = router;