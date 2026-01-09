const Room = require('../models/Room');
const User = require('../models/User');
const Message = require('../models/Message');
const { query } = require('../config/database');
const crypto = require('crypto');

/**
 * Room Controller
 * Handles room management, invitations, and member operations
 */

class RoomController {
  /**
   * Create a new chat room
   */
  async createRoom({
    name,
    createdBy,
    isPrivate = false,
    ephemeralKey = null,
    initialMembers = [],
    metadata = {}
  }) {
    try {
      // Verify creator exists
      const creator = await User.findById(createdBy);
      if (!creator) {
        throw new Error('Creator not found');
      }
      
      // Create room
      const room = await Room.create({
        name,
        createdBy,
        isPrivate,
        ephemeralKey,
        initialMembers,
        metadata
      });
      
      return room;
    } catch (error) {
      console.error('Create room error:', error);
      throw error;
    }
  }

  /**
   * Join an existing room
   */
  async joinRoom({ roomId, userId, invitationKey = null }) {
    try {
      // Verify user exists
      const user = await User.findById(userId);
      if (!user) {
        return {
          success: false,
          message: 'User not found',
          status: 404
        };
      }
      
      // Get room
      const room = await Room.findById(roomId);
      if (!room) {
        return {
          success: false,
          message: 'Room not found',
          status: 404
        };
      }
      
      // Check if room is private
      if (room.is_private) {
        if (!invitationKey) {
          return {
            success: false,
            message: 'Invitation required for private room',
            status: 403
          };
        }
        
        // Validate invitation
        const userHash = User.hashUsername(user.username_hash, '');
        const invitation = await this.validateInvitation(invitationKey, userHash);
        
        if (!invitation || invitation.room_id !== roomId) {
          return {
            success: false,
            message: 'Invalid or expired invitation',
            status: 403
          };
        }
      }
      
      // Check if user is already a member
      const isMember = await Room.isMember(roomId, userId, false);
      if (isMember) {
        // Reactivate membership
        await Room.addMember(roomId, userId, 'member');
      } else {
        // Add as new member
        await Room.addMember(roomId, userId, 'member');
      }
      
      // Get updated room with members
      const updatedRoom = await Room.findById(roomId);
      
      return {
        success: true,
        room: updatedRoom,
        joinedAt: new Date().toISOString(),
        role: 'member'
      };
    } catch (error) {
      console.error('Join room error:', error);
      return {
        success: false,
        message: 'Failed to join room',
        status: 500
      };
    }
  }

  /**
   * Leave a room
   */
  async leaveRoom({ roomId, userId }) {
    try {
      const left = await Room.removeMember(roomId, userId);
      return left;
    } catch (error) {
      console.error('Leave room error:', error);
      throw error;
    }
  }

  /**
   * Create invitation for private room
   */
  async createInvitation({
    roomId,
    senderId,
    username,
    invitationKey,
    ttlHours = 24
  }) {
    try {
      // Verify sender is admin of room
      const isAdmin = await Room.isAdmin(roomId, senderId);
      if (!isAdmin) {
        throw new Error('Not authorized to create invitation');
      }
      
      // Find recipient by username
      // Note: This is simplified - in reality we'd need the salt
      const recipient = await User.findByUsernameHash(
        User.hashUsername(username, '')
      );
      
      if (!recipient) {
        return null;
      }
      
      // Generate recipient hash
      const recipientHash = User.hashUsername(username, '');
      
      // Create invitation in database
      const expiresAt = new Date(Date.now() + (ttlHours * 60 * 60 * 1000));
      
      const result = await query(
        `INSERT INTO invitations (
          room_id, sender_id, recipient_hash, invitation_key, expires_at
        ) VALUES ($1, $2, $3, $4, $5)
        RETURNING *`,
        [roomId, senderId, recipientHash, invitationKey, expiresAt]
      );
      
      return result.rows[0];
    } catch (error) {
      console.error('Create invitation error:', error);
      throw error;
    }
  }

  /**
   * Validate invitation
   */
  async validateInvitation(invitationKey, recipientHash) {
    try {
      const result = await query(
        `SELECT * FROM invitations 
         WHERE invitation_key = $1 
         AND recipient_hash = $2
         AND expires_at > NOW()
         AND used_at IS NULL`,
        [invitationKey, recipientHash]
      );
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const invitation = result.rows[0];
      
      // Mark invitation as used
      await query(
        'UPDATE invitations SET used_at = NOW() WHERE invitation_id = $1',
        [invitation.invitation_id]
      );
      
      return invitation;
    } catch (error) {
      console.error('Validate invitation error:', error);
      throw error;
    }
  }

  /**
   * Search public rooms by name prefix
   */
  async searchPublicRooms({ query: searchQuery, limit = 20, offset = 0 }) {
    try {
      // Hash the search query for privacy-preserving search
      const queryHash = crypto.createHash('sha256')
        .update(searchQuery)
        .digest('hex')
        .substring(0, 32);
      
      const rooms = await Room.searchByNamePrefix(queryHash, true, limit);
      return rooms;
    } catch (error) {
      console.error('Search public rooms error:', error);
      throw error;
    }
  }

  /**
   * Get public rooms
   */
  async getPublicRooms({ limit = 20, offset = 0 }) {
    try {
      const rooms = await Room.findPublicRooms(limit, offset);
      return rooms;
    } catch (error) {
      console.error('Get public rooms error:', error);
      throw error;
    }
  }

  /**
   * Get rooms user is member of
   */
  async getUserRooms(userId) {
    try {
      const rooms = await Room.findByUser(userId);
      return rooms;
    } catch (error) {
      console.error('Get user rooms error:', error);
      throw error;
    }
  }

  /**
   * Get room details
   */
  async getRoomDetails(roomId) {
    try {
      const room = await Room.findById(roomId);
      return room;
    } catch (error) {
      console.error('Get room details error:', error);
      throw error;
    }
  }

  /**
   * Update room settings
   */
  async updateRoom(roomId, updates) {
    try {
      const updated = await Room.update(roomId, updates);
      return updated;
    } catch (error) {
      console.error('Update room error:', error);
      throw error;
    }
  }

  /**
   * Archive room (soft delete)
   */
  async archiveRoom({ roomId, archivedBy }) {
    try {
      const archived = await Room.archive(roomId, archivedBy);
      return archived;
    } catch (error) {
      console.error('Archive room error:', error);
      throw error;
    }
  }

  /**
   * Get room members
   */
  async getRoomMembers(roomId) {
    try {
      const members = await Room.getMembers(roomId);
      return members;
    } catch (error) {
      console.error('Get room members error:', error);
      throw error;
    }
  }

  /**
   * Get room statistics
   */
  async getRoomStatistics(roomId) {
    try {
      const statistics = await Room.getStatistics(roomId);
      return statistics;
    } catch (error) {
      console.error('Get room statistics error:', error);
      throw error;
    }
  }

  /**
   * Kick user from room
   */
  async kickUser({ roomId, targetUserId, kickedBy }) {
    try {
      // Verify kicker is admin
      const isAdmin = await Room.isAdmin(roomId, kickedBy);
      if (!isAdmin) {
        throw new Error('Not authorized to kick users');
      }
      
      // Cannot kick self
      if (targetUserId === kickedBy) {
        throw new Error('Cannot kick yourself');
      }
      
      // Remove user from room
      const kicked = await Room.removeMember(roomId, targetUserId);
      return kicked;
    } catch (error) {
      console.error('Kick user error:', error);
      throw error;
    }
  }

  /**
   * Get invitation details
   */
  async getInvitation(invitationId) {
    try {
      const result = await query(
        'SELECT * FROM invitations WHERE invitation_id = $1',
        [invitationId]
      );
      
      return result.rows[0] || null;
    } catch (error) {
      console.error('Get invitation error:', error);
      throw error;
    }
  }

  /**
   * Verify user has access to room
   */
  async verifyAccess({ roomId, userId }) {
    try {
      const hasAccess = await Room.isMember(roomId, userId);
      return hasAccess;
    } catch (error) {
      console.error('Verify access error:', error);
      return false;
    }
  }

  /**
   * Check if user is room admin
   */
  async isRoomAdmin({ roomId, userId }) {
    try {
      const isAdmin = await Room.isAdmin(roomId, userId);
      return isAdmin;
    } catch (error) {
      console.error('Check room admin error:', error);
      return false;
    }
  }

  /**
   * Check if user is room creator
   */
  async isRoomCreator({ roomId, userId }) {
    try {
      const room = await Room.findById(roomId);
      if (!room) {
        return false;
      }
      
      return room.created_by === userId;
    } catch (error) {
      console.error('Check room creator error:', error);
      return false;
    }
  }

  /**
   * Update room ephemeral key
   */
  async updateEphemeralKey(roomId, ephemeralKey) {
    try {
      const updated = await Room.updateEphemeralKey(roomId, ephemeralKey);
      return updated;
    } catch (error) {
      console.error('Update ephemeral key error:', error);
      throw error;
    }
  }

  /**
   * Get recently active rooms
   */
  async getRecentlyActiveRooms(hoursThreshold = 24, limit = 50) {
    try {
      const rooms = await Room.getRecentlyActive(hoursThreshold, limit);
      return rooms;
    } catch (error) {
      console.error('Get recently active rooms error:', error);
      throw error;
    }
  }

  /**
   * Clean up archived rooms
   */
  async cleanupArchivedRooms(daysThreshold = 30) {
    try {
      const deletedCount = await Room.cleanupArchivedRooms(daysThreshold);
      return deletedCount;
    } catch (error) {
      console.error('Cleanup archived rooms error:', error);
      throw error;
    }
  }

  /**
   * Get room by invitation key
   */
  async getRoomByInvitation(invitationKey) {
    try {
      const result = await query(
        `SELECT r.* 
         FROM rooms r
         INNER JOIN invitations i ON r.room_id = i.room_id
         WHERE i.invitation_key = $1
         AND i.expires_at > NOW()
         AND i.used_at IS NULL`,
        [invitationKey]
      );
      
      return result.rows[0] || null;
    } catch (error) {
      console.error('Get room by invitation error:', error);
      throw error;
    }
  }
}

module.exports = new RoomController();