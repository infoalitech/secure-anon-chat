const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { query } = require('../config/database');

class Room {
  /**
   * Room model for chat rooms
   * Note: Room names are hashed for privacy
   */

  /**
   * Create a new chat room
   * @param {Object} roomData - Room data
   * @param {string} roomData.name - Room name (hashed before storage)
   * @param {string} roomData.createdBy - Creator user UUID
   * @param {boolean} roomData.isPrivate - Whether room is private
   * @param {string} roomData.ephemeralKey - Encrypted room key
   * @param {Array<string>} roomData.initialMembers - Initial member user IDs
   * @returns {Promise<Object>} Created room object
   */
  static async create({
    name,
    createdBy,
    isPrivate = false,
    ephemeralKey = null,
    initialMembers = []
  }) {
    try {
      // Generate unique salt for room name hashing
      const roomSalt = crypto.randomBytes(32).toString('hex');
      const roomNameHash = this.hashRoomName(name, roomSalt);
      
      const roomId = uuidv4();
      const now = new Date();
      
      // Start transaction
      const client = await query.getClient();
      
      try {
        await client.query('BEGIN');
        
        // Create room
        const roomResult = await client.query(
          `INSERT INTO rooms (
            room_id, room_name_hash, room_salt, is_private,
            created_by, ephemeral_key, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING *`,
          [
            roomId,
            roomNameHash,
            roomSalt,
            isPrivate,
            createdBy,
            ephemeralKey,
            now
          ]
        );
        
        const room = roomResult.rows[0];
        
        // Add creator as member
        await client.query(
          `INSERT INTO room_members (room_id, user_id, joined_at, role)
           VALUES ($1, $2, $3, 'admin')`,
          [roomId, createdBy, now]
        );
        
        // Add initial members if any
        if (initialMembers.length > 0) {
          const memberValues = initialMembers.map((memberId, index) => {
            const offset = index * 3;
            return `($${offset + 1}, $${offset + 2}, $${offset + 3}, 'member')`;
          }).join(',');
          
          const memberParams = initialMembers.flatMap(memberId => [
            roomId, memberId, now
          ]);
          
          await client.query(
            `INSERT INTO room_members (room_id, user_id, joined_at, role)
             VALUES ${memberValues}`,
            memberParams
          );
        }
        
        await client.query('COMMIT');
        
        // Add members to room object
        room.members = await this.getMembers(roomId);
        
        return room;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      if (error.code === '23505') { // unique_violation
        throw new Error('Room name already exists');
      }
      throw error;
    }
  }

  /**
   * Find room by ID
   * @param {string} roomId - Room UUID
   * @returns {Promise<Object|null>} Room object or null
   */
  static async findById(roomId) {
    const result = await query(
      `SELECT r.*, 
              json_agg(
                json_build_object(
                  'user_id', u.user_id,
                  'username_hash', u.username_hash,
                  'joined_at', rm.joined_at,
                  'role', rm.role,
                  'is_active', rm.is_active
                )
              ) as members
       FROM rooms r
       LEFT JOIN room_members rm ON r.room_id = rm.room_id
       LEFT JOIN users u ON rm.user_id = u.user_id
       WHERE r.room_id = $1
       AND r.archived_at IS NULL
       GROUP BY r.room_id`,
      [roomId]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Find room by name (hashed)
   * @param {string} name - Room name
   * @param {string} salt - Room salt
   * @returns {Promise<Object|null>} Room object or null
   */
  static async findByName(name, salt) {
    const roomNameHash = this.hashRoomName(name, salt);
    
    const result = await query(
      `SELECT * FROM rooms 
       WHERE room_name_hash = $1 
       AND archived_at IS NULL`,
      [roomNameHash]
    );
    
    return result.rows[0] || null;
  }

  /**
   * Find public rooms
   * @param {number} limit - Number of rooms to return
   * @param {number} offset - Pagination offset
   * @returns {Promise<Array<Object>>} Array of public rooms
   */
  static async findPublicRooms(limit = 50, offset = 0) {
    const result = await query(
      `SELECT r.*, 
              COUNT(rm.user_id) as member_count,
              MAX(m.created_at) as last_activity
       FROM rooms r
       LEFT JOIN room_members rm ON r.room_id = rm.room_id AND rm.is_active = TRUE
       LEFT JOIN messages m ON r.room_id = m.room_id
       WHERE r.is_private = FALSE 
       AND r.archived_at IS NULL
       GROUP BY r.room_id
       ORDER BY last_activity DESC NULLS LAST
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    
    return result.rows;
  }

  /**
   * Find rooms for a user
   * @param {string} userId - User UUID
   * @returns {Promise<Array<Object>>} Array of rooms
   */
  static async findByUser(userId) {
    const result = await query(
      `SELECT r.*, 
              rm.joined_at,
              rm.role,
              COUNT(DISTINCT rm2.user_id) as member_count,
              MAX(m.created_at) as last_activity
       FROM rooms r
       INNER JOIN room_members rm ON r.room_id = rm.room_id
       LEFT JOIN room_members rm2 ON r.room_id = rm2.room_id AND rm2.is_active = TRUE
       LEFT JOIN messages m ON r.room_id = m.room_id
       WHERE rm.user_id = $1 
       AND rm.is_active = TRUE
       AND r.archived_at IS NULL
       GROUP BY r.room_id, rm.joined_at, rm.role
       ORDER BY last_activity DESC NULLS LAST`,
      [userId]
    );
    
    return result.rows;
  }

  /**
   * Add user to room
   * @param {string} roomId - Room UUID
   * @param {string} userId - User UUID
   * @param {string} role - User role in room
   * @returns {Promise<boolean>} Success status
   */
  static async addMember(roomId, userId, role = 'member') {
    const now = new Date();
    
    // Check if user is already a member
    const existing = await query(
      `SELECT 1 FROM room_members 
       WHERE room_id = $1 AND user_id = $2`,
      [roomId, userId]
    );
    
    if (existing.rowCount > 0) {
      // Reactivate existing membership
      const result = await query(
        `UPDATE room_members 
         SET is_active = TRUE, 
             left_at = NULL,
             role = COALESCE($3, role),
             joined_at = $4
         WHERE room_id = $1 AND user_id = $2`,
        [roomId, userId, role, now]
      );
      
      return result.rowCount > 0;
    } else {
      // Add new member
      const result = await query(
        `INSERT INTO room_members (room_id, user_id, joined_at, role)
         VALUES ($1, $2, $3, $4)`,
        [roomId, userId, now, role]
      );
      
      return result.rowCount > 0;
    }
  }

  /**
   * Remove user from room (soft remove)
   * @param {string} roomId - Room UUID
   * @param {string} userId - User UUID
   * @returns {Promise<boolean>} Success status
   */
  static async removeMember(roomId, userId) {
    const result = await query(
      `UPDATE room_members 
       SET is_active = FALSE, left_at = NOW()
       WHERE room_id = $1 AND user_id = $2 AND is_active = TRUE`,
      [roomId, userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Get room members
   * @param {string} roomId - Room UUID
   * @param {boolean} activeOnly - Whether to return only active members
   * @returns {Promise<Array<Object>>} Array of members
   */
  static async getMembers(roomId, activeOnly = true) {
    let queryStr = `
      SELECT u.user_id, u.username_hash, u.public_key,
             rm.joined_at, rm.role, rm.is_active
      FROM room_members rm
      INNER JOIN users u ON rm.user_id = u.user_id
      WHERE rm.room_id = $1
    `;
    
    const params = [roomId];
    
    if (activeOnly) {
      queryStr += ' AND rm.is_active = TRUE AND rm.left_at IS NULL';
    }
    
    queryStr += ' ORDER BY rm.joined_at';
    
    const result = await query(queryStr, params);
    return result.rows;
  }

  /**
   * Update room metadata
   * @param {string} roomId - Room UUID
   * @param {Object} updates - Updates to apply
   * @returns {Promise<boolean>} Success status
   */
  static async update(roomId, updates) {
    const validFields = ['ephemeral_key', 'metadata', 'is_private'];
    const setClauses = [];
    const params = [];
    let paramIndex = 1;
    
    Object.entries(updates).forEach(([key, value]) => {
      if (validFields.includes(key)) {
        setClauses.push(`${key} = $${paramIndex}`);
        params.push(value);
        paramIndex++;
      }
    });
    
    if (setClauses.length === 0) {
      return false;
    }
    
    params.push(roomId);
    
    const result = await query(
      `UPDATE rooms 
       SET ${setClauses.join(', ')}
       WHERE room_id = $${paramIndex}`,
      params
    );
    
    return result.rowCount > 0;
  }

  /**
   * Archive room (soft delete)
   * @param {string} roomId - Room UUID
   * @param {string} archivedBy - User UUID who archived the room
   * @returns {Promise<boolean>} Success status
   */
  static async archive(roomId, archivedBy) {
    const result = await query(
      `UPDATE rooms 
       SET archived_at = NOW(),
           metadata = jsonb_set(
             COALESCE(metadata, '{}'::jsonb),
             '{archivedBy}',
             to_jsonb($2::text)
           )
       WHERE room_id = $1`,
      [roomId, archivedBy]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Update room ephemeral key
   * @param {string} roomId - Room UUID
   * @param {string} ephemeralKey - New ephemeral key
   * @returns {Promise<boolean>} Success status
   */
  static async updateEphemeralKey(roomId, ephemeralKey) {
    const result = await query(
      'UPDATE rooms SET ephemeral_key = $1 WHERE room_id = $2',
      [ephemeralKey, roomId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Check if user is a member of room
   * @param {string} roomId - Room UUID
   * @param {string} userId - User UUID
   * @param {boolean} activeOnly - Whether to check only active membership
   * @returns {Promise<boolean>} Whether user is a member
   */
  static async isMember(roomId, userId, activeOnly = true) {
    let queryStr = `
      SELECT 1 FROM room_members 
      WHERE room_id = $1 AND user_id = $2
    `;
    
    const params = [roomId, userId];
    
    if (activeOnly) {
      queryStr += ' AND is_active = TRUE AND left_at IS NULL';
    }
    
    const result = await query(queryStr, params);
    return result.rowCount > 0;
  }

  /**
   * Check if user is admin of room
   * @param {string} roomId - Room UUID
   * @param {string} userId - User UUID
   * @returns {Promise<boolean>} Whether user is admin
   */
  static async isAdmin(roomId, userId) {
    const result = await query(
      `SELECT 1 FROM room_members 
       WHERE room_id = $1 
       AND user_id = $2 
       AND role = 'admin'
       AND is_active = TRUE
       AND left_at IS NULL`,
      [roomId, userId]
    );
    
    return result.rowCount > 0;
  }

  /**
   * Get room statistics
   * @param {string} roomId - Room UUID
   * @returns {Promise<Object>} Statistics object
   */
  static async getStatistics(roomId) {
    const result = await query(
      `SELECT 
         COUNT(DISTINCT rm.user_id) as total_members,
         COUNT(DISTINCT CASE WHEN rm.is_active = TRUE THEN rm.user_id END) as active_members,
         COUNT(DISTINCT m.message_id) as total_messages,
         MIN(m.created_at) as first_message_date,
         MAX(m.created_at) as last_message_date
       FROM rooms r
       LEFT JOIN room_members rm ON r.room_id = rm.room_id
       LEFT JOIN messages m ON r.room_id = m.room_id
       WHERE r.room_id = $1`,
      [roomId]
    );
    
    return result.rows[0] || {};
  }

  /**
   * Hash room name with salt
   * @param {string} name - Room name
   * @param {string} salt - Salt for hashing
   * @returns {string} Hashed room name
   */
  static hashRoomName(name, salt) {
    return crypto.createHash('sha256')
      .update(name + salt)
      .digest('hex');
  }

  /**
   * Clean up archived rooms older than threshold
   * @param {number} daysThreshold - Days threshold
   * @returns {Promise<number>} Number of deleted rooms
   */
  static async cleanupArchivedRooms(daysThreshold = 30) {
    const result = await query(
      `DELETE FROM rooms 
       WHERE archived_at < NOW() - INTERVAL '${daysThreshold} days'
       RETURNING room_id`,
      []
    );
    
    return result.rowCount;
  }

  /**
   * Search rooms by name prefix (hashed)
   * @param {string} prefixHash - Hashed room name prefix
   * @param {boolean} publicOnly - Whether to search only public rooms
   * @param {number} limit - Number of results
   * @returns {Promise<Array<Object>>} Matching rooms
   */
  static async searchByNamePrefix(prefixHash, publicOnly = true, limit = 20) {
    let queryStr = `
      SELECT r.*, COUNT(rm.user_id) as member_count
      FROM rooms r
      LEFT JOIN room_members rm ON r.room_id = rm.room_id AND rm.is_active = TRUE
      WHERE r.room_name_hash LIKE $1 || '%'
      AND r.archived_at IS NULL
    `;
    
    const params = [prefixHash];
    
    if (publicOnly) {
      queryStr += ' AND r.is_private = FALSE';
    }
    
    queryStr += ' GROUP BY r.room_id ORDER BY r.created_at DESC LIMIT $2';
    params.push(limit);
    
    const result = await query(queryStr, params);
    return result.rows;
  }

  /**
   * Get rooms with recent activity
   * @param {number} hoursThreshold - Hours threshold for recent activity
   * @param {number} limit - Number of rooms to return
   * @returns {Promise<Array<Object>>} Active rooms
   */
  static async getRecentlyActive(hoursThreshold = 24, limit = 50) {
    const result = await query(
      `SELECT r.*, 
              MAX(m.created_at) as last_activity,
              COUNT(DISTINCT rm.user_id) as member_count
       FROM rooms r
       LEFT JOIN messages m ON r.room_id = m.room_id
       LEFT JOIN room_members rm ON r.room_id = rm.room_id AND rm.is_active = TRUE
       WHERE r.archived_at IS NULL
       AND (m.created_at > NOW() - INTERVAL '${hoursThreshold} hours' OR m.created_at IS NULL)
       GROUP BY r.room_id
       ORDER BY last_activity DESC NULLS LAST
       LIMIT $1`,
      [limit]
    );
    
    return result.rows;
  }
}

module.exports = Room;