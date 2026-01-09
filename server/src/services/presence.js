const { getRedisClient } = require('../config/database');
const User = require('../models/User');
const Session = require('../models/Session');

/**
 * Presence Service
 * Tracks user online/offline status and activity
 */

class PresenceService {
  constructor() {
    this.presenceStore = new Map(); // userId -> { status, lastSeen, customStatus }
    this.activityStore = new Map(); // userId -> { typingIn: roomId, lastActivity }
    
    // Presence states
    this.STATUS = {
      ONLINE: 'online',
      AWAY: 'away',
      BUSY: 'busy',
      OFFLINE: 'offline'
    };
    
    // Redis keys
    this.REDIS_KEYS = {
      PRESENCE: 'presence:',
      ACTIVITY: 'activity:',
      ROOM_PRESENCE: 'room_presence:'
    };
    
    // Cleanup interval
    this.cleanupInterval = 5 * 60 * 1000; // 5 minutes
    this.startCleanup();
  }

  /**
   * Update user presence
   */
  async updatePresence(userId, status, customStatus = null) {
    try {
      // Validate status
      if (!Object.values(this.STATUS).includes(status)) {
        throw new Error(`Invalid status: ${status}`);
      }
      
      const presence = {
        userId,
        status,
        customStatus,
        lastSeen: new Date().toISOString(),
        updatedAt: Date.now()
      };
      
      // Store in memory
      this.presenceStore.set(userId, presence);
      
      // Store in Redis if available
      const redisClient = getRedisClient();
      if (redisClient) {
        await redisClient.set(
          `${this.REDIS_KEYS.PRESENCE}${userId}`,
          JSON.stringify(presence),
          {
            EX: 3600 // Expire after 1 hour
          }
        );
      }
      
      // Update user last seen in database
      await User.updateLastSeen(userId);
      
      return presence;
    } catch (error) {
      console.error('Update presence error:', error);
      throw error;
    }
  }

  /**
   * Get user presence
   */
  async getPresence(userId) {
    try {
      // Check memory store first
      let presence = this.presenceStore.get(userId);
      
      // Check Redis if not in memory
      if (!presence) {
        const redisClient = getRedisClient();
        if (redisClient) {
          const redisData = await redisClient.get(`${this.REDIS_KEYS.PRESENCE}${userId}`);
          if (redisData) {
            presence = JSON.parse(redisData);
            this.presenceStore.set(userId, presence);
          }
        }
      }
      
      // If still not found, check database
      if (!presence) {
        const user = await User.findById(userId);
        if (user) {
          presence = {
            userId,
            status: this.STATUS.OFFLINE,
            lastSeen: user.last_seen || user.created_at,
            updatedAt: new Date(user.last_seen || user.created_at).getTime()
          };
        }
      }
      
      // Auto-update status if too old
      if (presence && presence.status !== this.STATUS.OFFLINE) {
        const lastSeenTime = new Date(presence.lastSeen).getTime();
        const now = Date.now();
        
        if (now - lastSeenTime > 5 * 60 * 1000) { // 5 minutes
          presence.status = this.STATUS.AWAY;
        }
        
        if (now - lastSeenTime > 30 * 60 * 1000) { // 30 minutes
          presence.status = this.STATUS.OFFLINE;
        }
      }
      
      return presence || {
        userId,
        status: this.STATUS.OFFLINE,
        lastSeen: null,
        updatedAt: Date.now()
      };
    } catch (error) {
      console.error('Get presence error:', error);
      return {
        userId,
        status: this.STATUS.OFFLINE,
        lastSeen: null,
        updatedAt: Date.now()
      };
    }
  }

  /**
   * Update user activity (typing, etc.)
   */
  async updateActivity(userId, activityType, data = {}) {
    try {
      const activity = {
        userId,
        type: activityType,
        data,
        timestamp: new Date().toISOString(),
        updatedAt: Date.now()
      };
      
      // Store in memory
      this.activityStore.set(userId, activity);
      
      // Store in Redis if available
      const redisClient = getRedisClient();
      if (redisClient) {
        await redisClient.set(
          `${this.REDIS_KEYS.ACTIVITY}${userId}`,
          JSON.stringify(activity),
          {
            EX: 300 // Expire after 5 minutes
          }
        );
      }
      
      return activity;
    } catch (error) {
      console.error('Update activity error:', error);
      throw error;
    }
  }

  /**
   * Get user activity
   */
  async getActivity(userId) {
    try {
      // Check memory store first
      let activity = this.activityStore.get(userId);
      
      // Check Redis if not in memory
      if (!activity) {
        const redisClient = getRedisClient();
        if (redisClient) {
          const redisData = await redisClient.get(`${this.REDIS_KEYS.ACTIVITY}${userId}`);
          if (redisData) {
            activity = JSON.parse(redisData);
            this.activityStore.set(userId, activity);
          }
        }
      }
      
      // Check if activity is stale (older than 30 seconds)
      if (activity && Date.now() - activity.updatedAt > 30000) {
        activity = null;
        this.activityStore.delete(userId);
      }
      
      return activity;
    } catch (error) {
      console.error('Get activity error:', error);
      return null;
    }
  }

  /**
   * Track user joining a room
   */
  async joinRoom(userId, roomId) {
    try {
      const redisClient = getRedisClient();
      if (redisClient) {
        // Add user to room presence set
        await redisClient.sAdd(`${this.REDIS_KEYS.ROOM_PRESENCE}${roomId}`, userId);
        
        // Set expiration for room presence (24 hours)
        await redisClient.expire(`${this.REDIS_KEYS.ROOM_PRESENCE}${roomId}`, 86400);
      }
      
      // Update presence to online
      await this.updatePresence(userId, this.STATUS.ONLINE);
      
      return true;
    } catch (error) {
      console.error('Join room presence error:', error);
      return false;
    }
  }

  /**
   * Track user leaving a room
   */
  async leaveRoom(userId, roomId) {
    try {
      const redisClient = getRedisClient();
      if (redisClient) {
        // Remove user from room presence set
        await redisClient.sRem(`${this.REDIS_KEYS.ROOM_PRESENCE}${roomId}`, userId);
      }
      
      return true;
    } catch (error) {
      console.error('Leave room presence error:', error);
      return false;
    }
  }

  /**
   * Get users in room
   */
  async getRoomPresence(roomId) {
    try {
      const redisClient = getRedisClient();
      let userIds = new Set();
      
      if (redisClient) {
        // Get users from Redis set
        const redisUserIds = await redisClient.sMembers(`${this.REDIS_KEYS.ROOM_PRESENCE}${roomId}`);
        redisUserIds.forEach(id => userIds.add(id));
      }
      
      // Get presence for each user
      const presences = [];
      for (const userId of userIds) {
        const presence = await this.getPresence(userId);
        if (presence) {
          presences.push(presence);
        }
      }
      
      // Sort by status (online first) then last seen
      presences.sort((a, b) => {
        if (a.status === b.status) {
          return new Date(b.lastSeen) - new Date(a.lastSeen);
        }
        return this.getStatusPriority(a.status) - this.getStatusPriority(b.status);
      });
      
      return presences;
    } catch (error) {
      console.error('Get room presence error:', error);
      return [];
    }
  }

  /**
   * Get multiple users presence
   */
  async getBulkPresence(userIds) {
    try {
      const presences = [];
      
      for (const userId of userIds) {
        const presence = await this.getPresence(userId);
        presences.push(presence);
      }
      
      return presences;
    } catch (error) {
      console.error('Get bulk presence error:', error);
      return userIds.map(userId => ({
        userId,
        status: this.STATUS.OFFLINE,
        lastSeen: null,
        updatedAt: Date.now()
      }));
    }
  }

  /**
   * Get active sessions for user
   */
  async getUserSessions(userId) {
    try {
      const sessions = await Session.findByUser(userId);
      
      return sessions.map(session => ({
        sessionId: session.session_id,
        deviceInfo: session.user_agent_hash ? 'Web Client' : 'Unknown',
        ipHash: session.ip_hash,
        lastActivity: session.last_activity || session.created_at,
        expiresAt: session.expires_at,
        isActive: session.is_active
      }));
    } catch (error) {
      console.error('Get user sessions error:', error);
      return [];
    }
  }

  /**
   * Clean up stale presence data
   */
  async cleanupStalePresence() {
    try {
      const now = Date.now();
      const staleThreshold = 30 * 60 * 1000; // 30 minutes
      
      // Clean memory store
      for (const [userId, presence] of this.presenceStore.entries()) {
        if (now - presence.updatedAt > staleThreshold) {
          this.presenceStore.delete(userId);
        }
      }
      
      // Clean activity store
      for (const [userId, activity] of this.activityStore.entries()) {
        if (now - activity.updatedAt > 30000) { // 30 seconds for activity
          this.activityStore.delete(userId);
        }
      }
      
      // Clean Redis if available
      const redisClient = getRedisClient();
      if (redisClient) {
        // Redis TTL handles expiration automatically
        console.log('🧹 Cleaned up stale presence data');
      }
      
      return {
        memoryPresenceCleaned: this.presenceStore.size,
        memoryActivityCleaned: this.activityStore.size,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Cleanup stale presence error:', error);
      throw error;
    }
  }

  /**
   * Start automatic cleanup
   */
  startCleanup() {
    setInterval(() => {
      this.cleanupStalePresence().catch(console.error);
    }, this.cleanupInterval);
  }

  /**
   * Get presence statistics
   */
  async getStatistics() {
    try {
      const redisClient = getRedisClient();
      
      let totalOnline = 0;
      let totalAway = 0;
      let totalBusy = 0;
      let totalOffline = 0;
      
      // Count from memory store
      for (const presence of this.presenceStore.values()) {
        switch (presence.status) {
          case this.STATUS.ONLINE:
            totalOnline++;
            break;
          case this.STATUS.AWAY:
            totalAway++;
            break;
          case this.STATUS.BUSY:
            totalBusy++;
            break;
          case this.STATUS.OFFLINE:
            totalOffline++;
            break;
        }
      }
      
      return {
        online: totalOnline,
        away: totalAway,
        busy: totalBusy,
        offline: totalOffline,
        total: totalOnline + totalAway + totalBusy + totalOffline,
        memoryStoreSize: this.presenceStore.size,
        activityStoreSize: this.activityStore.size,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Get presence statistics error:', error);
      return {
        online: 0,
        away: 0,
        busy: 0,
        offline: 0,
        total: 0,
        memoryStoreSize: 0,
        activityStoreSize: 0,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Helper: Get status priority for sorting
   */
  getStatusPriority(status) {
    const priorities = {
      [this.STATUS.ONLINE]: 1,
      [this.STATUS.BUSY]: 2,
      [this.STATUS.AWAY]: 3,
      [this.STATUS.OFFLINE]: 4
    };
    
    return priorities[status] || 4;
  }

  /**
   * Broadcast presence update to room
   */
  async broadcastPresenceToRoom(roomId, userId, status) {
    try {
      const presence = await this.getPresence(userId);
      
      // Get WebSocket service
      const websocketService = require('./websocket');
      
      // Broadcast to room via WebSocket
      await websocketService.broadcastToRoom(roomId, {
        type: 'presence_update',
        data: {
          userId,
          status: presence.status,
          customStatus: presence.customStatus,
          lastSeen: presence.lastSeen,
          timestamp: new Date().toISOString()
        }
      });
      
      return true;
    } catch (error) {
      console.error('Broadcast presence error:', error);
      return false;
    }
  }

  /**
   * Set user as typing in room
   */
  async setTyping(userId, roomId, isTyping = true) {
    try {
      if (isTyping) {
        await this.updateActivity(userId, 'typing', { roomId });
      } else {
        this.activityStore.delete(userId);
        
        const redisClient = getRedisClient();
        if (redisClient) {
          await redisClient.del(`${this.REDIS_KEYS.ACTIVITY}${userId}`);
        }
      }
      
      // Broadcast typing indicator
      const websocketService = require('./websocket');
      await websocketService.broadcastToRoom(roomId, {
        type: 'typing_indicator',
        data: {
          userId,
          roomId,
          isTyping,
          timestamp: new Date().toISOString()
        }
      }, []); // Broadcast to all in room
      
      return true;
    } catch (error) {
      console.error('Set typing error:', error);
      return false;
    }
  }

  /**
   * Get typing users in room
   */
  async getTypingUsers(roomId) {
    try {
      const typingUsers = [];
      
      // Check memory store
      for (const [userId, activity] of this.activityStore.entries()) {
        if (activity.type === 'typing' && activity.data.roomId === roomId) {
          // Check if activity is recent (last 10 seconds)
          if (Date.now() - activity.updatedAt < 10000) {
            typingUsers.push({
              userId,
              startedAt: activity.timestamp,
              lastActivity: activity.updatedAt
            });
          }
        }
      }
      
      return typingUsers;
    } catch (error) {
      console.error('Get typing users error:', error);
      return [];
    }
  }
}

module.exports = new PresenceService();