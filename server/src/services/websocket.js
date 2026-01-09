const WebSocket = require('ws');
const crypto = require('crypto');
const { getRedisPublisher, getRedisSubscriber, getRedisClient } = require('../config/database');
const Session = require('../models/Session');
const User = require('../models/User');
const Message = require('../models/Message');
const Room = require('../models/Room');
const securityMiddleware = require('../middleware/security');

/**
 * WebSocket Service
 * Handles real-time communication for the chat system
 */

class WebSocketService {
  constructor() {
    this.wss = null;
    this.clients = new Map(); // websocketId -> { ws, userId, sessionId }
    this.userConnections = new Map(); // userId -> Set(websocketId)
    this.roomSubscriptions = new Map(); // roomId -> Set(websocketId)
    
    // Heartbeat intervals
    this.heartbeatInterval = 30000; // 30 seconds
    this.connectionTimeout = 45000; // 45 seconds
    
    // Redis channels
    this.REDIS_CHANNELS = {
      PRESENCE: 'presence',
      MESSAGES: 'messages',
      ROOM_UPDATES: 'room_updates',
      USER_UPDATES: 'user_updates'
    };
  }

  /**
   * Initialize WebSocket server
   */
  initialize(wss) {
    this.wss = wss;
    
    this.setupEventHandlers();
    this.setupRedisPubSub();
    this.startHeartbeat();
    
    console.log('✅ WebSocket service initialized');
  }

  /**
   * Setup WebSocket event handlers
   */
  setupEventHandlers() {
    this.wss.on('connection', async (ws, req) => {
      try {
        // Authenticate connection
        const authData = await securityMiddleware.authenticateWebSocket(ws, req);
        if (!authData) {
          return;
        }
        
        const { sessionId, userId, usernameHash, isEphemeral, websocketId } = authData;
        
        // Store connection
        this.clients.set(websocketId, {
          ws,
          userId,
          sessionId,
          usernameHash,
          isEphemeral,
          lastActivity: Date.now(),
          subscriptions: new Set()
        });
        
        // Track user connections
        if (!this.userConnections.has(userId)) {
          this.userConnections.set(userId, new Set());
        }
        this.userConnections.get(userId).add(websocketId);
        
        // Setup message handler
        ws.on('message', (data) => this.handleMessage(websocketId, data));
        
        // Setup close handler
        ws.on('close', () => this.handleDisconnect(websocketId));
        
        // Setup error handler
        ws.on('error', (error) => this.handleError(websocketId, error));
        
        // Send connection confirmation
        this.sendToClient(websocketId, {
          type: 'connection_established',
          data: {
            websocketId,
            timestamp: new Date().toISOString()
          }
        });
        
        // Broadcast presence
        await this.broadcastPresence(userId, 'online');
        
        console.log(`🔗 WebSocket connected: ${userId} (${websocketId})`);
      } catch (error) {
        console.error('WebSocket connection error:', error);
        ws.close(1011, 'Connection error');
      }
    });
  }

  /**
   * Setup Redis Pub/Sub for distributed WebSocket messaging
   */
  async setupRedisPubSub() {
    try {
      const redisSubscriber = getRedisSubscriber();
      const redisPublisher = getRedisPublisher();
      
      if (!redisSubscriber || !redisPublisher) {
        console.warn('Redis not available, using local WebSocket broadcasting only');
        return;
      }
      
      // Subscribe to channels
      await redisSubscriber.subscribe(
        this.REDIS_CHANNELS.PRESENCE,
        this.REDIS_CHANNELS.MESSAGES,
        this.REDIS_CHANNELS.ROOM_UPDATES,
        this.REDIS_CHANNELS.USER_UPDATES,
        (message, channel) => this.handleRedisMessage(channel, message)
      );
      
      this.redisPublisher = redisPublisher;
      this.redisSubscriber = redisSubscriber;
      
      console.log('✅ Redis Pub/Sub initialized for WebSocket');
    } catch (error) {
      console.error('Redis Pub/Sub setup error:', error);
    }
  }

  /**
   * Handle incoming WebSocket messages
   */
  async handleMessage(websocketId, rawData) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    try {
      // Update last activity
      client.lastActivity = Date.now();
      
      // Parse message
      const message = this.parseMessage(rawData);
      if (!message) {
        this.sendError(websocketId, 'Invalid message format');
        return;
      }
      
      // Validate message structure
      if (!message.type || !message.data) {
        this.sendError(websocketId, 'Missing message type or data');
        return;
      }
      
      // Route message based on type
      switch (message.type) {
        case 'ping':
          this.handlePing(websocketId, message.data);
          break;
        
        case 'subscribe':
          await this.handleSubscribe(websocketId, message.data);
          break;
        
        case 'unsubscribe':
          await this.handleUnsubscribe(websocketId, message.data);
          break;
        
        case 'message':
          await this.handleChatMessage(websocketId, message.data);
          break;
        
        case 'typing':
          await this.handleTyping(websocketId, message.data);
          break;
        
        case 'presence':
          await this.handlePresence(websocketId, message.data);
          break;
        
        case 'room_invite':
          await this.handleRoomInvite(websocketId, message.data);
          break;
        
        default:
          this.sendError(websocketId, `Unknown message type: ${message.type}`);
      }
    } catch (error) {
      console.error('Message handling error:', {
        websocketId,
        userId: client.userId,
        error: error.message
      });
      
      this.sendError(websocketId, 'Message processing failed');
    }
  }

  /**
   * Handle ping message (heartbeat)
   */
  handlePing(websocketId, data) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    client.lastActivity = Date.now();
    
    this.sendToClient(websocketId, {
      type: 'pong',
      data: {
        timestamp: new Date().toISOString(),
        serverTime: Date.now()
      }
    });
  }

  /**
   * Handle room subscription
   */
  async handleSubscribe(websocketId, data) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    const { roomId } = data;
    if (!roomId) {
      this.sendError(websocketId, 'Room ID required');
      return;
    }
    
    // Verify user has access to room
    const hasAccess = await Room.isMember(roomId, client.userId);
    if (!hasAccess) {
      this.sendError(websocketId, 'Access denied to room');
      return;
    }
    
    // Subscribe to room
    client.subscriptions.add(roomId);
    
    if (!this.roomSubscriptions.has(roomId)) {
      this.roomSubscriptions.set(roomId, new Set());
    }
    this.roomSubscriptions.get(roomId).add(websocketId);
    
    // Send subscription confirmation
    this.sendToClient(websocketId, {
      type: 'subscribed',
      data: {
        roomId,
        timestamp: new Date().toISOString()
      }
    });
    
    // Broadcast room join
    await this.broadcastToRoom(roomId, {
      type: 'user_joined',
      data: {
        userId: client.userId,
        usernameHash: client.usernameHash,
        timestamp: new Date().toISOString()
      }
    }, [websocketId]); // Exclude self
  }

  /**
   * Handle room unsubscription
   */
  async handleUnsubscribe(websocketId, data) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    const { roomId } = data;
    if (!roomId) {
      this.sendError(websocketId, 'Room ID required');
      return;
    }
    
    // Unsubscribe from room
    client.subscriptions.delete(roomId);
    
    const roomSubs = this.roomSubscriptions.get(roomId);
    if (roomSubs) {
      roomSubs.delete(websocketId);
      if (roomSubs.size === 0) {
        this.roomSubscriptions.delete(roomId);
      }
    }
    
    // Send unsubscription confirmation
    this.sendToClient(websocketId, {
      type: 'unsubscribed',
      data: {
        roomId,
        timestamp: new Date().toISOString()
      }
    });
  }

  /**
   * Handle chat message
   */
  async handleChatMessage(websocketId, data) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    const { roomId, encryptedContent, metadata, messageType = 'text' } = data;
    
    if (!roomId || !encryptedContent) {
      this.sendError(websocketId, 'Room ID and content required');
      return;
    }
    
    // Verify user has access to room
    const hasAccess = await Room.isMember(roomId, client.userId);
    if (!hasAccess) {
      this.sendError(websocketId, 'Access denied to room');
      return;
    }
    
    // Check rate limiting
    const canSend = await this.checkRateLimit(client.userId, roomId);
    if (!canSend) {
      this.sendError(websocketId, 'Rate limit exceeded');
      return;
    }
    
    // Store message in database
    const message = await Message.create({
      roomId,
      senderId: client.userId,
      encryptedContent,
      messageType,
      metadata: metadata || {}
    });
    
    // Broadcast message to room
    await this.broadcastToRoom(roomId, {
      type: 'message',
      data: {
        messageId: message.message_id,
        roomId,
        senderId: client.userId,
        senderUsernameHash: client.usernameHash,
        encryptedContent,
        contentHash: message.content_hash,
        metadata: message.metadata,
        messageType,
        sequenceNumber: message.sequence_number,
        createdAt: message.created_at
      }
    });
    
    // Update user last seen
    await User.updateLastSeen(client.userId);
  }

  /**
   * Handle typing indicator
   */
  async handleTyping(websocketId, data) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    const { roomId, isTyping } = data;
    
    if (!roomId) {
      this.sendError(websocketId, 'Room ID required');
      return;
    }
    
    // Verify user has access to room
    const hasAccess = await Room.isMember(roomId, client.userId);
    if (!hasAccess) {
      this.sendError(websocketId, 'Access denied to room');
      return;
    }
    
    // Broadcast typing indicator
    await this.broadcastToRoom(roomId, {
      type: 'typing',
      data: {
        userId: client.userId,
        usernameHash: client.usernameHash,
        roomId,
        isTyping: !!isTyping,
        timestamp: new Date().toISOString()
      }
    }, [websocketId]); // Exclude self
  }

  /**
   * Handle presence updates
   */
  async handlePresence(websocketId, data) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    const { status, customStatus } = data;
    
    if (!status || !['online', 'away', 'busy', 'offline'].includes(status)) {
      this.sendError(websocketId, 'Invalid presence status');
      return;
    }
    
    // Broadcast presence to subscribed rooms
    for (const roomId of client.subscriptions) {
      await this.broadcastToRoom(roomId, {
        type: 'presence',
        data: {
          userId: client.userId,
          usernameHash: client.usernameHash,
          status,
          customStatus,
          timestamp: new Date().toISOString()
        }
      }, [websocketId]); // Exclude self
    }
  }

  /**
   * Handle room invitation
   */
  async handleRoomInvite(websocketId, data) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    const { roomId, targetUsername, invitationKey } = data;
    
    if (!roomId || !targetUsername || !invitationKey) {
      this.sendError(websocketId, 'Room ID, username, and invitation key required');
      return;
    }
    
    // Verify user is admin of room
    const isAdmin = await Room.isAdmin(roomId, client.userId);
    if (!isAdmin) {
      this.sendError(websocketId, 'Only room admins can invite users');
      return;
    }
    
    // Find target user
    const targetUser = await User.findByUsernameHash(
      User.hashUsername(targetUsername, '')
    );
    
    if (!targetUser) {
      this.sendError(websocketId, 'User not found');
      return;
    }
    
    // Check if user is already a member
    const isMember = await Room.isMember(roomId, targetUser.user_id, false);
    if (isMember) {
      this.sendError(websocketId, 'User is already a member of this room');
      return;
    }
    
    // Get room details
    const room = await Room.findById(roomId);
    if (!room) {
      this.sendError(websocketId, 'Room not found');
      return;
    }
    
    // Send invitation to target user
    await this.sendToUser(targetUser.user_id, {
      type: 'room_invitation',
      data: {
        roomId,
        roomNameHash: room.room_name_hash,
        invitationKey,
        invitedBy: client.userId,
        invitedByUsernameHash: client.usernameHash,
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
      }
    });
    
    // Send confirmation to sender
    this.sendToClient(websocketId, {
      type: 'invitation_sent',
      data: {
        roomId,
        targetUserId: targetUser.user_id,
        timestamp: new Date().toISOString()
      }
    });
  }

  /**
   * Handle Redis messages for distributed broadcasting
   */
  async handleRedisMessage(channel, message) {
    try {
      const data = JSON.parse(message);
      
      switch (channel) {
        case this.REDIS_CHANNELS.MESSAGES:
          await this.handleRedisMessageBroadcast(data);
          break;
        
        case this.REDIS_CHANNELS.PRESENCE:
          await this.handleRedisPresenceBroadcast(data);
          break;
        
        case this.REDIS_CHANNELS.ROOM_UPDATES:
          await this.handleRedisRoomUpdate(data);
          break;
        
        case this.REDIS_CHANNELS.USER_UPDATES:
          await this.handleRedisUserUpdate(data);
          break;
      }
    } catch (error) {
      console.error('Redis message handling error:', error);
    }
  }

  /**
   * Broadcast message via Redis
   */
  async publishToRedis(channel, data) {
    try {
      if (this.redisPublisher) {
        await this.redisPublisher.publish(channel, JSON.stringify(data));
      }
    } catch (error) {
      console.error('Redis publish error:', error);
    }
  }

  /**
   * Broadcast message to all clients in a room
   */
  async broadcastToRoom(roomId, message, excludeWebsocketIds = []) {
    // Local broadcast
    const roomSubs = this.roomSubscriptions.get(roomId);
    if (roomSubs) {
      for (const websocketId of roomSubs) {
        if (!excludeWebsocketIds.includes(websocketId)) {
          this.sendToClient(websocketId, message);
        }
      }
    }
    
    // Distributed broadcast via Redis
    await this.publishToRedis(this.REDIS_CHANNELS.MESSAGES, {
      roomId,
      message,
      excludeWebsocketIds,
      serverId: process.env.SERVER_ID || 'local'
    });
  }

  /**
   * Broadcast presence update
   */
  async broadcastPresence(userId, status) {
    const user = await User.findById(userId);
    if (!user) return;
    
    const presenceData = {
      userId,
      usernameHash: user.username_hash,
      status,
      timestamp: new Date().toISOString()
    };
    
    // Local broadcast to user's subscribed rooms
    const userConnections = this.userConnections.get(userId);
    if (userConnections) {
      for (const websocketId of userConnections) {
        const client = this.clients.get(websocketId);
        if (client) {
          for (const roomId of client.subscriptions) {
            await this.broadcastToRoom(roomId, {
              type: 'presence',
              data: presenceData
            }, [websocketId]);
          }
        }
      }
    }
    
    // Distributed broadcast via Redis
    await this.publishToRedis(this.REDIS_CHANNELS.PRESENCE, presenceData);
  }

  /**
   * Send message to specific user
   */
  async sendToUser(userId, message) {
    const userConnections = this.userConnections.get(userId);
    if (userConnections) {
      for (const websocketId of userConnections) {
        this.sendToClient(websocketId, message);
      }
    }
  }

  /**
   * Send message to specific client
   */
  sendToClient(websocketId, message) {
    const client = this.clients.get(websocketId);
    if (!client || client.ws.readyState !== WebSocket.OPEN) {
      return false;
    }
    
    try {
      const data = JSON.stringify(message);
      client.ws.send(data);
      return true;
    } catch (error) {
      console.error('Send to client error:', error);
      this.handleDisconnect(websocketId);
      return false;
    }
  }

  /**
   * Send error to client
   */
  sendError(websocketId, errorMessage, errorCode = 'GENERIC_ERROR') {
    this.sendToClient(websocketId, {
      type: 'error',
      data: {
        code: errorCode,
        message: errorMessage,
        timestamp: new Date().toISOString()
      }
    });
  }

  /**
   * Handle client disconnect
   */
  async handleDisconnect(websocketId) {
    const client = this.clients.get(websocketId);
    if (!client) return;
    
    // Remove from room subscriptions
    for (const roomId of client.subscriptions) {
      const roomSubs = this.roomSubscriptions.get(roomId);
      if (roomSubs) {
        roomSubs.delete(websocketId);
        if (roomSubs.size === 0) {
          this.roomSubscriptions.delete(roomId);
        }
      }
    }
    
    // Remove from user connections
    const userConnections = this.userConnections.get(client.userId);
    if (userConnections) {
      userConnections.delete(websocketId);
      if (userConnections.size === 0) {
        this.userConnections.delete(client.userId);
        
        // Broadcast offline presence if no more connections
        await this.broadcastPresence(client.userId, 'offline');
      }
    }
    
    // Remove client
    this.clients.delete(websocketId);
    
    // Update session
    if (client.sessionId) {
      await Session.updateWebSocketId(client.sessionId, null);
    }
    
    console.log(`🔌 WebSocket disconnected: ${client.userId} (${websocketId})`);
  }

  /**
   * Handle WebSocket error
   */
  handleError(websocketId, error) {
    console.error('WebSocket error:', {
      websocketId,
      error: error.message
    });
    
    this.handleDisconnect(websocketId);
  }

  /**
   * Start heartbeat monitoring
   */
  startHeartbeat() {
    setInterval(() => {
      this.checkHeartbeats();
    }, this.heartbeatInterval);
  }

  /**
   * Check client heartbeats
   */
  checkHeartbeats() {
    const now = Date.now();
    
    for (const [websocketId, client] of this.clients.entries()) {
      if (now - client.lastActivity > this.connectionTimeout) {
        console.log(`💓 Heartbeat timeout: ${websocketId}`);
        client.ws.close(1000, 'Connection timeout');
        this.handleDisconnect(websocketId);
      }
    }
  }

  /**
   * Check message rate limit
   */
  async checkRateLimit(userId, roomId) {
    const key = `rate_limit:${userId}:${roomId}`;
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    const maxMessages = 60; // 60 messages per minute
    
    // This would integrate with Redis in production
    // For now, using simplified in-memory check
    if (!this.rateLimitStore) {
      this.rateLimitStore = new Map();
    }
    
    const record = this.rateLimitStore.get(key) || { count: 0, resetTime: now + windowMs };
    
    if (now > record.resetTime) {
      record.count = 0;
      record.resetTime = now + windowMs;
    }
    
    if (record.count >= maxMessages) {
      return false;
    }
    
    record.count++;
    this.rateLimitStore.set(key, record);
    
    return true;
  }

  /**
   * Parse WebSocket message
   */
  parseMessage(rawData) {
    try {
      if (Buffer.isBuffer(rawData)) {
        rawData = rawData.toString('utf8');
      }
      
      return JSON.parse(rawData);
    } catch (error) {
      return null;
    }
  }

  /**
   * Get connected clients count
   */
  getStats() {
    return {
      totalClients: this.clients.size,
      totalUsers: this.userConnections.size,
      roomSubscriptions: this.roomSubscriptions.size,
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = new WebSocketService();