const { Pool } = require('pg');
const Redis = require('redis');

/**
 * Database configuration with security considerations
 */

// PostgreSQL connection pool
const pgPool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'secure_chat_db',
  user: process.env.DB_USER || 'secure_chat_user',
  password: process.env.DB_PASSWORD,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: true,
    ca: process.env.DB_SSL_CA
  } : false,
  max: 20, // Maximum number of clients in the pool
  min: 4,  // Minimum number of idle clients
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  application_name: 'secure_chat_server'
});

// Redis client for presence and WebSocket management
let redisClient;
let redisPublisher;
let redisSubscriber;

/**
 * Initialize Redis connections
 */
const initRedis = async () => {
  try {
    const redisOptions = {
      socket: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT) || 6379,
        reconnectStrategy: (retries) => {
          const delay = Math.min(retries * 100, 5000);
          return delay;
        }
      }
    };

    if (process.env.REDIS_PASSWORD) {
      redisOptions.password = process.env.REDIS_PASSWORD;
    }

    redisClient = Redis.createClient(redisOptions);
    redisPublisher = Redis.createClient(redisOptions);
    redisSubscriber = Redis.createClient(redisOptions);

    // Error handling
    const handleRedisError = (client, type) => (err) => {
      console.error(`${type} Redis client error:`, err.message);
    };

    redisClient.on('error', handleRedisError(redisClient, 'Main'));
    redisPublisher.on('error', handleRedisError(redisPublisher, 'Publisher'));
    redisSubscriber.on('error', handleRedisError(redisSubscriber, 'Subscriber'));

    // Connect all clients
    await Promise.all([
      redisClient.connect(),
      redisPublisher.connect(),
      redisSubscriber.connect()
    ]);

    console.log('✅ Redis connections established');
    return { redisClient, redisPublisher, redisSubscriber };
  } catch (error) {
    console.error('❌ Failed to connect to Redis:', error);
    throw error;
  }
};

/**
 * Execute database query with error handling
 */
const query = async (text, params) => {
  const start = Date.now();
  try {
    const result = await pgPool.query(text, params);
    const duration = Date.now() - start;
    
    // Log slow queries
    if (duration > 1000) {
      console.warn(`Slow query (${duration}ms):`, { text, params: params?.length });
    }
    
    return result;
  } catch (error) {
    console.error('Database query error:', {
      error: error.message,
      query: text,
      params: params?.length
    });
    throw error;
  }
};

/**
 * Initialize database schema
 */
const initDatabase = async () => {
  try {
    // Enable necessary extensions
    await query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";
      CREATE EXTENSION IF NOT EXISTS "citext";
    `);

    // Create tables if they don't exist
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username_hash VARCHAR(128) UNIQUE NOT NULL,
        username_salt VARCHAR(64) NOT NULL,
        public_key TEXT NOT NULL,
        identity_key TEXT,
        signed_pre_key TEXT,
        pre_keys TEXT[] DEFAULT '{}',
        one_time_keys TEXT[] DEFAULT '{}',
        is_ephemeral BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_seen TIMESTAMPTZ,
        metadata JSONB DEFAULT '{}'
      );

      CREATE TABLE IF NOT EXISTS sessions (
        session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        session_key_hash VARCHAR(128) NOT NULL,
        websocket_id VARCHAR(256),
        ip_hash VARCHAR(128),
        user_agent_hash VARCHAR(128),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        last_activity TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(session_key_hash)
      );

      CREATE TABLE IF NOT EXISTS rooms (
        room_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        room_name_hash VARCHAR(128),
        room_salt VARCHAR(64),
        is_private BOOLEAN DEFAULT FALSE,
        created_by UUID REFERENCES users(user_id),
        ephemeral_key TEXT,
        members JSONB DEFAULT '[]',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        archived_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS messages (
        message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        room_id UUID NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
        sender_id UUID NOT NULL REFERENCES users(user_id),
        encrypted_content TEXT NOT NULL,
        content_hash VARCHAR(128) NOT NULL,
        metadata JSONB DEFAULT '{}',
        message_type VARCHAR(32) DEFAULT 'text',
        sequence_number BIGINT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        deleted_at TIMESTAMPTZ,
        INDEX idx_room_created (room_id, created_at DESC),
        INDEX idx_sender_room (sender_id, room_id)
      );

      CREATE TABLE IF NOT EXISTS room_members (
        room_id UUID REFERENCES rooms(room_id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
        joined_at TIMESTAMPTZ DEFAULT NOW(),
        left_at TIMESTAMPTZ,
        role VARCHAR(32) DEFAULT 'member',
        is_active BOOLEAN DEFAULT TRUE,
        PRIMARY KEY (room_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS invitations (
        invitation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        room_id UUID REFERENCES rooms(room_id) ON DELETE CASCADE,
        sender_id UUID REFERENCES users(user_id),
        recipient_hash VARCHAR(128),
        invitation_key TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Create indexes for performance
    await query(`
      CREATE INDEX IF NOT EXISTS idx_users_username_hash ON users(username_hash);
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at) WHERE is_active = TRUE;
      CREATE INDEX IF NOT EXISTS idx_messages_room_sequence ON messages(room_id, sequence_number);
      CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id, is_active);
      CREATE INDEX IF NOT EXISTS idx_invitations_expires ON invitations(expires_at, used_at);
    `);

    console.log('✅ Database schema initialized');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
};

/**
 * Health check for database connections
 */
const healthCheck = async () => {
  try {
    // Check PostgreSQL
    await pgPool.query('SELECT 1');
    
    // Check Redis
    if (redisClient) {
      await redisClient.ping();
    }
    
    return {
      postgres: 'healthy',
      redis: redisClient ? 'healthy' : 'not_initialized',
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('Health check failed:', error);
    return {
      postgres: 'unhealthy',
      redis: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
};

module.exports = {
  query,
  initDatabase,
  initRedis,
  healthCheck,
  getRedisClient: () => redisClient,
  getRedisPublisher: () => redisPublisher,
  getRedisSubscriber: () => redisSubscriber,
  pgPool
};