const crypto = require('crypto');
const User = require('../models/User');
const Session = require('../models/Session');
const { query } = require('../config/database');

/**
 * Authentication Controller
 * Handles user registration, login, session management, and key exchange
 * Note: No real identities are stored or verified
 */

class AuthController {
  /**
   * Register a new anonymous user
   */
  async register({
    username,
    salt,
    publicKey,
    isEphemeral = true,
    preKeys = [],
    signedPreKey = null,
    identityKey = null,
    userAgent = null,
    ip = null
  }) {
    try {
      // Generate identity key if not provided
      if (!identityKey) {
        identityKey = crypto.randomBytes(32).toString('base64');
      }
      
      // Create user in database
      const user = await User.create(
        username,
        publicKey,
        isEphemeral,
        salt
      );
      
      // Update user with cryptographic keys
      const updates = [];
      
      if (signedPreKey) {
        updates.push(User.updateSignedPreKey(user.user_id, signedPreKey));
      }
      
      if (identityKey) {
        // Store identity key in metadata for now
        await query(
          'UPDATE users SET metadata = jsonb_set(metadata, \'{identityKey}\', $1) WHERE user_id = $2',
          [JSON.stringify(identityKey), user.user_id]
        );
      }
      
      if (preKeys.length > 0) {
        updates.push(User.addPreKeys(user.user_id, preKeys));
      }
      
      await Promise.all(updates);
      
      // Generate session
      const sessionKey = Session.generateSessionKey();
      const session = await Session.create({
        userId: user.user_id,
        sessionKey,
        ip,
        userAgent,
        ttlSeconds: isEphemeral ? 3600 : 86400 // 1 hour for ephemeral, 24 hours for persistent
      });
      
      // Generate IDs for stored pre-keys
      const preKeyIds = preKeys.map((_, index) => index);
      
      return {
        user,
        session,
        sessionKey,
        preKeyIds
      };
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  }

  /**
   * Login existing user
   */
  async login({
    username,
    sessionKey,
    userAgent = null,
    ip = null
  }) {
    try {
      // Find user by username (need to try with known salts)
      // In production, we'd need a different approach for username lookup
      // This is simplified - in reality we'd need the salt from registration
      const users = await query(
        `SELECT * FROM users 
         WHERE username_hash = $1 
         AND (is_ephemeral = FALSE OR last_seen > NOW() - INTERVAL '24 hours')
         LIMIT 1`,
        [User.hashUsername(username, '')] // Simplified - need salt from client
      );
      
      if (users.rows.length === 0) {
        return null;
      }
      
      const user = users.rows[0];
      
      // Invalidate old sessions if this is an ephemeral user
      if (user.is_ephemeral) {
        await Session.invalidateAllForUser(user.user_id);
      }
      
      // Create new session
      const newSessionKey = Session.generateSessionKey();
      const session = await Session.create({
        userId: user.user_id,
        sessionKey: newSessionKey,
        ip,
        userAgent,
        ttlSeconds: user.is_ephemeral ? 3600 : 86400
      });
      
      // Update last seen
      await User.updateLastSeen(user.user_id);
      
      // Check if keys need refreshing
      const needsKeyRefresh = await this.checkKeysNeedRefresh(user.user_id);
      
      return {
        user,
        session,
        newSessionKey,
        needsKeyRefresh
      };
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  }

  /**
   * Logout user
   */
  async logout({ sessionId, userId }) {
    try {
      if (sessionId) {
        // Invalidate specific session
        await Session.invalidate(sessionId);
      } else if (userId) {
        // Invalidate all sessions for user
        await Session.invalidateAllForUser(userId);
      }
      
      return true;
    } catch (error) {
      console.error('Logout error:', error);
      throw error;
    }
  }

  /**
   * Refresh session with new key
   */
  async refreshSession({ sessionId, userId, userAgent = null, ip = null }) {
    try {
      // Verify old session is valid
      const oldSession = await Session.findById(sessionId);
      if (!oldSession || oldSession.user_id !== userId) {
        throw new Error('Invalid session');
      }
      
      // Invalidate old session
      await Session.invalidate(sessionId);
      
      // Create new session
      const sessionKey = Session.generateSessionKey();
      const session = await Session.create({
        userId,
        sessionKey,
        ip,
        userAgent,
        ttlSeconds: oldSession.is_ephemeral ? 3600 : 86400
      });
      
      return {
        session,
        sessionKey
      };
    } catch (error) {
      console.error('Session refresh error:', error);
      throw error;
    }
  }

  /**
   * Verify session validity
   */
  async verifySession({ sessionId, userId }) {
    try {
      const session = await Session.findById(sessionId);
      
      if (!session || session.user_id !== userId) {
        return false;
      }
      
      // Update last activity
      await Session.updateLastActivity(sessionId);
      
      // Update user last seen
      await User.updateLastSeen(userId);
      
      return true;
    } catch (error) {
      console.error('Session verification error:', error);
      return false;
    }
  }

  /**
   * Update user's encryption keys
   */
  async updateKeys({
    userId,
    publicKey = null,
    signedPreKey = null,
    preKeys = [],
    oneTimeKeys = []
  }) {
    try {
      const updates = [];
      const results = {
        updated: [],
        preKeyIds: [],
        oneTimeKeyIds: []
      };
      
      if (publicKey) {
        updates.push(User.updatePublicKey(userId, publicKey));
        results.updated.push('publicKey');
      }
      
      if (signedPreKey) {
        updates.push(User.updateSignedPreKey(userId, signedPreKey));
        results.updated.push('signedPreKey');
      }
      
      if (preKeys.length > 0) {
        updates.push(User.addPreKeys(userId, preKeys));
        results.preKeyIds = preKeys.map((_, index) => index);
      }
      
      if (oneTimeKeys.length > 0) {
        updates.push(User.addOneTimeKeys(userId, oneTimeKeys));
        results.oneTimeKeyIds = oneTimeKeys.map((_, index) => index);
      }
      
      await Promise.all(updates);
      
      // Update last seen
      await User.updateLastSeen(userId);
      
      return results;
    } catch (error) {
      console.error('Key update error:', error);
      throw error;
    }
  }

  /**
   * Get keys for encrypted message exchange (X3DH)
   */
  async getKeysForExchange({
    userId,
    requesterId,
    ephemeralKey,
    preKeyId = null,
    oneTimeKeyId = null
  }) {
    try {
      // Verify user exists and is active
      const user = await User.findById(userId);
      if (!user) {
        return null;
      }
      
      // Get identity key
      const identityKey = await User.getIdentityKey(userId);
      
      // Get signed pre-key
      const signedPreKey = await User.getSignedPreKey(userId);
      
      // Get a pre-key
      let preKey = null;
      let usedPreKeyId = preKeyId;
      
      if (preKeyId !== null) {
        // Client specified which pre-key to use
        // This would require additional logic to retrieve specific pre-key
        preKey = 'specified-pre-key'; // Placeholder
      } else {
        // Consume next available pre-key
        preKey = await User.consumePreKey(userId);
        if (preKey) {
          // We need to track which pre-key ID was used
          usedPreKeyId = 0; // Simplified - need proper tracking
        }
      }
      
      // Get one-time key if requested
      let oneTimeKey = null;
      let usedOneTimeKeyId = oneTimeKeyId;
      
      if (oneTimeKeyId !== null) {
        // Client specified which one-time key to use
        oneTimeKey = 'specified-one-time-key'; // Placeholder
      } else if (preKey) {
        // Try to consume a one-time key
        oneTimeKey = await User.consumeOneTimeKey(userId);
        if (oneTimeKey) {
          usedOneTimeKeyId = 0; // Simplified - need proper tracking
        }
      }
      
      if (!preKey && !oneTimeKey) {
        // No keys available for exchange
        return null;
      }
      
      // In a real implementation, we would sign the bundle
      // For now, return placeholder signature
      const signature = crypto.randomBytes(64).toString('base64');
      
      return {
        identityKey,
        signedPreKey,
        preKey,
        oneTimeKey,
        preKeyId: usedPreKeyId,
        oneTimeKeyId: usedOneTimeKeyId,
        signature
      };
    } catch (error) {
      console.error('Key exchange error:', error);
      throw error;
    }
  }

  /**
   * Get pre-key bundle for user (anonymous access)
   */
  async getPreKeyBundle(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        return null;
      }
      
      // Get identity key
      const identityKey = await User.getIdentityKey(userId);
      
      // Get signed pre-key
      const signedPreKey = await User.getSignedPreKey(userId);
      
      // Get a pre-key
      const preKey = await User.consumePreKey(userId);
      if (!preKey) {
        return null;
      }
      
      // Generate signature (simplified)
      const signature = crypto.randomBytes(64).toString('base64');
      
      return {
        identityKey,
        signedPreKey,
        preKey,
        preKeyId: 0, // Simplified
        signature
      };
    } catch (error) {
      console.error('Pre-key bundle error:', error);
      throw error;
    }
  }

  /**
   * Delete user account and all data
   */
  async deleteAccount({ userId, sessionId }) {
    try {
      // Start transaction
      const client = await query.getClient();
      
      try {
        await client.query('BEGIN');
        
        // Invalidate all sessions
        await client.query(
          'UPDATE sessions SET is_active = FALSE WHERE user_id = $1',
          [userId]
        );
        
        // Delete room memberships
        await client.query(
          'DELETE FROM room_members WHERE user_id = $1',
          [userId]
        );
        
        // Delete messages sent by user
        await client.query(
          'UPDATE messages SET deleted_at = NOW() WHERE sender_id = $1',
          [userId]
        );
        
        // Delete user
        await client.query(
          'DELETE FROM users WHERE user_id = $1',
          [userId]
        );
        
        await client.query('COMMIT');
        
        return true;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Account deletion error:', error);
      throw error;
    }
  }

  /**
   * Check if user's keys need refreshing
   */
  async checkKeysNeedRefresh(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        return false;
      }
      
      // Check pre-key count
      const preKeyCount = user.pre_keys?.length || 0;
      if (preKeyCount < 10) {
        return true;
      }
      
      // Check one-time key count
      const oneTimeKeyCount = user.one_time_keys?.length || 0;
      if (oneTimeKeyCount < 5) {
        return true;
      }
      
      // Check key age (simplified)
      const keyAge = Date.now() - new Date(user.last_seen).getTime();
      if (keyAge > 7 * 24 * 60 * 60 * 1000) { // 7 days
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('Key refresh check error:', error);
      return false;
    }
  }

  /**
   * Health check for authentication service
   */
  async healthCheck() {
    try {
      // Test database connection
      await query('SELECT 1');
      
      // Test session cleanup
      const cleanupCount = await Session.cleanupExpired();
      
      // Test user cleanup
      const userCleanupCount = await User.cleanupEphemeralUsers();
      
      return {
        database: 'connected',
        sessionsCleaned: cleanupCount,
        usersCleaned: userCleanupCount,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Auth health check error:', error);
      throw error;
    }
  }

  /**
   * Generate invitation for private room
   */
  async generateInvitation({
    roomId,
    senderId,
    recipientHash,
    ttlHours = 24
  }) {
    try {
      // Generate secure invitation key
      const invitationKey = crypto.randomBytes(32).toString('base64');
      
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
      console.error('Invitation generation error:', error);
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
      console.error('Invitation validation error:', error);
      throw error;
    }
  }
}

module.exports = new AuthController();