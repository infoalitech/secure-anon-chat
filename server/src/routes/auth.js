const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const authController = require('../controllers/authController');
const securityMiddleware = require('../middleware/security');
const validationMiddleware = require('../middleware/validation');

/**
 * Authentication routes for anonymous chat system
 * Note: No real identities are stored or verified
 */

// Validation schemas
const authValidation = {
  register: [
    body('username')
      .trim()
      .isLength({ min: 3, max: 32 })
      .withMessage('Username must be 3-32 characters')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Username can only contain letters, numbers, underscores, and dashes')
      .custom(value => {
        // Disallow common/reserved usernames
        const disallowed = ['admin', 'system', 'root', 'moderator', 'anonymous', 'null', 'undefined'];
        if (disallowed.includes(value.toLowerCase())) {
          throw new Error('This username is not allowed');
        }
        return true;
      }),
    body('publicKey')
      .trim()
      .isLength({ min: 64, max: 1024 })
      .withMessage('Invalid public key format')
      .matches(/^[A-Za-z0-9+/=]+$/)
      .withMessage('Public key must be base64 encoded'),
    body('isEphemeral')
      .optional()
      .isBoolean()
      .withMessage('isEphemeral must be boolean'),
    body('preKeys')
      .optional()
      .isArray()
      .withMessage('preKeys must be an array'),
    body('signedPreKey')
      .optional()
      .isString()
      .withMessage('signedPreKey must be string'),
    body('identityKey')
      .optional()
      .isString()
      .withMessage('identityKey must be string')
  ],
  
  login: [
    body('username')
      .trim()
      .isLength({ min: 3, max: 32 })
      .withMessage('Username must be 3-32 characters'),
    body('sessionKey')
      .trim()
      .isLength({ min: 64, max: 512 })
      .withMessage('Invalid session key format')
  ],
  
  logout: [
    body('sessionId')
      .optional()
      .isUUID()
      .withMessage('Invalid session ID format'),
    body('sessionKey')
      .optional()
      .isString()
      .withMessage('Session key is required')
  ],
  
  keyExchange: [
    body('userId')
      .isUUID()
      .withMessage('Invalid user ID format'),
    body('ephemeralKey')
      .isString()
      .withMessage('Ephemeral key is required'),
    body('preKeyId')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Invalid pre-key ID'),
    body('oneTimeKeyId')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Invalid one-time key ID')
  ]
};

/**
 * @route   POST /api/auth/register
 * @desc    Register a new anonymous user
 * @access  Public
 * @security No PII stored, only cryptographic identifiers
 */
router.post(
  '/register',
  securityMiddleware.rateLimit.auth,
  authValidation.register,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      // Generate random salt for username hashing
      const salt = crypto.randomBytes(32).toString('hex');
      
      const result = await authController.register({
        username: req.body.username,
        salt: salt,
        publicKey: req.body.publicKey,
        isEphemeral: req.body.isEphemeral !== false, // Default to true
        preKeys: req.body.preKeys || [],
        signedPreKey: req.body.signedPreKey,
        identityKey: req.body.identityKey,
        userAgent: req.headers['user-agent'],
        ip: req.ip
      });
      
      res.status(201).json({
        success: true,
        data: {
          userId: result.user.user_id,
          sessionId: result.session.session_id,
          sessionKey: result.sessionKey, // Only returned once
          salt: salt, // Return salt for client to hash future logins
          isEphemeral: result.user.is_ephemeral,
          publicKey: result.user.public_key,
          identityKey: result.user.identity_key,
          signedPreKey: result.user.signed_pre_key,
          preKeyIds: result.preKeyIds // Return IDs of stored pre-keys
        }
      });
    } catch (error) {
      console.error('Registration error:', {
        error: error.message,
        ipHash: securityMiddleware.hashIP(req.ip)
      });
      
      if (error.message === 'Username already exists') {
        return res.status(409).json({
          success: false,
          error: 'Username already exists'
        });
      }
      
      res.status(500).json({
        success: false,
        error: 'Registration failed'
      });
    }
  }
);

/**
 * @route   POST /api/auth/login
 * @desc    Login existing user
 * @access  Public
 * @security Session-based with ephemeral keys
 */
router.post(
  '/login',
  securityMiddleware.rateLimit.auth,
  authValidation.login,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const result = await authController.login({
        username: req.body.username,
        sessionKey: req.body.sessionKey,
        userAgent: req.headers['user-agent'],
        ip: req.ip
      });
      
      if (!result) {
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }
      
      res.json({
        success: true,
        data: {
          userId: result.user.user_id,
          sessionId: result.session.session_id,
          sessionKey: result.newSessionKey, // New session key for this login
          isEphemeral: result.user.is_ephemeral,
          publicKey: result.user.public_key,
          identityKey: result.user.identity_key,
          signedPreKey: result.user.signed_pre_key,
          needsKeyRefresh: result.needsKeyRefresh
        }
      });
    } catch (error) {
      console.error('Login error:', {
        error: error.message,
        ipHash: securityMiddleware.hashIP(req.ip)
      });
      
      res.status(401).json({
        success: false,
        error: 'Authentication failed'
      });
    }
  }
);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user and invalidate session
 * @access  Private
 * @security Clears all session data
 */
router.post(
  '/logout',
  securityMiddleware.authenticate,
  authValidation.logout,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      await authController.logout({
        sessionId: req.body.sessionId || req.session.sessionId,
        userId: req.user.user_id
      });
      
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      console.error('Logout error:', {
        error: error.message,
        userId: req.user?.user_id
      });
      
      res.status(500).json({
        success: false,
        error: 'Logout failed'
      });
    }
  }
);

/**
 * @route   POST /api/auth/session/refresh
 * @desc    Refresh session with new key
 * @access  Private
 * @security Rotates session keys
 */
router.post(
  '/session/refresh',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const result = await authController.refreshSession({
        sessionId: req.session.sessionId,
        userId: req.user.user_id,
        userAgent: req.headers['user-agent'],
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: {
          sessionId: result.session.session_id,
          sessionKey: result.sessionKey, // New session key
          expiresAt: result.session.expires_at
        }
      });
    } catch (error) {
      console.error('Session refresh error:', {
        error: error.message,
        userId: req.user?.user_id
      });
      
      res.status(401).json({
        success: false,
        error: 'Session refresh failed'
      });
    }
  }
);

/**
 * @route   GET /api/auth/session/verify
 * @desc    Verify current session
 * @access  Private
 * @security Validates session without exposing details
 */
router.get(
  '/session/verify',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      const isValid = await authController.verifySession({
        sessionId: req.session.sessionId,
        userId: req.user.user_id
      });
      
      if (!isValid) {
        return res.status(401).json({
          success: false,
          error: 'Session invalid'
        });
      }
      
      res.json({
        success: true,
        data: {
          userId: req.user.user_id,
          usernameHash: req.user.username_hash,
          isEphemeral: req.user.is_ephemeral,
          sessionExpiresAt: req.session.expires_at,
          publicKey: req.user.public_key
        }
      });
    } catch (error) {
      console.error('Session verification error:', {
        error: error.message,
        userId: req.user?.user_id
      });
      
      res.status(401).json({
        success: false,
        error: 'Session verification failed'
      });
    }
  }
);

/**
 * @route   POST /api/auth/keys/update
 * @desc    Update user's encryption keys
 * @access  Private
 * @security Allows key rotation
 */
router.post(
  '/keys/update',
  securityMiddleware.authenticate,
  [
    body('publicKey')
      .optional()
      .isString()
      .withMessage('Public key must be string'),
    body('signedPreKey')
      .optional()
      .isString()
      .withMessage('Signed pre-key must be string'),
    body('preKeys')
      .optional()
      .isArray()
      .withMessage('Pre-keys must be array'),
    body('oneTimeKeys')
      .optional()
      .isArray()
      .withMessage('One-time keys must be array')
  ],
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const result = await authController.updateKeys({
        userId: req.user.user_id,
        publicKey: req.body.publicKey,
        signedPreKey: req.body.signedPreKey,
        preKeys: req.body.preKeys,
        oneTimeKeys: req.body.oneTimeKeys
      });
      
      res.json({
        success: true,
        data: {
          updated: result.updated,
          preKeyIds: result.preKeyIds,
          oneTimeKeyIds: result.oneTimeKeyIds
        }
      });
    } catch (error) {
      console.error('Key update error:', {
        error: error.message,
        userId: req.user?.user_id
      });
      
      res.status(400).json({
        success: false,
        error: 'Key update failed'
      });
    }
  }
);

/**
 * @route   POST /api/auth/keys/exchange
 * @desc    Get keys for encrypted message exchange (X3DH)
 * @access  Private
 * @security Returns keys for initiating E2EE conversation
 */
router.post(
  '/keys/exchange',
  securityMiddleware.authenticate,
  authValidation.keyExchange,
  validationMiddleware.validate,
  async (req, res) => {
    try {
      const result = await authController.getKeysForExchange({
        userId: req.body.userId, // Target user ID
        requesterId: req.user.user_id, // Current user
        ephemeralKey: req.body.ephemeralKey,
        preKeyId: req.body.preKeyId,
        oneTimeKeyId: req.body.oneTimeKeyId
      });
      
      if (!result) {
        return res.status(404).json({
          success: false,
          error: 'User not found or no keys available'
        });
      }
      
      res.json({
        success: true,
        data: {
          identityKey: result.identityKey,
          signedPreKey: result.signedPreKey,
          preKey: result.preKey,
          oneTimeKey: result.oneTimeKey,
          preKeyId: result.preKeyId,
          oneTimeKeyId: result.oneTimeKeyId,
          signature: result.signature
        }
      });
    } catch (error) {
      console.error('Key exchange error:', {
        error: error.message,
        userId: req.user?.user_id,
        targetUserId: req.body?.userId
      });
      
      res.status(400).json({
        success: false,
        error: 'Key exchange failed'
      });
    }
  }
);

/**
 * @route   GET /api/auth/keys/prekey-bundle/:userId
 * @desc    Get pre-key bundle for user (anonymous access)
 * @access  Public (limited)
 * @security Returns public keys for initiating conversation
 */
router.get(
  '/keys/prekey-bundle/:userId',
  securityMiddleware.rateLimit.api,
  async (req, res) => {
    try {
      const result = await authController.getPreKeyBundle(req.params.userId);
      
      if (!result) {
        return res.status(404).json({
          success: false,
          error: 'User not found or no keys available'
        });
      }
      
      res.json({
        success: true,
        data: {
          identityKey: result.identityKey,
          signedPreKey: result.signedPreKey,
          preKey: result.preKey,
          preKeyId: result.preKeyId,
          signature: result.signature
        }
      });
    } catch (error) {
      console.error('Pre-key bundle error:', {
        error: error.message,
        targetUserId: req.params.userId
      });
      
      res.status(400).json({
        success: false,
        error: 'Failed to get pre-key bundle'
      });
    }
  }
);

/**
 * @route   DELETE /api/auth/account
 * @desc    Delete user account and all data
 * @access  Private
 * @security Permanent deletion with cleanup
 */
router.delete(
  '/account',
  securityMiddleware.authenticate,
  async (req, res) => {
    try {
      await authController.deleteAccount({
        userId: req.user.user_id,
        sessionId: req.session.sessionId
      });
      
      res.json({
        success: true,
        message: 'Account deleted successfully'
      });
    } catch (error) {
      console.error('Account deletion error:', {
        error: error.message,
        userId: req.user?.user_id
      });
      
      res.status(500).json({
        success: false,
        error: 'Account deletion failed'
      });
    }
  }
);

/**
 * @route   GET /api/auth/health
 * @desc    Authentication service health check
 * @access  Public
 */
router.get(
  '/health',
  securityMiddleware.rateLimit.api,
  async (req, res) => {
    try {
      const health = await authController.healthCheck();
      
      res.json({
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          ...health
        }
      });
    } catch (error) {
      res.status(503).json({
        success: false,
        error: 'Authentication service unhealthy',
        details: error.message
      });
    }
  }
);

module.exports = router;