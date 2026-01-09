const { validationResult } = require('express-validator');
const { sanitizationRules } = require('../config/security');

/**
 * Validation Middleware
 * Handles request validation and sanitization
 */

class ValidationMiddleware {
  /**
   * Validate request using express-validator results
   */
  validate = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      // Format errors for response
      const formattedErrors = errors.array().map(error => ({
        field: error.path,
        message: error.msg,
        value: error.value
      }));
      
      console.error('Validation errors:', {
        path: req.path,
        errors: formattedErrors,
        ipHash: this.hashIP(req.ip)
      });
      
      return res.status(400).json({
        error: 'Validation failed',
        details: formattedErrors
      });
    }
    
    next();
  };

  /**
   * Validate username format and availability
   */
  validateUsername = async (req, res, next) => {
    const { username } = req.body;
    
    if (!username) {
      return next();
    }
    
    // Check format
    if (username.length < sanitizationRules.username.minLength || 
        username.length > sanitizationRules.username.maxLength) {
      return res.status(400).json({
        error: `Username must be ${sanitizationRules.username.minLength}-${sanitizationRules.username.maxLength} characters`
      });
    }
    
    // Check pattern
    if (!sanitizationRules.username.pattern.test(username)) {
      return res.status(400).json({
        error: 'Username can only contain letters, numbers, underscores, and dashes'
      });
    }
    
    // Check disallowed usernames
    if (sanitizationRules.username.disallow.includes(username.toLowerCase())) {
      return res.status(400).json({
        error: 'This username is not allowed'
      });
    }
    
    next();
  };

  /**
   * Validate message content
   */
  validateMessage = (req, res, next) => {
    const { encryptedContent } = req.body;
    
    if (!encryptedContent) {
      return res.status(400).json({
        error: 'Message content is required'
      });
    }
    
    // Check length
    if (encryptedContent.length < sanitizationRules.message.minLength || 
        encryptedContent.length > sanitizationRules.message.maxLength) {
      return res.status(400).json({
        error: `Message must be ${sanitizationRules.message.minLength}-${sanitizationRules.message.maxLength} characters`
      });
    }
    
    // Check if content appears to be base64
    if (!/^[A-Za-z0-9+/=]+$/.test(encryptedContent)) {
      return res.status(400).json({
        error: 'Invalid message format'
      });
    }
    
    next();
  };

  /**
   * Validate room name
   */
  validateRoomName = (req, res, next) => {
    const { name } = req.body;
    
    if (!name) {
      return res.status(400).json({
        error: 'Room name is required'
      });
    }
    
    // Check length
    if (name.length < sanitizationRules.roomName.minLength || 
        name.length > sanitizationRules.roomName.maxLength) {
      return res.status(400).json({
        error: `Room name must be ${sanitizationRules.roomName.minLength}-${sanitizationRules.roomName.maxLength} characters`
      });
    }
    
    // Check pattern
    if (!sanitizationRules.roomName.pattern.test(name)) {
      return res.status(400).json({
        error: 'Room name can only contain letters, numbers, spaces, underscores, and dashes'
      });
    }
    
    next();
  };

  /**
   * Validate UUID parameters
   */
  validateUUID = (paramName) => {
    return (req, res, next) => {
      const uuid = req.params[paramName];
      
      if (!uuid) {
        return res.status(400).json({
          error: `${paramName} is required`
        });
      }
      
      // UUID v4 pattern
      const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      
      if (!uuidPattern.test(uuid)) {
        return res.status(400).json({
          error: `Invalid ${paramName} format`
        });
      }
      
      next();
    };
  };

  /**
   * Validate encryption key format
   */
  validateEncryptionKey = (keyName) => {
    return (req, res, next) => {
      const key = req.body[keyName];
      
      if (!key) {
        return next(); // Some keys might be optional
      }
      
      // Check if it looks like a base64 encoded key
      if (typeof key !== 'string') {
        return res.status(400).json({
          error: `${keyName} must be a string`
        });
      }
      
      // Basic base64 validation
      if (!/^[A-Za-z0-9+/=]+$/.test(key)) {
        return res.status(400).json({
          error: `Invalid ${keyName} format`
        });
      }
      
      // Reasonable key size limits
      if (key.length < 16 || key.length > 4096) {
        return res.status(400).json({
          error: `${keyName} must be 16-4096 characters`
        });
      }
      
      next();
    };
  };

  /**
   * Validate session key
   */
  validateSessionKey = (req, res, next) => {
    const { sessionKey } = req.body;
    
    if (!sessionKey) {
      return res.status(400).json({
        error: 'Session key is required'
      });
    }
    
    // Session keys should be base64 and reasonably sized
    if (!/^[A-Za-z0-9+/=]+$/.test(sessionKey)) {
      return res.status(400).json({
        error: 'Invalid session key format'
      });
    }
    
    if (sessionKey.length < 32 || sessionKey.length > 512) {
      return res.status(400).json({
        error: 'Invalid session key length'
      });
    }
    
    next();
  };

  /**
   * Validate pagination parameters
   */
  validatePagination = (req, res, next) => {
    const { limit, offset } = req.query;
    
    if (limit) {
      const limitNum = parseInt(limit, 10);
      if (isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
        return res.status(400).json({
          error: 'Limit must be between 1 and 100'
        });
      }
    }
    
    if (offset) {
      const offsetNum = parseInt(offset, 10);
      if (isNaN(offsetNum) || offsetNum < 0) {
        return res.status(400).json({
          error: 'Offset must be a non-negative number'
        });
      }
    }
    
    next();
  };

  /**
   * Validate timestamp parameters
   */
  validateTimestamp = (paramName) => {
    return (req, res, next) => {
      const timestamp = req.query[paramName] || req.body[paramName];
      
      if (!timestamp) {
        return next();
      }
      
      const timestampNum = parseInt(timestamp, 10);
      
      if (isNaN(timestampNum) || timestampNum < 0) {
        return res.status(400).json({
          error: `${paramName} must be a valid timestamp`
        });
      }
      
      // Check if timestamp is in the future (with some tolerance)
      const now = Date.now();
      const tolerance = 5 * 60 * 1000; // 5 minutes
      
      if (timestampNum > now + tolerance) {
        return res.status(400).json({
          error: `${paramName} cannot be in the future`
        });
      }
      
      next();
    };
  };

  /**
   * Validate JSON metadata
   */
  validateMetadata = (req, res, next) => {
    const { metadata } = req.body;
    
    if (!metadata) {
      return next();
    }
    
    try {
      // Ensure metadata is an object
      if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
        return res.status(400).json({
          error: 'Metadata must be an object'
        });
      }
      
      // Limit metadata size (prevent DoS)
      const metadataStr = JSON.stringify(metadata);
      if (metadataStr.length > 1024) { // 1KB max
        return res.status(400).json({
          error: 'Metadata too large'
        });
      }
      
      // Validate metadata keys and values
      for (const [key, value] of Object.entries(metadata)) {
        // Key validation
        if (typeof key !== 'string' || key.length > 64) {
          return res.status(400).json({
            error: 'Invalid metadata key'
          });
        }
        
        // Value validation (basic types only)
        if (!this.isValidMetadataValue(value)) {
          return res.status(400).json({
            error: 'Invalid metadata value'
          });
        }
      }
      
      next();
    } catch (error) {
      console.error('Metadata validation error:', error);
      return res.status(400).json({
        error: 'Invalid metadata format'
      });
    }
  };

  /**
   * Validate invitation key
   */
  validateInvitationKey = (req, res, next) => {
    const { invitationKey } = req.body;
    
    if (!invitationKey) {
      return next(); // Some endpoints might not require invitation key
    }
    
    if (typeof invitationKey !== 'string') {
      return res.status(400).json({
        error: 'Invitation key must be a string'
      });
    }
    
    // Invitation keys should be base64
    if (!/^[A-Za-z0-9+/=]+$/.test(invitationKey)) {
      return res.status(400).json({
        error: 'Invalid invitation key format'
      });
    }
    
    if (invitationKey.length < 32 || invitationKey.length > 256) {
      return res.status(400).json({
        error: 'Invalid invitation key length'
      });
    }
    
    next();
  };

  /**
   * Validate public key format
   */
  validatePublicKey = (req, res, next) => {
    const { publicKey } = req.body;
    
    if (!publicKey) {
      return res.status(400).json({
        error: 'Public key is required'
      });
    }
    
    if (typeof publicKey !== 'string') {
      return res.status(400).json({
        error: 'Public key must be a string'
      });
    }
    
    // Basic validation for base64 encoded key
    if (!/^[A-Za-z0-9+/=]+$/.test(publicKey)) {
      return res.status(400).json({
        error: 'Invalid public key format'
      });
    }
    
    // Reasonable size for public keys (depends on algorithm)
    if (publicKey.length < 32 || publicKey.length > 1024) {
      return res.status(400).json({
        error: 'Invalid public key length'
      });
    }
    
    next();
  };

  /**
   * Helper: Check if value is valid for metadata
   */
  isValidMetadataValue(value) {
    const type = typeof value;
    
    // Allow basic types
    if (type === 'string' || type === 'number' || type === 'boolean') {
      // Additional checks for strings
      if (type === 'string' && value.length > 256) {
        return false;
      }
      return true;
    }
    
    // Allow null
    if (value === null) {
      return true;
    }
    
    // Allow arrays of basic types
    if (Array.isArray(value)) {
      return value.every(item => this.isValidMetadataValue(item));
    }
    
    // Allow nested objects (with recursion depth limit)
    if (type === 'object') {
      // Prevent circular references by limiting depth
      return this.isValidMetadataObject(value, 0, 3);
    }
    
    return false;
  }

  /**
   * Helper: Check if object is valid for metadata with depth limit
   */
  isValidMetadataObject(obj, depth, maxDepth) {
    if (depth >= maxDepth) {
      return false;
    }
    
    for (const [key, value] of Object.entries(obj)) {
      if (!this.isValidMetadataValue(value)) {
        return false;
      }
      
      // Recursive check for nested objects
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        if (!this.isValidMetadataObject(value, depth + 1, maxDepth)) {
          return false;
        }
      }
    }
    
    return true;
  }

  /**
   * Helper: Hash IP for logging
   */
  hashIP(ip) {
    if (!ip) return 'unknown';
    const crypto = require('crypto');
    return crypto.createHash('sha256')
      .update(ip + process.env.SESSION_SECRET)
      .digest('hex')
      .substring(0, 32);
  }
}

module.exports = new ValidationMiddleware();