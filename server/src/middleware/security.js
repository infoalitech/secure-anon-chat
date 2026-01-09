const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const Session = require('../models/Session');
const User = require('../models/User');
const { securityAudit } = require('../config/security');

/**
 * Security Middleware
 * Handles authentication, rate limiting, and security headers
 */

class SecurityMiddleware {
  /**
   * Authenticate user session
   */
  authenticate = async (req, res, next) => {
    try {
      // Get session key from Authorization header or cookie
      let sessionKey = null;
      
      // Check Authorization header
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        sessionKey = authHeader.substring(7);
      }
      
      // Check session cookie
      if (!sessionKey && req.cookies?.sessionKey) {
        sessionKey = req.cookies.sessionKey;
      }
      
      if (!sessionKey) {
        this.logSecurityEvent('auth_failure', req, 'No session key provided');
        return res.status(401).json({
          error: 'Authentication required'
        });
      }
      
      // Find session by key
      const session = await Session.findBySessionKey(sessionKey);
      
      if (!session) {
        this.logSecurityEvent('auth_failure', req, 'Invalid session key');
        return res.status(401).json({
          error: 'Invalid session'
        });
      }
      
      // Check if session is expired
      if (new Date(session.expires_at) < new Date()) {
        await Session.invalidate(session.session_id);
        this.logSecurityEvent('auth_failure', req, 'Session expired');
        return res.status(401).json({
          error: 'Session expired'
        });
      }
      
      // Get user details
      const user = await User.findById(session.user_id);
      if (!user) {
        this.logSecurityEvent('auth_failure', req, 'User not found');
        return res.status(401).json({
          error: 'User not found'
        });
      }
      
      // Check if user is active (for ephemeral users)
      if (user.is_ephemeral && user.last_seen) {
        const hoursSinceLastSeen = (Date.now() - new Date(user.last_seen).getTime()) / (1000 * 60 * 60);
        if (hoursSinceLastSeen > 24) {
          await Session.invalidate(session.session_id);
          this.logSecurityEvent('auth_failure', req, 'Ephemeral user expired');
          return res.status(401).json({
            error: 'User session expired'
          });
        }
      }
      
      // Update session last activity
      await Session.updateLastActivity(session.session_id);
      
      // Attach session and user to request
      req.session = {
        sessionId: session.session_id,
        expiresAt: session.expires_at,
        websocketId: session.websocket_id
      };
      
      req.user = {
        user_id: user.user_id,
        username_hash: user.username_hash,
        public_key: user.public_key,
        is_ephemeral: user.is_ephemeral
      };
      
      next();
    } catch (error) {
      console.error('Authentication error:', error);
      this.logSecurityEvent('auth_failure', req, error.message);
      res.status(500).json({
        error: 'Authentication failed'
      });
    }
  };

  /**
   * Verify WebSocket connection
   */
  authenticateWebSocket = async (ws, req) => {
    try {
      // Get session key from query parameters
      const sessionKey = req.query.sessionKey;
      
      if (!sessionKey) {
        this.logSecurityEvent('auth_failure', req, 'No session key for WebSocket');
        ws.close(1008, 'Authentication required');
        return null;
      }
      
      // Find session
      const session = await Session.findBySessionKey(sessionKey);
      
      if (!session) {
        this.logSecurityEvent('auth_failure', req, 'Invalid WebSocket session');
        ws.close(1008, 'Invalid session');
        return null;
      }
      
      // Check if session is expired
      if (new Date(session.expires_at) < new Date()) {
        await Session.invalidate(session.session_id);
        this.logSecurityEvent('auth_failure', req, 'WebSocket session expired');
        ws.close(1008, 'Session expired');
        return null;
      }
      
      // Get user
      const user = await User.findById(session.user_id);
      if (!user) {
        this.logSecurityEvent('auth_failure', req, 'WebSocket user not found');
        ws.close(1008, 'User not found');
        return null;
      }
      
      // Update session with WebSocket ID
      const websocketId = crypto.randomBytes(16).toString('hex');
      await Session.updateWebSocketId(session.session_id, websocketId);
      
      // Update user last seen
      await User.updateLastSeen(user.user_id);
      
      return {
        sessionId: session.session_id,
        userId: user.user_id,
        usernameHash: user.username_hash,
        isEphemeral: user.is_ephemeral,
        websocketId
      };
    } catch (error) {
      console.error('WebSocket authentication error:', error);
      this.logSecurityEvent('auth_failure', req, error.message);
      ws.close(1011, 'Authentication error');
      return null;
    }
  };

  /**
   * Rate limiting middleware
   */
  rateLimit = {
    // Global API rate limit
    api: (req, res, next) => {
      const ip = req.ip;
      const key = `rate_limit:api:${this.hashIP(ip)}`;
      
      // This would integrate with Redis in production
      // For now, using in-memory store
      const now = Date.now();
      const windowMs = 15 * 60 * 1000; // 15 minutes
      const maxRequests = 100;
      
      // Simple in-memory rate limiting
      if (!this.rateLimitStore) {
        this.rateLimitStore = new Map();
      }
      
      const record = this.rateLimitStore.get(key) || { count: 0, resetTime: now + windowMs };
      
      if (now > record.resetTime) {
        record.count = 0;
        record.resetTime = now + windowMs;
      }
      
      if (record.count >= maxRequests) {
        this.logSecurityEvent('rate_limit', req, `API rate limit exceeded for ${ip}`);
        return res.status(429).json({
          error: 'Too many requests'
        });
      }
      
      record.count++;
      this.rateLimitStore.set(key, record);
      
      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', maxRequests);
      res.setHeader('X-RateLimit-Remaining', maxRequests - record.count);
      res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));
      
      next();
    },
    
    // Stricter auth rate limit
    auth: (req, res, next) => {
      const ip = req.ip;
      const key = `rate_limit:auth:${this.hashIP(ip)}`;
      
      const now = Date.now();
      const windowMs = 15 * 60 * 1000; // 15 minutes
      const maxRequests = 10;
      
      if (!this.authRateLimitStore) {
        this.authRateLimitStore = new Map();
      }
      
      const record = this.authRateLimitStore.get(key) || { count: 0, resetTime: now + windowMs };
      
      if (now > record.resetTime) {
        record.count = 0;
        record.resetTime = now + windowMs;
      }
      
      if (record.count >= maxRequests) {
        this.logSecurityEvent('rate_limit', req, `Auth rate limit exceeded for ${ip}`);
        return res.status(429).json({
          error: 'Too many authentication attempts'
        });
      }
      
      record.count++;
      this.authRateLimitStore.set(key, record);
      
      next();
    },
    
    // WebSocket connection rate limit
    websocket: (req, res, next) => {
      const ip = req.ip;
      const key = `rate_limit:ws:${this.hashIP(ip)}`;
      
      const now = Date.now();
      const windowMs = 60 * 1000; // 1 minute
      const maxConnections = 30;
      
      if (!this.wsRateLimitStore) {
        this.wsRateLimitStore = new Map();
      }
      
      const record = this.wsRateLimitStore.get(key) || { count: 0, resetTime: now + windowMs };
      
      if (now > record.resetTime) {
        record.count = 0;
        record.resetTime = now + windowMs;
      }
      
      if (record.count >= maxConnections) {
        this.logSecurityEvent('rate_limit', req, `WebSocket rate limit exceeded for ${ip}`);
        return res.status(429).json({
          error: 'Too many WebSocket connections'
        });
      }
      
      record.count++;
      this.wsRateLimitStore.set(key, record);
      
      next();
    }
  };

  /**
   * Input sanitization middleware
   */
  sanitizeInput = (req, res, next) => {
    try {
      // Sanitize request body
      if (req.body) {
        req.body = this.sanitizeObject(req.body);
      }
      
      // Sanitize query parameters
      if (req.query) {
        req.query = this.sanitizeObject(req.query);
      }
      
      // Sanitize URL parameters
      if (req.params) {
        req.params = this.sanitizeObject(req.params);
      }
      
      next();
    } catch (error) {
      console.error('Input sanitization error:', error);
      this.logSecurityEvent('invalid_input', req, error.message);
      res.status(400).json({
        error: 'Invalid input'
      });
    }
  };

  /**
   * Prevent XSS attacks
   */
  preventXSS = (req, res, next) => {
    // Set XSS protection headers
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Check for suspicious content in request
    if (req.body) {
      const hasXSS = this.checkForXSS(req.body);
      if (hasXSS) {
        this.logSecurityEvent('xss_attempt', req, 'Potential XSS detected');
        return res.status(400).json({
          error: 'Invalid request content'
        });
      }
    }
    
    next();
  };

  /**
   * Prevent CSRF attacks
   */
  preventCSRF = (req, res, next) => {
    // Skip CSRF for GET, HEAD, OPTIONS
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next();
    }
    
    // Check CSRF token for state-changing operations
    const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
    
    if (!csrfToken) {
      this.logSecurityEvent('csrf_attempt', req, 'Missing CSRF token');
      return res.status(403).json({
        error: 'CSRF token required'
      });
    }
    
    // Verify CSRF token (in production, use proper CSRF library)
    // For now, using simplified validation
    if (!this.validateCSRFToken(csrfToken, req)) {
      this.logSecurityEvent('csrf_attempt', req, 'Invalid CSRF token');
      return res.status(403).json({
        error: 'Invalid CSRF token'
      });
    }
    
    next();
  };

  /**
   * Prevent clickjacking
   */
  preventClickjacking = (req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
    next();
  };

  /**
   * Security headers middleware
   */
  securityHeaders = (req, res, next) => {
    // HSTS
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    
    // Content Security Policy
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "media-src 'self'",
      "frame-src 'none'",
      "worker-src 'self' blob:",
      "manifest-src 'self'"
    ].join('; '));
    
    // Other security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Download-Options', 'noopen');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Remove unnecessary headers
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    
    next();
  };

  /**
   * Encryption verification middleware
   */
  verifyEncryption = (req, res, next) => {
    // Check for encryption version header
    const encryptionVersion = req.headers['x-encryption-version'];
    
    if (!encryptionVersion) {
      this.logSecurityEvent('crypto_error', req, 'Missing encryption version');
      return res.status(400).json({
        error: 'Encryption version required'
      });
    }
    
    // Validate encryption version (in production, check against supported versions)
    const supportedVersions = ['1.0.0'];
    if (!supportedVersions.includes(encryptionVersion)) {
      this.logSecurityEvent('crypto_error', req, `Unsupported encryption version: ${encryptionVersion}`);
      return res.status(400).json({
        error: 'Unsupported encryption version'
      });
    }
    
    // For encrypted endpoints, verify content type
    if (req.path.includes('/messages/') && req.method === 'POST') {
      if (!req.headers['content-type']?.includes('application/json')) {
        this.logSecurityEvent('crypto_error', req, 'Invalid content type for encrypted message');
        return res.status(400).json({
          error: 'Content must be JSON for encrypted messages'
        });
      }
    }
    
    next();
  };

  /**
   * Log security events
   */
  logSecurityEvent(eventType, req, details) {
    if (!securityAudit.enabled) {
      return;
    }
    
    if (!securityAudit.logLevels.includes(eventType)) {
      return;
    }
    
    if (securityAudit.excludePaths.some(path => req.path.includes(path))) {
      return;
    }
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      event: eventType,
      path: req.path,
      method: req.method,
      ipHash: this.hashIP(req.ip),
      userAgentHash: req.headers['user-agent'] ? this.hashString(req.headers['user-agent']) : 'unknown',
      details: details
    };
    
    console.log(`SECURITY: ${JSON.stringify(logEntry)}`);
  }

  /**
   * Hash IP address for logging (privacy preserving)
   */
  hashIP(ip) {
    if (!ip) return 'unknown';
    return crypto.createHash('sha256')
      .update(ip + process.env.SESSION_SECRET)
      .digest('hex')
      .substring(0, 32);
  }

  /**
   * Hash string for logging
   */
  hashString(str) {
    if (!str) return 'unknown';
    return crypto.createHash('sha256')
      .update(str + process.env.SESSION_SECRET)
      .digest('hex')
      .substring(0, 32);
  }

  /**
   * Sanitize object recursively
   */
  sanitizeObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
      return this.sanitizeValue(obj);
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = this.sanitizeObject(value);
    }
    
    return sanitized;
  }

  /**
   * Sanitize single value
   */
  sanitizeValue(value) {
    if (typeof value !== 'string') {
      return value;
    }
    
    // Remove null bytes
    let sanitized = value.replace(/\0/g, '');
    
    // Trim whitespace
    sanitized = sanitized.trim();
    
    // Limit length (prevent DoS)
    const maxLength = 10000;
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }
    
    return sanitized;
  }

  /**
   * Check for XSS patterns
   */
  checkForXSS(obj) {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /expression\s*\(/gi,
      /vbscript:/gi,
      /<iframe/gi,
      /<object/gi,
      /<embed/gi
    ];
    
    const checkValue = (value) => {
      if (typeof value === 'string') {
        return xssPatterns.some(pattern => pattern.test(value));
      }
      return false;
    };
    
    const checkObject = (obj) => {
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'object' && value !== null) {
          if (checkObject(value)) {
            return true;
          }
        } else if (checkValue(value)) {
          return true;
        }
      }
      return false;
    };
    
    return checkObject(obj);
  }

  /**
   * Validate CSRF token (simplified)
   */
  validateCSRFToken(token, req) {
    // In production, use proper CSRF token validation
    // This is a simplified version
    if (!token || typeof token !== 'string') {
      return false;
    }
    
    // Check token format (should be base64)
    if (!/^[A-Za-z0-9+/=]+$/.test(token)) {
      return false;
    }
    
    // Check token length
    if (token.length < 32 || token.length > 512) {
      return false;
    }
    
    return true;
  }

  /**
   * Generate CSRF token
   */
  generateCSRFToken() {
    return crypto.randomBytes(32).toString('base64');
  }

  /**
   * Session management middleware
   */
  sessionManagement = (req, res, next) => {
    // Generate CSRF token for new sessions
    if (!req.cookies?._csrf) {
      const csrfToken = this.generateCSRFToken();
      res.cookie('_csrf', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      
      // Also set in response headers for API clients
      res.setHeader('X-CSRF-Token', csrfToken);
    }
    
    // Set cache control for authenticated endpoints
    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
    
    next();
  };
}

module.exports = new SecurityMiddleware();