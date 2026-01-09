const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { CRYPTO_CONSTANTS } = require('../../../shared/cryptoConstants');

/**
 * Security middleware configuration
 */

// Strict CSP configuration
const contentSecurityPolicy = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "'wasm-unsafe-eval'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "blob:"],
    connectSrc: [
      "'self'",
      process.env.CLIENT_URL || 'https://localhost:3000',
      process.env.SERVER_URL || 'wss://localhost:3001'
    ],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    workerSrc: ["'self'", "blob:"],
    manifestSrc: ["'self'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: []
  }
};

// Rate limiting configurations
const limiterConfigs = {
  // Global API rate limit
  apiLimiter: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.',
    skipSuccessfulRequests: false
  }),

  // Authentication rate limit (stricter)
  authLimiter: rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many authentication attempts, please try again later.',
    skipSuccessfulRequests: true
  }),

  // WebSocket connection limit
  wsLimiter: rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // Max 30 WebSocket connections per minute per IP
    message: 'Too many WebSocket connection attempts'
  })
};

// Security headers configuration
const securityHeaders = (req, res, next) => {
  // HSTS - Force HTTPS
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );

  // X-Content-Type-Options
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // X-Frame-Options
  res.setHeader('X-Frame-Options', 'DENY');

  // X-XSS-Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Referrer-Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions-Policy
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), interest-cohort=()'
  );

  // Cache-Control for API endpoints
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  // Remove unnecessary headers
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');

  next();
};

// CORS configuration
const corsOptions = {
  origin: process.env.CLIENT_URL || 'https://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-Encryption-Version'
  ],
  exposedHeaders: [
    'X-Encryption-Version',
    'X-Session-Expiry'
  ],
  maxAge: 86400 // 24 hours
};

// Session security configuration
const sessionSecurity = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: parseInt(process.env.TOKEN_EXPIRY) || 24 * 60 * 60 * 1000, // 24 hours
  domain: process.env.NODE_ENV === 'production' ? '.yourdomain.com' : 'localhost'
};

// Input sanitization rules
const sanitizationRules = {
  username: {
    minLength: 3,
    maxLength: 32,
    pattern: /^[a-zA-Z0-9_-]+$/,
    disallow: ['admin', 'system', 'root', 'moderator']
  },
  message: {
    minLength: 1,
    maxLength: CRYPTO_CONSTANTS.LIMITS.MAX_MESSAGE_SIZE,
    disallowScripts: true
  },
  roomName: {
    minLength: 1,
    maxLength: 64,
    pattern: /^[a-zA-Z0-9 _-]+$/
  }
};

// Security audit logging
const securityAudit = {
  enabled: process.env.NODE_ENV === 'production',
  logLevels: ['auth_failure', 'rate_limit', 'invalid_input', 'crypto_error'],
  excludePaths: ['/health', '/metrics']
};

module.exports = {
  contentSecurityPolicy,
  limiterConfigs,
  securityHeaders,
  corsOptions,
  sessionSecurity,
  sanitizationRules,
  securityAudit
};