require('dotenv').config();
const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

// Security middleware
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const cookieParser = require('cookie-parser');

// Configurations
const securityConfig = require('./config/security');
const databaseConfig = require('./config/database');
const websocketService = require('./services/websocket');
const presenceService = require('./services/presence');

// Routes
const authRoutes = require('./routes/auth');
const messageRoutes = require('./routes/messages');
const roomRoutes = require('./routes/rooms');

// Constants
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === 'production';

class SecureChatServer {
  constructor() {
    this.app = express();
    this.server = null;
    this.wss = null;
    
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  setupMiddleware() {
    // Security headers
    this.app.use(securityConfig.securityHeaders);
    
    // Helmet with CSP
    this.app.use(helmet({
      contentSecurityPolicy: securityConfig.contentSecurityPolicy,
      crossOriginEmbedderPolicy: true,
      crossOriginOpenerPolicy: true,
      crossOriginResourcePolicy: { policy: "same-site" }
    }));
    
    // CORS
    this.app.use(cors(securityConfig.corsOptions));
    
    // Compression
    this.app.use(compression());
    
    // Body parsing
    this.app.use(express.json({ limit: '10kb' }));
    this.app.use(express.urlencoded({ extended: false, limit: '10kb' }));
    
    // Cookie parser
    this.app.use(cookieParser());
    
    // Rate limiting
    this.app.use('/api/auth', securityConfig.limiterConfigs.authLimiter);
    this.app.use('/api', securityConfig.limiterConfigs.apiLimiter);
    
    // Static files (for PWA if needed)
    this.app.use(express.static('public', {
      setHeaders: (res, path) => {
        // Security headers for static files
        res.setHeader('Cache-Control', 'no-store, max-age=0');
        res.setHeader('X-Content-Type-Options', 'nosniff');
      }
    }));
    
    // Request logging (minimal for privacy)
    this.app.use((req, res, next) => {
      const start = Date.now();
      const ipHash = this.hashIP(req.ip);
      
      res.on('finish', () => {
        const duration = Date.now() - start;
        const logData = {
          method: req.method,
          path: req.path,
          status: res.statusCode,
          duration: `${duration}ms`,
          ipHash: ipHash,
          userAgentHash: req.headers['user-agent'] ? 
            this.hashString(req.headers['user-agent']) : 'unknown'
        };
        
        // Only log errors and slow requests
        if (res.statusCode >= 400 || duration > 1000) {
          console.log(JSON.stringify(logData));
        }
      });
      
      next();
    });
  }

  setupRoutes() {
    // Health check endpoint (no logging)
    this.app.get('/health', async (req, res) => {
      const health = await databaseConfig.healthCheck();
      res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        ...health
      });
    });
    
    // Metrics endpoint (minimal, no sensitive data)
    this.app.get('/metrics', (req, res) => {
      res.json({
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        connections: this.wss?.clients?.size || 0
      });
    });
    
    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/messages', messageRoutes);
    this.app.use('/api/rooms', roomRoutes);
    
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({ error: 'Not found' });
    });
  }

  setupErrorHandling() {
    // Global error handler
    this.app.use((err, req, res, next) => {
      console.error('Unhandled error:', {
        error: err.message,
        stack: isProduction ? undefined : err.stack,
        path: req.path,
        ipHash: this.hashIP(req.ip)
      });
      
      // Don't expose error details in production
      const errorResponse = isProduction
        ? { error: 'Internal server error' }
        : { 
            error: err.message,
            ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
          };
      
      res.status(err.status || 500).json(errorResponse);
    });
    
    // Unhandled promise rejection
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });
    
    // Uncaught exception
    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      process.exit(1);
    });
  }

  async initializeDatabase() {
    try {
      await databaseConfig.initDatabase();
      await databaseConfig.initRedis();
      console.log('✅ Database and Redis initialized');
    } catch (error) {
      console.error('❌ Failed to initialize database:', error);
      throw error;
    }
  }

  setupWebSocket() {
    this.wss = new WebSocketServer({ 
      server: this.server,
      perMessageDeflate: false, // Disable compression for security
      maxPayload: 1024 * 1024, // 1MB max message size
      clientTracking: true
    });
    
    // Initialize WebSocket service
    websocketService.initialize(this.wss);
    console.log('✅ WebSocket server initialized');
  }

  async start() {
    try {
      // Initialize database
      await this.initializeDatabase();
      
      // Create HTTP/HTTPS server
      if (isProduction && fs.existsSync('/etc/letsencrypt/live/')) {
        // Production with SSL
        const privateKey = fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/privkey.pem', 'utf8');
        const certificate = fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/cert.pem', 'utf8');
        const ca = fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/chain.pem', 'utf8');
        
        const credentials = { key: privateKey, cert: certificate, ca: ca };
        this.server = https.createServer(credentials, this.app);
      } else {
        // Development
        this.server = http.createServer(this.app);
      }
      
      // Setup WebSocket
      this.setupWebSocket();
      
      // Start server
      this.server.listen(PORT, () => {
        console.log(`🚀 Secure Chat Server running on port ${PORT}`);
        console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`🌐 WebSocket: ${isProduction ? 'wss' : 'ws'}://localhost:${PORT}`);
        
        // Start cleanup jobs
        this.startCleanupJobs();
      });
      
      // Graceful shutdown
      this.setupGracefulShutdown();
      
    } catch (error) {
      console.error('❌ Failed to start server:', error);
      process.exit(1);
    }
  }

  startCleanupJobs() {
    // Clean up expired sessions every hour
    setInterval(async () => {
      try {
        await databaseConfig.query(
          'DELETE FROM sessions WHERE expires_at < NOW() OR is_active = FALSE'
        );
        console.log('🧹 Cleaned up expired sessions');
      } catch (error) {
        console.error('Failed to cleanup sessions:', error);
      }
    }, 3600000); // 1 hour
    
    // Clean up old ephemeral users (24h+ inactive)
    setInterval(async () => {
      try {
        await databaseConfig.query(`
          DELETE FROM users 
          WHERE is_ephemeral = TRUE 
          AND last_seen < NOW() - INTERVAL '24 hours'
        `);
        console.log('🧹 Cleaned up old ephemeral users');
      } catch (error) {
        console.error('Failed to cleanup ephemeral users:', error);
      }
    }, 6 * 3600000); // 6 hours
  }

  setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} received. Starting graceful shutdown...`);
      
      // Close WebSocket connections
      if (this.wss) {
        this.wss.clients.forEach(client => {
          if (client.readyState === 1) { // OPEN
            client.close(1001, 'Server shutting down');
          }
        });
        this.wss.close();
      }
      
      // Close server
      if (this.server) {
        this.server.close(async () => {
          console.log('HTTP server closed');
          
          // Close database connections
          try {
            await databaseConfig.pgPool.end();
            const redisClient = databaseConfig.getRedisClient();
            if (redisClient) {
              await redisClient.quit();
            }
            console.log('Database connections closed');
          } catch (error) {
            console.error('Error closing database connections:', error);
          }
          
          console.log('Graceful shutdown complete');
          process.exit(0);
        });
        
        // Force close after 10 seconds
        setTimeout(() => {
          console.error('Forcing shutdown after timeout');
          process.exit(1);
        }, 10000);
      }
    };
    
    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  }

  // Utility methods for hashing (privacy preserving)
  hashIP(ip) {
    if (!ip) return 'unknown';
    // Only hash for logging, not for identification
    const crypto = require('crypto');
    return crypto.createHash('sha256')
      .update(ip + process.env.SESSION_SECRET)
      .digest('hex')
      .substring(0, 32);
  }

  hashString(str) {
    if (!str) return 'unknown';
    const crypto = require('crypto');
    return crypto.createHash('sha256')
      .update(str)
      .digest('hex')
      .substring(0, 32);
  }
}

// Create and start server
const server = new SecureChatServer();

// Handle uncaught errors during startup
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception during startup:', error);
  process.exit(1);
});

server.start().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});

module.exports = server;