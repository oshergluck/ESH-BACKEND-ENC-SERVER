const express = require('express');
const cors = require('cors');
const CryptoJS = require('crypto-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');

// Enhanced Winston logger with daily rotate
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.File({ 
      filename: 'combined.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Health check state
let healthCheck = {
  startTime: new Date(),
  lastHealthCheck: new Date(),
  memoryUsage: process.memoryUsage(),
  activeConnections: 0,
  totalRequests: 0,
  failedRequests: 0,
  lastError: null
};

const app = express();
let server = null;
let isShuttingDown = false;
let restartAttempts = 0;
const MAX_RESTART_ATTEMPTS = 1000;
const BASE_RETRY_DELAY = 5000;

// Server state monitoring
let serverState = {
  lastRestartTime: null,
  failureReason: null,
  activeConnections: 0,
  lastError: null
};

// Enhanced connection tracking
const connectionTracker = new Map();

// More specific trust proxy configuration for Cloudflare
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

// Connection tracking middleware with timeout
app.use((req, res, next) => {
  const connectionId = Math.random().toString(36).substring(7);
  healthCheck.activeConnections++;
  serverState.activeConnections++;
  
  // Track connection start time
  connectionTracker.set(connectionId, {
    startTime: Date.now(),
    ip: req.ip,
    path: req.path
  });
  
  // Set connection timeout
  const connectionTimeout = setTimeout(() => {
    if (connectionTracker.has(connectionId)) {
      logger.warn(`Connection ${connectionId} timed out after 30s`, {
        connection: connectionTracker.get(connectionId)
      });
      res.status(504).end();
    }
  }, 30000);
  
  res.on('finish', () => {
    clearTimeout(connectionTimeout);
    connectionTracker.delete(connectionId);
    healthCheck.activeConnections--;
    serverState.activeConnections--;
    logger.debug(`Connection closed. Active connections: ${serverState.activeConnections}`);
  });
  
  next();
});

// Request tracking middleware
app.use((req, res, next) => {
  const startTime = Date.now();
  const requestId = Math.random().toString(36).substring(7);
  healthCheck.totalRequests++;
  
  logger.info({
    message: 'Request received',
    requestId,
    method: req.method,
    path: req.path,
    ip: req.ip,
    headers: req.headers
  });
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    logger.info({
      message: 'Request completed',
      requestId,
      duration,
      statusCode: res.statusCode
    });
  });
  
  next();
});

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));

// JSON parser with size limit and validation
app.use(express.json({ 
  limit: '10kb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch(e) {
      res.status(400).json({ error: 'Invalid JSON' });
      throw new Error('Invalid JSON');
    }
  }
}));

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const cfIp = req.headers['cf-connecting-ip'];
    const realIp = req.headers['x-real-ip'];
    const forwardedFor = req.headers['x-forwarded-for'];
    return cfIp || realIp || (forwardedFor ? forwardedFor.split(',')[0] : req.ip);
  }
});
app.use(limiter);

// Allowed origins
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FULLWEBSITEWITHWWW,
  process.env.FULLWEBSITEWITHOUTWWW,
];

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn('Blocked CORS request:', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key'],
  credentials: true,
  maxAge: 86400
}));

// Memory monitoring
setInterval(() => {
  const memoryUsage = process.memoryUsage();
  healthCheck.memoryUsage = memoryUsage;
  
  // Log high memory usage
  if (memoryUsage.heapUsed > 1024 * 1024 * 512) { // 512MB
    logger.warn('High memory usage detected', { memoryUsage });
    if (global.gc) {
      global.gc(); // Force garbage collection if available
    }
  }
  
  // Check for leaked connections
  const now = Date.now();
  connectionTracker.forEach((connection, id) => {
    if (now - connection.startTime > 60000) { // 1 minute
      logger.warn(`Possible connection leak detected`, { connection });
      connectionTracker.delete(id);
      healthCheck.activeConnections = Math.max(0, healthCheck.activeConnections - 1);
      serverState.activeConnections = Math.max(0, serverState.activeConnections - 1);
    }
  });
}, 30000);

// Health check endpoint
app.get('/health', (req, res) => {
  healthCheck.lastHealthCheck = new Date();
  res.json({
    ...healthCheck,
    serverState
  });
});

// Utility functions
const generatePassword = () => {
  return Array.from(
    { length: 16 },
    () => Math.floor(Math.random() * 10)
  ).join('');
};

const readPasswordsFile = async () => {
  const filePath = path.join(__dirname, 'passwords.json');
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      await fs.writeFile(filePath, JSON.stringify({}));
      return {};
    }
    throw error;
  }
};

const writePasswordsFile = async (data) => {
  const filePath = path.join(__dirname, 'passwords.json');
  await fs.writeFile(filePath, JSON.stringify(data, null, 2));
};

const isValidAddress = (address) => {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
};

const generateKey = async (address1, address2, secret) => {
  try {
    const combinedKey = secret.toLowerCase();
    return CryptoJS.SHA256(combinedKey).toString();
  } catch (error) {
    throw new Error('Key generation failed');
  }
};

// Middleware
const validateApiKey = (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.API_KEY) {
      logger.warn('Invalid API key attempt', { 
        ip: req.ip, 
        path: req.path 
      });
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  } catch (error) {
    next(error);
  }
};

const validateAddressRegistration = (req, res, next) => {
  try {
    const { address } = req.body;
    if (!address) {
      return res.status(400).json({ error: 'Missing address' });
    }
    if (!isValidAddress(address)) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }
    next();
  } catch (error) {
    next(error);
  }
};

const validateEncryptionInput = (req, res, next) => {
  try {
    const { data, address1, address2, type } = req.body;
    
    if (type === 'ipfs' && !data) {
      return res.status(400).json({ error: 'Missing required IPFS data' });
    }
    
    if (type !== 'ipfs' && (!data || !address1 || !address2)) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }
    
    if (type !== 'ipfs' && (!isValidAddress(address1) || !isValidAddress(address2))) {
      return res.status(400).json({ error: 'Invalid Ethereum addresses' });
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

const validateDecryptionInput = (req, res, next) => {
  try {
    const { encryptedData, address1, address2, ENC, type, password } = req.body;
    
    if (!encryptedData) {
      return res.status(400).json({ error: 'Missing encrypted data' });
    }
    
    if (type === 'default') {
      if (!password) {
        return res.status(400).json({ error: 'Password required for decryption' });
      }
      
      if (typeof password !== 'string' || password.length !== 16) {
        return res.status(400).json({ error: 'Invalid password format' });
      }
    }
    
    if (type !== 'ipfs' && (!address1 || !address2)) {
      return res.status(400).json({ error: 'Missing addresses' });
    }
    
    if (type !== 'ipfs' && (!isValidAddress(address1) || !isValidAddress(address2))) {
      return res.status(400).json({ error: 'Invalid Ethereum addresses' });
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

const validatePasswordCheck = (req, res, next) => {
  try {
    const { address, password } = req.body;
    
    if (!address || !password) {
      return res.status(400).json({ error: 'Missing address or password' });
    }
    
    if (!isValidAddress(address)) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }
    
    if (typeof password !== 'string' || password.length !== 16) {
      return res.status(400).json({ error: 'Invalid password format' });
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

// Apply API key validation to all routes
app.use(validateApiKey);

// Routes
app.post('/api/encrypt', validateEncryptionInput, async (req, res, next) => {
  try {
    const { data, address1, address2, type } = req.body;
    
    if (type === 'ipfs') {
      const encrypted = CryptoJS.AES.encrypt(data, process.env.IPFS_ENC);
      return res.json({ encryptedData: encrypted.toString() });
    }
    
    const key = await generateKey(
      address1.toLowerCase(),
      address2.toLowerCase(),
      process.env.ULTIMATEDEAL_STORE_SECRETKEY.toLowerCase()
    );
    
    const encryptedData = CryptoJS.AES.encrypt(data, key).toString();
    const base64Data = CryptoJS.enc.Base64.stringify(
      CryptoJS.enc.Utf8.parse(encryptedData)
    );
    
    res.json({ encryptedData: base64Data });
  } catch (error) {
    logger.error('Encryption error:', { error });
    next(error);
  }
});

app.post('/api/decrypt', validateDecryptionInput, async (req, res, next) => {
  try {
    const { encryptedData, address1, address2, ENC, type, password } = req.body;
    
    if (type === 'ipfs') {
      const decrypted = CryptoJS.AES.decrypt(encryptedData, process.env.IPFS_ENC);
      return res.json({ 
        decryptedData: decrypted.toString(CryptoJS.enc.Utf8) 
      });
    }

    if (type === 'default') {
      const passwords = await readPasswordsFile();
      const lowerAddress = address2.toLowerCase();

      if (passwords[lowerAddress] !== password) {
        logger.warn('Invalid password attempt', { address: lowerAddress });
        return res.status(401).json({ error: 'Invalid password for the given address' });
      }
    }

    const key = await generateKey(
      address1.toLowerCase(),
      address2.toLowerCase(),
      process.env.ULTIMATEDEAL_STORE_SECRETKEY.toLowerCase()
    );

    const rawData = CryptoJS.enc.Base64.parse(encryptedData).toString(CryptoJS.enc.Utf8);
    const bytes = CryptoJS.AES.decrypt(rawData, key);
    const decryptedData = bytes.toString(CryptoJS.enc.Utf8);

    if (!decryptedData) {
      throw new Error('Decryption resulted in empty data');
    }

    res.json({ decryptedData });
  } catch (error) {
    logger.error('Decryption error:', { error });
    next(error);
  }
});

app.post('/api/verify-password', validatePasswordCheck, async (req, res, next) => {
  try {
    const { address, password } = req.body;
    const lowerAddress = address.toLowerCase();

    const passwords = await readPasswordsFile();
    const isValid = passwords[lowerAddress] === password;

    res.json({ valid: isValid });
  } catch (error) {
    logger.error('Password verification error:', { error });
    next(error);
  }
});

app.post('/api/register-address', validateAddressRegistration, async (req, res, next) => {
  try {
    const { address } = req.body;
    const lowerAddress = address.toLowerCase();

    const passwords = await readPasswordsFile();

    if (passwords[lowerAddress]) {
      return res.status(409).json({ 
        error: 'Address already registered' 
      });
    }

    const password = generatePassword();
    passwords[lowerAddress] = password;
    await writePasswordsFile(passwords);

    logger.info('New address registered', { address: lowerAddress });

    res.json({ 
      success: true,
      address: lowerAddress,
      password: password
    });
  } catch (error) {
    logger.error('Address registration error:', { error });
    next(error);
  }
});

// Error Handlers
app.use((err, req, res, next) => {
  if (err.code === 'ERR_ERL_PERMISSIVE_TRUST_PROXY') {
    logger.warn('Rate limit trust proxy warning:', { error: err });
    next();
  } else {
    next(err);
  }
});

const errorHandler = (err, req, res, next) => {
  const errorId = Math.random().toString(36).substring(7);
  healthCheck.failedRequests++;
  
  logger.error({
    message: 'Server error',
    errorId,
    error: {
      name: err.name,
      message: err.message,
      stack: err.stack
    },
    request: {
      method: req.method,
      path: req.path,
      headers: req.headers,
      body: req.body
    }
  });

  healthCheck.lastError = {
    time: new Date(),
    errorId,
    message: err.message
  };

  serverState.lastError = {
    time: new Date(),
    errorId,
    message: err.message
  };

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      status: 'error',
      message: 'CORS error: Origin not allowed'
    });
  }
  
  res.status(500).json({
    status: 'error',
    errorId,
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
};

app.use(errorHandler);

// Server startup and management
const PORT = process.env.PORT || 3000;

async function startServer() {
  return new Promise((resolve, reject) => {
    let promiseHandled = false;

    const startServerInstance = () => {
      try {
        server = app.listen(PORT, '127.0.0.1', () => {
          healthCheck.startTime = new Date();
          serverState.lastRestartTime = new Date();
          serverState.failureReason = null;
          restartAttempts = 0;

          logger.info({
            message: `Server running on port ${PORT} in ${process.env.NODE_ENV} mode`,
            state: {
              port: PORT,
              mode: process.env.NODE_ENV,
              startTime: healthCheck.startTime,
              pid: process.pid
            }
          });
          
          resolve(server);
        });

        // Enhanced error handling for server
        server.on('error', (error) => {
          logger.error('Server error:', error);
          serverState.failureReason = error.code || 'unknown_error';
          healthCheck.lastError = {
            time: new Date(),
            error: error.message
          };
          
          if (!isShuttingDown) {
            scheduleRestart();
          }
        });

        // Keep-alive timeout
        server.keepAliveTimeout = 65000;
        server.headersTimeout = 66000;
        
        // Monitor connections
        server.on('connection', (socket) => {
          socket.setTimeout(60000); // 60 second timeout
        });

      } catch (error) {
        if (!promiseHandled) {
          promiseHandled = true;
          logger.error('Failed to start server:', error);
          reject(error);
        }
      }
    };

    // Check if port is in use before starting
    const net = require('net');
    const testServer = net.createServer()
      .once('error', async (err) => {
        if (err.code === 'EADDRINUSE') {
          logger.error(`Port ${PORT} is in use. Attempting to force close...`);
          // Try to force close any existing connections
          await new Promise(resolve => {
            require('child_process').exec(
              `lsof -i :${PORT} | grep LISTEN | awk '{print $2}' | xargs kill -9`,
              resolve
            );
          });
        }
        if (!promiseHandled) {
          promiseHandled = true;
          startServerInstance();
        }
      })
      .once('listening', () => {
        testServer.close();
        if (!promiseHandled) {
          promiseHandled = true;
          startServerInstance();
        }
      })
      .listen(PORT);
  });
}

// Enhanced restart mechanism
function scheduleRestart() {
  if (restartAttempts >= MAX_RESTART_ATTEMPTS) {
    logger.error('Maximum restart attempts reached. Exiting...', {
      attempts: restartAttempts,
      healthCheck,
      serverState
    });
    process.exit(1);
  }
  
  const delay = Math.min(
    BASE_RETRY_DELAY * Math.pow(2, restartAttempts),
    300000
  );
  restartAttempts++;
  
  logger.info({
    message: 'Scheduling server restart',
    attempt: restartAttempts,
    delay,
    healthCheck,
    serverState
  });
  
  setTimeout(async () => {
    try {
      if (server) {
        await new Promise((resolve) => {
          server.close(() => {
            connectionTracker.clear();
            healthCheck.activeConnections = 0;
            serverState.activeConnections = 0;
            resolve();
          });
        });
      }
      await startServer();
    } catch (error) {
      logger.error('Restart failed:', error);
      scheduleRestart();
    }
  }, delay);
}

// Enhanced shutdown handler
async function shutdownServer() {
  isShuttingDown = true;
  logger.info('Starting graceful shutdown...', {
    activeConnections: healthCheck.activeConnections,
    serverState
  });

  try {
    // Stop accepting new connections
    if (server) {
      server.close();
    }
    
    // Give existing connections time to complete
    const forcedShutdownTimeout = setTimeout(() => {
      logger.warn('Forcing shutdown after timeout', {
        remainingConnections: healthCheck.activeConnections
      });
      process.exit(1);
    }, 30000);
    
    // Wait for active connections to finish
    while (healthCheck.activeConnections > 0) {
      logger.info(`Waiting for ${healthCheck.activeConnections} connections to close...`);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    clearTimeout(forcedShutdownTimeout);
    logger.info('Server shut down successfully');
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown:', error);
    process.exit(1);
  }
}

// Graceful shutdown signals
process.on('SIGTERM', shutdownServer);
process.on('SIGINT', shutdownServer);

// Enhanced error handling
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', {
    error,
    healthCheck,
    serverState,
    stack: error.stack
  });
  
  if (!isShuttingDown) {
    scheduleRestart();
  }
});

process.on('unhandledRejection', (error) => {
  logger.error('Unhandled Rejection:', {
    error,
    healthCheck,
    serverState,
    stack: error.stack
  });
  
  if (!isShuttingDown) {
    scheduleRestart();
  }
});

// Start server
startServer().catch(error => {
  logger.error('Initial server startup failed:', error);
  scheduleRestart();
});