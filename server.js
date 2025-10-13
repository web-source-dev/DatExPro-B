const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cookie-manager';

// Security: Secret token for admin and extension
const API_SECRET = process.env.API_SECRET || 'your-super-secret-api-key-change-this-in-production';

// CORS configuration - only allow Chrome extension and localhost admin
const corsOptions = {
  origin: function (origin, callback) {
    // Allow Chrome extension (chrome-extension://)
    // Allow localhost for admin panel (development)
    // Allow no origin (for same-origin requests)
    if (!origin || 
        origin.startsWith('chrome-extension://') || 
        origin === 'http://localhost:3000' ||
        origin === 'https://dat-ex-pro.vercel.app' ||
        origin === 'http://127.0.0.1:3000' ||
        origin === 'http://127.0.0.1:3001') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Secret', 'X-Client-Type', 'X-Challenge-Token', 'X-Extension-Id']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting storage (in-memory, use Redis in production)
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 100;

// Challenge token storage (temporary tokens for request verification)
const challengeTokens = new Map();
const CHALLENGE_TOKEN_EXPIRY = 300000; // 5 minutes
const VERIFICATION_SECRET = crypto.randomBytes(64).toString('hex'); // Master verification key

// Clean up expired challenge tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of challengeTokens.entries()) {
    if (now > data.expiresAt) {
      challengeTokens.delete(token);
    }
  }
}, 60000); // Clean every minute

// Rate limiting middleware
function rateLimiter(req, res, next) {
  const clientId = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (!requestCounts.has(clientId)) {
    requestCounts.set(clientId, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return next();
  }
  
  const clientData = requestCounts.get(clientId);
  
  if (now > clientData.resetTime) {
    // Reset the counter
    clientData.count = 1;
    clientData.resetTime = now + RATE_LIMIT_WINDOW;
    return next();
  }
  
  if (clientData.count >= MAX_REQUESTS_PER_WINDOW) {
    return res.status(429).json({ 
      error: 'Too many requests. Please try again later.' 
    });
  }
  
  clientData.count++;
  next();
}

// Generate challenge token with HMAC signature
function generateChallengeToken() {
  const randomToken = crypto.randomBytes(32).toString('hex');
  const timestamp = Date.now();
  
  // Sign the token with verification secret
  const signature = crypto
    .createHmac('sha256', VERIFICATION_SECRET)
    .update(`${randomToken}:${timestamp}`)
    .digest('hex');
  
  const challengeToken = `${randomToken}.${timestamp}.${signature}`;
  
  return { challengeToken, timestamp };
}

// Verify challenge token
function verifyChallengeToken(token) {
  try {
    if (!token) return false;
    
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    const [randomToken, timestamp, signature] = parts;
    
    // Verify signature
    const expectedSignature = crypto
      .createHmac('sha256', VERIFICATION_SECRET)
      .update(`${randomToken}:${timestamp}`)
      .digest('hex');
    
    if (signature !== expectedSignature) {
      return false;
    }
    
    // Check if token exists in storage
    if (!challengeTokens.has(token)) {
      return false;
    }
    
    // Check if token has expired
    const tokenData = challengeTokens.get(token);
    if (Date.now() > tokenData.expiresAt) {
      challengeTokens.delete(token);
      return false;
    }
    
    // Token is valid - delete it (one-time use)
    challengeTokens.delete(token);
    return true;
  } catch (error) {
    console.error('Error verifying challenge token:', error);
    return false;
  }
}

// Middleware to validate challenge token
function validateChallengeToken(req, res, next) {
  const challengeToken = req.headers['x-challenge-token'] || req.body.challengeToken || req.query.challengeToken;
  
  if (!verifyChallengeToken(challengeToken)) {
    return res.status(403).json({ 
      error: 'Invalid or expired challenge token. Request a new challenge.' 
    });
  }
  
  next();
}

// Security middleware - Validate API access based on client type
function validateApiAccess(req, res, next) {
  const apiSecret = req.headers['x-api-secret'];
  const clientType = req.headers['x-client-type'];
  const extensionId = req.headers['x-extension-id'];
  
  // Check if client type is valid
  if (clientType !== 'extension' && clientType !== 'admin') {
    return res.status(403).json({ 
      error: 'Forbidden: Invalid client type' 
    });
  }
  
  // For admin requests, require API secret
  if (clientType === 'admin') {
    if (apiSecret !== API_SECRET) {
      return res.status(403).json({ 
        error: 'Forbidden: Invalid API credentials' 
      });
    }
  }
  
  // For extension requests, validate extension ID (optional but recommended)
  if (clientType === 'extension') {
    // Extension ID validation - you can whitelist specific extension IDs
    // For unpacked extensions, the ID changes, so we'll allow any chrome-extension origin
    const origin = req.headers.origin || req.headers.referer;
    
    if (origin && !origin.startsWith('chrome-extension://')) {
      return res.status(403).json({ 
        error: 'Forbidden: Invalid extension origin' 
      });
    }
    
    // Extension relies on user secret key validation (validateSecretKey middleware)
    // No shared secret required - each user has their own secret key
  }
  
  req.clientType = clientType;
  next();
}

// Apply rate limiting and security to all routes
app.use(rateLimiter);

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  secretKey: { type: String, required: true, unique: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  blocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const cookieDataSchema = new mongoose.Schema({
  secretKey: { type: String, required: true, index: true },
  domain: { type: String, required: true },
  cookies: { type: Array, required: true },
  lastUpdated: { type: Date, default: Date.now }
});

// Create compound index for efficient queries
cookieDataSchema.index({ secretKey: 1, domain: 1 }, { unique: true });

const User = mongoose.model('User', userSchema);
const CookieData = mongoose.model('CookieData', cookieDataSchema);

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
  })
  .catch((error) => {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  });

// Middleware to validate secret key
async function validateSecretKey(req, res, next) {
  const key = req.body.key || req.query.key;
  
  if (!key) {
    return res.status(400).json({ error: 'Secret key is required' });
  }
  
  if (typeof key !== 'string' || key.trim().length === 0) {
    return res.status(400).json({ error: 'Secret key must be a non-empty string' });
  }
  
  try {
    // Check if user is blocked
    const user = await User.findOne({ secretKey: key.trim() });
    
    if (user && user.blocked) {
      return res.status(403).json({ error: 'Access blocked. Contact administrator.' });
    }
    
    req.secretKey = key.trim();
    next();
  } catch (error) {
    console.error('Error validating secret key:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// API Routes

// POST /auth/challenge - Get a challenge token (no authentication required for this endpoint)
app.post('/auth/challenge', validateApiAccess, async (req, res) => {
  try {
    const { challengeToken, timestamp } = generateChallengeToken();
    
    // Store the token with expiration
    challengeTokens.set(challengeToken, {
      createdAt: timestamp,
      expiresAt: timestamp + CHALLENGE_TOKEN_EXPIRY,
      clientType: req.clientType
    });
    
    res.json({
      challengeToken,
      expiresIn: CHALLENGE_TOKEN_EXPIRY,
      timestamp
    });
  } catch (error) {
    console.error('Error generating challenge token:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /auth/userinfo - Get user information by secret key
app.get('/auth/userinfo', validateApiAccess, validateChallengeToken, validateSecretKey, async (req, res) => {
  try {
    const secretKey = req.secretKey;
    
    const user = await User.findOne({ secretKey });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      blocked: user.blocked,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Error getting user info:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /saveCookies - Save cookies for a domain and user
app.post('/saveCookies', validateApiAccess, validateChallengeToken, validateSecretKey, async (req, res) => {
  try {
    const { domain, cookies } = req.body;
    const secretKey = req.secretKey;
    
    if (!domain || !cookies || !Array.isArray(cookies)) {
      return res.status(400).json({ 
        error: 'Domain and cookies array are required' 
      });
    }
    
    // Upsert cookie data
    await CookieData.findOneAndUpdate(
      { secretKey, domain },
      { 
        secretKey,
        domain,
        cookies,
        lastUpdated: new Date()
      },
      { upsert: true, new: true }
    );
    
    res.json({ 
      message: `Saved ${cookies.length} cookies for domain: ${domain}`,
      count: cookies.length
    });
  } catch (error) {
    console.error('Error saving cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /getCookies - Get cookies for a domain and user
app.get('/getCookies', validateApiAccess, validateChallengeToken, validateSecretKey, async (req, res) => {
  try {
    const { domain } = req.query;
    const secretKey = req.secretKey;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain parameter is required' });
    }
    
    const cookieData = await CookieData.findOne({ secretKey, domain });
    
    if (!cookieData) {
      return res.json({ 
        message: 'No cookies found for this domain',
        cookies: []
      });
    }
    
    res.json({
      domain: domain,
      cookies: cookieData.cookies,
      lastUpdated: cookieData.lastUpdated,
      count: cookieData.cookies.length
    });
  } catch (error) {
    console.error('Error getting cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /importCookies - Import cookies JSON for a user
app.post('/importCookies', validateApiAccess, validateChallengeToken, validateSecretKey, async (req, res) => {
  try {
    const { cookies } = req.body;
    const secretKey = req.secretKey;
    
    if (!cookies || typeof cookies !== 'object') {
      return res.status(400).json({ 
        error: 'Cookies object is required' 
      });
    }
    
    let importedCount = 0;
    const bulkOps = [];
    
    // Prepare bulk operations
    for (const [domain, domainData] of Object.entries(cookies)) {
      if (domainData && domainData.cookies && Array.isArray(domainData.cookies)) {
        bulkOps.push({
          updateOne: {
            filter: { secretKey, domain },
            update: {
              $set: {
                secretKey,
                domain,
                cookies: domainData.cookies,
                lastUpdated: new Date()
              }
            },
            upsert: true
          }
        });
        importedCount += domainData.cookies.length;
      }
    }
    
    if (bulkOps.length > 0) {
      await CookieData.bulkWrite(bulkOps);
    }
    
    res.json({ 
      message: `Imported ${importedCount} cookies across ${bulkOps.length} domains`,
      importedCount: importedCount,
      domainsCount: bulkOps.length
    });
  } catch (error) {
    console.error('Error importing cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /exportCookies - Export all cookies for a user
app.get('/exportCookies', validateApiAccess, validateChallengeToken, validateSecretKey, async (req, res) => {
  try {
    const secretKey = req.secretKey;
    
    const allCookieData = await CookieData.find({ secretKey });
    
    if (allCookieData.length === 0) {
      return res.json({ 
        message: 'No cookies found for this user',
        cookies: {}
      });
    }
    
    // Format data in the expected structure
    const cookies = {};
    let totalCount = 0;
    
    allCookieData.forEach(data => {
      cookies[data.domain] = {
        cookies: data.cookies,
        lastUpdated: data.lastUpdated
      };
      totalCount += data.cookies.length;
    });
    
    res.json({
      cookies: cookies,
      totalCount: totalCount,
      domainsCount: allCookieData.length,
      exportedAt: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error exporting cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /generateKey - Generate a new secret key
app.get('/generateKey', validateApiAccess, (req, res) => {
  try {
    // Generate a cryptographically secure random key
    const secretKey = crypto.randomBytes(32).toString('hex');
    
    res.json({
      key: secretKey,
      message: 'Secret key generated successfully',
      timestamp: new Date().toISOString(),
      keyLength: secretKey.length
    });
  } catch (error) {
    console.error('Error generating secret key:', error);
    res.status(500).json({ error: 'Failed to generate secret key' });
  }
});

// User Management API Routes

// POST /admin/users - Create a new user
app.post('/admin/users', validateApiAccess, validateChallengeToken, async (req, res) => {
  try {
    const { name, email, phone, role } = req.body;
    
    if (!name || !email || !phone) {
      return res.status(400).json({ 
        error: 'Name, email, and phone are required' 
      });
    }
    
    // Validate role
    const userRole = role || 'user';
    if (userRole !== 'admin' && userRole !== 'user') {
      return res.status(400).json({ error: 'Role must be either "admin" or "user"' });
    }
    
    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    
    // Generate secret key
    const secretKey = crypto.randomBytes(32).toString('hex');
    
    const newUser = new User({
      name,
      email,
      phone,
      secretKey,
      role: userRole,
      blocked: false
    });
    
    await newUser.save();
    
    res.json({ 
      message: 'User created successfully',
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        phone: newUser.phone,
        secretKey: newUser.secretKey,
        role: newUser.role,
        blocked: newUser.blocked,
        createdAt: newUser.createdAt
      }
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /admin/users - Get all users with their cookie stats
app.get('/admin/users', validateApiAccess, validateChallengeToken, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    
    // Enhance users with cookie statistics
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const cookieData = await CookieData.find({ secretKey: user.secretKey });
        
        const domains = cookieData.map(data => data.domain);
        const totalCookies = cookieData.reduce((sum, data) => sum + data.cookies.length, 0);
        
        return {
          id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          secretKey: user.secretKey,
          role: user.role,
          blocked: user.blocked,
          createdAt: user.createdAt,
          domainsCount: domains.length,
          cookiesCount: totalCookies,
          domains: domains
        };
      })
    );
    
    res.json({
      users: usersWithStats,
      totalUsers: usersWithStats.length
    });
  } catch (error) {
    console.error('Error getting users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /admin/users/:id/block - Block/unblock a user
app.put('/admin/users/:id/block', validateApiAccess, validateChallengeToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { blocked } = req.body;
    
    if (typeof blocked !== 'boolean') {
      return res.status(400).json({ error: 'Blocked must be a boolean' });
    }
    
    const user = await User.findByIdAndUpdate(
      id,
      { blocked },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ 
      message: `User ${blocked ? 'blocked' : 'unblocked'} successfully`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        secretKey: user.secretKey,
        blocked: user.blocked,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error blocking/unblocking user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /admin/users/:id/cookies - Delete all cookies for a user
app.delete('/admin/users/:id/cookies', validateApiAccess, validateChallengeToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const user = await User.findById(id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const result = await CookieData.deleteMany({ secretKey: user.secretKey });
    
    res.json({ 
      message: `Deleted ${result.deletedCount} cookie records`,
      userId: id,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Error deleting cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /admin/users/:id/upload - Upload cookies JSON for a user
app.post('/admin/users/:id/upload', validateApiAccess, validateChallengeToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { cookies } = req.body;
    
    if (!cookies || typeof cookies !== 'object') {
      return res.status(400).json({ 
        error: 'Cookies object is required' 
      });
    }
    
    const user = await User.findById(id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    let importedCount = 0;
    const bulkOps = [];
    
    // Import cookies for each domain
    for (const [domain, domainData] of Object.entries(cookies)) {
      if (domainData && domainData.cookies && Array.isArray(domainData.cookies)) {
        bulkOps.push({
          updateOne: {
            filter: { secretKey: user.secretKey, domain },
            update: {
              $set: {
                secretKey: user.secretKey,
                domain,
                cookies: domainData.cookies,
                lastUpdated: new Date()
              }
            },
            upsert: true
          }
        });
        importedCount += domainData.cookies.length;
      }
    }
    
    if (bulkOps.length > 0) {
      await CookieData.bulkWrite(bulkOps);
    }
    
    res.json({ 
      message: `Uploaded ${importedCount} cookies across ${bulkOps.length} domains`,
      importedCount: importedCount,
      domainsCount: bulkOps.length,
      userId: id
    });
  } catch (error) {
    console.error('Error uploading cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /admin/users/bulk/block - Bulk block/unblock users
app.post('/admin/users/bulk/block', validateApiAccess, validateChallengeToken, async (req, res) => {
  try {
    const { userIds, blocked } = req.body;
    
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'userIds array is required' });
    }
    
    if (typeof blocked !== 'boolean') {
      return res.status(400).json({ error: 'blocked must be a boolean' });
    }
    
    const result = await User.updateMany(
      { _id: { $in: userIds } },
      { $set: { blocked } }
    );
    
    res.json({ 
      message: `${result.modifiedCount} users ${blocked ? 'blocked' : 'unblocked'} successfully`,
      updatedCount: result.modifiedCount
    });
  } catch (error) {
    console.error('Error bulk blocking users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /admin/users/bulk/cookies - Bulk delete cookies for users
app.delete('/admin/users/bulk/cookies', validateApiAccess, validateChallengeToken, async (req, res) => {
  try {
    const { userIds } = req.body;
    
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'userIds array is required' });
    }
    
    const users = await User.find({ _id: { $in: userIds } });
    const secretKeys = users.map(u => u.secretKey);
    
    const result = await CookieData.deleteMany({ 
      secretKey: { $in: secretKeys } 
    });
    
    res.json({ 
      message: `Cookies deleted for ${users.length} users`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Error bulk deleting cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /contact-info - Get contact information
app.get('/contact-info', (req, res) => {
  res.json({
    phone: "+92 (318) 334-2804, +92 (304) 967-2196"
  });
});

// GET /health - Health check endpoint
app.get('/health', async (req, res) => {
  try {
    // Check MongoDB connection
    const mongoStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      service: 'Cookie Manager Backend',
      mongodb: mongoStatus
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'ERROR',
      error: error.message 
    });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🍪 Cookie Manager Backend running on port ${PORT}`);
  console.log(`📊 MongoDB URI: ${MONGODB_URI}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});
