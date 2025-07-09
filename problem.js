const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const retry = require('async-retry');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const { combine, timestamp, printf, colorize } = winston.format;

// Load environment variables
if (fs.existsSync(path.join(__dirname, 'server.env'))) {
  dotenv.config({ path: path.join(__dirname, 'server.env') });
} else {
  dotenv.config();
}

const app = express();

// Create Uploads directory if it doesn't exist
const uploadDir = './Uploads/';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Enhanced Logging Setup
const logDir = 'logs';
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logFormat = printf(({ level, message, timestamp, stack }) => {
  return `${timestamp} [${level}] ${stack || message}`;
});

const logger = winston.createLogger({
  level: 'debug',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    logFormat
  ),
  transports: [
    new winston.transports.Console({
      format: combine(
        colorize(),
        timestamp({ format: 'HH:mm:ss' }),
        printf(info => `${info.timestamp} [${info.level}] ${info.message}`)
      )
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      level: 'info'
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'errors.log'),
      level: 'error'
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'auth.log'),
      level: 'debug',
      format: combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        printf(({ message }) => message)
      )
    })
  ]
});

// Environment logging
logger.info('Environment Configuration:', {
  DB_USER: process.env.DB_USER,
  DB_HOST: process.env.DB_HOST,
  DB_NAME: process.env.DB_NAME,
  DB_PASSWORD: '****',
  DB_PORT: process.env.DB_PORT,
  FRONTEND_URL: process.env.FRONTEND_URL,
  JWT_SECRET: process.env.JWT_SECRET ? '****' : 'Not set',
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV
});

// Server Configuration
const allowedOrigins = [
  'http://44.223.23.145:8012',
  'http://44.223.23.145:8013',
  'http://44.223.23.145:8057',
  'http://44.223.23.145:8010',
  'http://44.223.23.145:3404',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5502',
  'http://localhost:8012',
  'http://localhost:8013',
  'http://localhost:8057',
  'http://localhost:8010',
  process.env.FRONTEND_URL || 'http://44.223.23.145:3404',
];

app.use(cors({
  origin: (origin, callback) => {
    logger.debug(`CORS request from: ${origin}`);
    if (!origin || allowedOrigins.includes(origin) || origin === 'null') {
      callback(null, true);
    } else {
      logger.warn(`CORS blocked: ${origin}`);
      callback(new Error(`CORS policy: Origin ${origin} not allowed`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use('/uploads', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
}, express.static(path.join(__dirname, 'Uploads')));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  const { method, originalUrl, ip } = req;

  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${method} ${originalUrl} ${res.statusCode} ${duration}ms - ${ip}`);

    if (originalUrl.includes('/auth') || originalUrl.includes('/login') || originalUrl.includes('/logout')) {
      logger.debug(`Auth Request: ${method} ${originalUrl}`, {
        headers: req.headers,
        body: method === 'POST' ? req.body : null
      });
    }
  });

  next();
});

// Database Configuration
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'postgres-ajay',
  database: process.env.DB_NAME || 'new_employee_db',
  password: process.env.DB_PASSWORD || 'admin123',
  port: process.env.DB_PORT || 5432,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

pool.on('connect', (client) => {
  logger.debug('Database client connected');
});

pool.on('error', (err) => {
  logger.error('Database pool error:', err);
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'Abderoiouwi@12342';
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';
const verifyToken = (req, res, next) => {
  const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];

  if (!token) {
    logger.warn('Access denied: No token provided');
    return res.status(401).json({ error: 'Access denied, no token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    logger.debug(`Authenticated request from: ${decoded.email}`);
    next();
  } catch (err) {
    logger.error('Token verification failed:', err.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// File Upload Configuration
const storage = multer.diskStorage({
  destination: './Uploads/',
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Database Initialization with robust table creation
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create user_accounts table
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_accounts (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        profile_image TEXT,
        is_verified BOOLEAN DEFAULT FALSE,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create auth_sessions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES user_accounts(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
      );
    `);

    // Create personnel table with explicit column creation
    await client.query(`
      CREATE TABLE IF NOT EXISTS personnel (
        emp_id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        job_role VARCHAR(100),
        location VARCHAR(100),
        department VARCHAR(100),
        hire_date DATE,
        phone VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Verify personnel table structure
    const check = await client.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'personnel' AND column_name = 'emp_id'
    `);

    if (check.rows.length === 0) {
      throw new Error('Failed to create emp_id column in personnel table');
    }

    // Create indexes
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_email ON user_accounts(email);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON auth_sessions(token);
      CREATE INDEX IF NOT EXISTS idx_personnel_email ON personnel(email);
    `);

    await client.query('COMMIT');
    logger.info('Database schema initialized successfully');
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error('Database initialization failed:', err);
    throw err;
  } finally {
    client.release();
  }
}

async function connectWithRetry() {
  return retry(
    async () => {
      const client = await pool.connect();
      try {
        await client.query('SELECT 1');
        logger.info('Successfully connected to PostgreSQL');
        await initializeDatabase();
      } finally {
        client.release();
      }
    },
    {
      retries: 10,
      factor: 2,
      minTimeout: 1000,
      maxTimeout: 10000,
      onRetry: (err, attempt) => {
        logger.warn(`Retry attempt ${attempt}: ${err.message}`);
        if (attempt === 10) {
          logger.error('Maximum retry attempts reached. Exiting...');
          process.exit(1);
        }
      }
    }
  );
}

connectWithRetry().catch(err => {
  logger.error('Fatal database connection error:', err);
  process.exit(1);
});

// API Endpoints

// Enhanced health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const dbCheck = await pool.query('SELECT 1');
    const uptime = process.uptime();

    // Verify personnel table structure
    const tableCheck = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'personnel'
    `);

    const hasEmpId = tableCheck.rows.some(row => row.column_name === 'emp_id');

    res.json({
      status: hasEmpId ? 'healthy' : 'degraded',
      db: dbCheck ? 'connected' : 'disconnected',
      tables: tableCheck.rows,
      uptime: `${Math.floor(uptime / 60)} minutes`,
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (err) {
    logger.error('Health check failed:', err);
    res.status(503).json({
      status: 'unhealthy',
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Check email availability endpoint
app.post('/check-email-data', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const result = await pool.query('SELECT id FROM user_accounts WHERE email = $1', [email]);
    res.json({ exists: result.rows.length > 0 });
  } catch (err) {
    logger.error('Check email error:', err);
    res.status(500).json({ error: 'Error checking email availability' });
  }
});

// Signup endpoint
app.post('/api/signup', upload.single('profileImage'), async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const emailRegex = /^[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*@(gmail\.com|outlook\.com)$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Only gmail.com or outlook.com domains allowed' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const userExists = await pool.query(
      'SELECT id FROM user_accounts WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (userExists.rows.length > 0) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const profileImage = req.file ? `/uploads/${req.file.filename}` : null;

    const result = await pool.query(
      `INSERT INTO user_accounts
       (username, email, password, profile_image)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, profile_image, created_at`,
      [username, email, hashedPassword, profileImage]
    );

    const verificationToken = jwt.sign(
      { userId: result.rows[0].id, email: result.rows[0].email },
      JWT_SECRET,
      { expiresIn: '1d' }
    );

    logger.debug(`Verification token generated for ${email}`);

    res.status(201).json({
      message: 'User created successfully.',
      user: result.rows[0]
    });
  } catch (err) {
    logger.error('Signup error:', err);

    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }

    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// Login endpoint with personnel data handling
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, email, password, profile_image FROM user_accounts WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      logger.warn(`Login attempt for non-existent email: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      logger.warn(`Invalid password attempt for email: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      JWT_SECRET,
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    await pool.query(
      'INSERT INTO auth_sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    logger.debug(`User ${email} logged in successfully`);

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    const { password: _, ...userData } = user;

    // Fetch personnel details with error handling
    let personnelData = null;
    try {
      const personnelResult = await pool.query(
        'SELECT emp_id, name, email, job_role, location, department, hire_date, phone FROM personnel WHERE email = $1',
        [email]
      );
      personnelData = personnelResult.rows.length > 0 ? personnelResult.rows[0] : null;
    } catch (personnelErr) {
      logger.warn('Personnel data fetch failed, proceeding without:', personnelErr.message);
      personnelData = null;
    }

    res.json({
      message: 'Login successful',
      user: userData,
      personnel: personnelData,
      accessToken,
      refreshToken
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Personnel details endpoint
app.get('/api/personnel', verifyToken, async (req, res) => {
  try {
    const { email } = req.user;
    const result = await pool.query(
      'SELECT emp_id, name, email, job_role, location, department, hire_date, phone FROM personnel WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Personnel details not found' });
    }

    res.json({
      message: 'Personnel details fetched successfully',
      personnel: result.rows[0]
    });
  } catch (err) {
    logger.error('Personnel fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch personnel details' });
  }
});

// Profile endpoint
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const { userId } = req.user;

    const result = await pool.query(
      'SELECT id, username, email, profile_image FROM user_accounts WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    const profileData = {
      ...user,
      profile_image: user.profile_image
        ? `${req.protocol}://${req.get('host')}${user.profile_image}`
        : null
    };

    res.json({
      message: 'Profile fetched successfully',
      profile: profileData
    });
  } catch (err) {
    logger.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Logout endpoint
app.post('/api/logout', verifyToken, async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    await pool.query('DELETE FROM auth_sessions WHERE token = $1', [refreshToken]);

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    logger.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Forgot Password endpoint
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const result = await pool.query(
      'SELECT id FROM user_accounts WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      logger.warn(`Password reset attempt for non-existent email: ${email}`);
      return res.status(404).json({ error: 'Email not found' });
    }

    const resetToken = jwt.sign(
      { userId: result.rows[0].id, email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    await pool.query(
      'UPDATE user_accounts SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
      [resetToken, new Date(Date.now() + 60 * 60 * 1000), email]
    );

    logger.debug(`Password reset token generated for ${email}`);

    res.json({ message: 'Password reset link sent to your email.' });
  } catch (err) {
    logger.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process request. Please try again.' });
  }
});

// Error Handling
app.use((err, req, res, next) => {
  logger.error('Server error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'File upload error: ' + err.message });
  }

  res.status(500).json({ error: 'Internal server error' });
});

// Server Startup
const PORT = process.env.PORT || 3404;
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Allowed CORS origins: ${allowedOrigins.join(', ')}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Log rotation
function rotateLogs() {
  const files = fs.readdirSync(logDir);
  const dateStr = new Date().toISOString().split('T')[0];

  files.forEach(file => {
    if (file.endsWith('.log') && !file.includes(dateStr)) {
      const oldPath = path.join(logDir, file);
      const newPath = `${oldPath}-${dateStr}`;
      fs.renameSync(oldPath, newPath);
    }
  });
}

setInterval(() => {
  const now = new Date();
  if (now.getHours() === 0 && now.getMinutes() === 0) {
    rotateLogs();
  }
}, 60 * 1000);
document.addEventListener('DOMContentLoaded', async () => {
  const config = {
    apiBaseUrl: 'http://44.223.23.145:3404/api',
    authUrls: {
      login: 'http://44.223.23.145:8012',
      signup: 'http://44.223.23.145:8013/',
      forgotPassword: 'http://44.223.23.145:8010'
    },
    modules: {
      emp_attendance: 'http://44.223.23.145:8051/',
      emp_leave: 'http://44.223.23.145:8037/',
      emp_wfh: 'http://44.223.23.145:8025/',
      emp_payslip: 'http://3.85.61.23:7019/',
      emp_tasks: 'http://44.223.23.145:8045/',
      emp_helpdesk: 'http://44.223.23.145:8049/',
      emp_Onboarding: 'http://44.223.23.145:8039/',
      emp_benefits: 'http://44.223.23.145:8043/',
      emp_Appraisal: 'http://44.223.23.145:8014/',
      emp_notifications: 'http://44.223.23.145:8053/',
      emp_asset: 'http://44.223.23.145:8047/',
      emp_bonus: 'http://44.223.23.145:8055/',
      emp_joblists: 'http://3.85.61.23:8020/',
      emp_claim: 'http://44.223.23.145:8027/',
      emp_offboarding: 'http://44.223.23.145:8041/',
      emp_jobapplication: 'http://44.223.23.145:8031/',
      emp_offerletter: 'http://44.223.23.145:8033/',
      emp_logout: '',
      hr_attendance: 'http://44.223.23.145:8052/',
      hr_leave: 'http://44.223.23.145:8038/',
      hr_wfh: 'http://44.223.23.145:8026/',
      hr_payslip: 'http://3.85.61.23:7020/',
      hr_tasks: 'http://44.223.23.145:8046/',
      hr_helpdesk: 'http://44.223.23.145:8050/',
      hr_Onboarding: 'http://44.223.23.145:8040/',
      hr_employeemanagement: 'http://44.223.23.145:8036/',
      hr_benefits: 'http://44.223.23.145:8044/',
      hr_appraisal: 'http://44.223.23.145:8015/',
      hr_notifications: 'http://44.223.23.145:8054/',
      hr_asset: 'http://44.223.23.145:8048/',
      hr_bonus: 'http://44.223.23.145:8056/',
      hr_joblists: 'http://3.85.61.23:8021/',
      hr_claim: 'http://44.223.23.145:8028/',
      hr_offboarding: 'http://44.223.23.145:8042/',
      hr_jobapplication: 'http://44.223.23.145:8032/',
      hr_logout: ''
    },
    sessionCheckInterval: 300000
  };

  const elements = {
    appBody: document.getElementById('appBody'),
    loginView: document.getElementById('loginView'),
    dashboardView: document.getElementById('dashboardView'),
    loginForm: document.getElementById('loginForm'),
    emailInput: document.getElementById('email'),
    passwordInput: document.getElementById('password'),
    errorMessage: document.getElementById('error-message'),
    eyeIcon: document.getElementById('eyeIcon'),
    loginButton: document.querySelector('.login-button'),
    contentFrame: document.getElementById('contentFrame'),
    avatarSkeleton: document.getElementById('avatarSkeleton'),
    userAvatar: document.getElementById('userAvatar'),
    userName: document.getElementById('userName'),
    themeToggle: document.getElementById('themeToggle'),
    toggleBtn: document.getElementById('toggleBtn'),
    radialMenu: document.getElementById('radialMenu'),
    innerCircle: document.getElementById('innerCircle'),
    moduleSelector: document.getElementById('moduleSelector'),
    empMenu: document.getElementById('empMenu'),
    hrMenu: document.getElementById('hrMenu'),
    mainContent: document.getElementById('mainContent'),
    searchInput: document.getElementById('searchInput'),
    searchButton: document.getElementById('searchButton'),
    searchBar: document.getElementById('searchBar'),
    autocompleteDropdown: document.getElementById('autocompleteDropdown')
  };

  const state = {
    user: null,
    token: null,
    refreshToken: null,
    isDarkMode: false,
    isAuthenticated: false,
    isToggling: false,
    currentMenu: 'emp',
    personnelDetails: null
  };

  const utils = {
    showAlert: (type, message) => {
      const alert = document.createElement('div');
      alert.className = `alert ${type}`;
      const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
      };
      alert.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${message}`;
      document.body.appendChild(alert);
      setTimeout(() => {
        alert.style.animation = 'slideOutRight 0.5s ease-out forwards';
        setTimeout(() => alert.remove(), 500);
      }, 3000);
    },

    handleApiError: (error) => {
      console.error('API Error:', error);
      utils.showAlert('error', error.message || 'An error occurred');
      if (error.status === 401) {
        core.verifySession();
      }
    },

    getCookie: (name) => {
      const value = `; ${document.cookie}`;
      const parts = value.split(`; ${name}=`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    },

    fetchWithAuth: async (url, options = {}) => {
      try {
        let token = utils.getCookie('accessToken') || state.token;
        if (!token) {
          throw { status: 401, message: 'No authentication token found' };
        }

        const response = await fetch(`${config.apiBaseUrl}${url}`, {
          ...options,
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers
          },
          credentials: 'include'
        });

        if (!response.ok) {
          const errorData = await response.json();
          if (response.status === 401 && state.refreshToken) {
            const refreshResponse = await fetch(`${config.apiBaseUrl}/refresh`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ refreshToken: state.refreshToken }),
              credentials: 'include'
            });

            if (refreshResponse.ok) {
              const { accessToken } = await refreshResponse.json();
              document.cookie = `accessToken=${accessToken}; maxAge=900; path=/`;
              state.token = accessToken;
              options.headers = { ...options.headers, 'Authorization': `Bearer ${accessToken}` };
              return await fetch(`${config.apiBaseUrl}${url}`, options);
            }
          }
          throw {
            status: response.status,
            message: errorData.error || 'Request failed'
          };
        }

        return await response.json();
      } catch (error) {
        utils.handleApiError(error);
        throw error;
      }
    }
  };

  const core = {
    showLoginView: () => {
      elements.appBody.classList.add('login-body');
      elements.loginView.classList.remove('hidden');
      elements.dashboardView.classList.add('hidden');
      elements.emailInput.focus();
    },

    showDashboardView: () => {
      elements.appBody.classList.remove('login-body');
      elements.loginView.classList.add('hidden');
      elements.dashboardView.classList.remove('hidden');
      core.initTheme();
      core.initNavigation();
      core.initSessionChecker();
    },

    verifySession: async () => {
      const token = utils.getCookie('accessToken') || state.token;
      const refreshToken = utils.getCookie('refreshToken') || state.refreshToken;

      if (!token && !refreshToken) {
        state.isAuthenticated = false;
        core.showLoginView();
        return false;
      }

      try {
        const response = await utils.fetchWithAuth('/profile');
        state.user = response.profile;
        state.personnelDetails = response.personnel || null;
        
        if (state.personnelDetails) {
          localStorage.setItem('abccompanyempdetails', JSON.stringify(state.personnelDetails));
        }
        
        state.token = token;
        state.isAuthenticated = true;

        setTimeout(() => {
          elements.avatarSkeleton.style.display = 'none';
          elements.userAvatar.style.display = 'block';
          elements.userAvatar.src = state.user.profile_image || 
            'https://img.icons8.com/fluency/48/user-male-circle.png';
          elements.userName.textContent = state.user.username || 'User';
          elements.userName.style.opacity = 0;
          setTimeout(() => {
            elements.userName.style.transition = 'opacity 0.3s ease';
            elements.userName.style.opacity = 1;
          }, 50);
        }, 800);

        core.showDashboardView();
        return true;
      } catch (error) {
        if (refreshToken && error.status === 401) {
          try {
            const refreshResponse = await fetch(`${config.apiBaseUrl}/refresh`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ refreshToken }),
              credentials: 'include'
            });

            if (refreshResponse.ok) {
              const { accessToken } = await refreshResponse.json();
              document.cookie = `accessToken=${accessToken}; maxAge=900; path=/`;
              state.token = accessToken;
              return await core.verifySession();
            }
          } catch (refreshError) {
            console.error('Refresh token failed:', refreshError);
          }
        }
        localStorage.removeItem('abccompanyempdetails');
        sessionStorage.removeItem('user');
        document.cookie = 'accessToken=; Max-Age=0; path=/;';
        document.cookie = 'refreshToken=; Max-Age=0; path=/;';
        state.isAuthenticated = false;
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.personnelDetails = null;
        core.showLoginView();
        return false;
      }
    },

    initTheme: () => {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const savedTheme = localStorage.getItem('theme');
      state.isDarkMode = savedTheme === 'dark' || (!savedTheme && prefersDark);
      if (state.isDarkMode) {
        document.body.classList.add('dark-mode');
        elements.themeToggle.innerHTML = '<i class="material-icons">light_mode</i>';
      } else {
        elements.themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
      }

      elements.themeToggle.addEventListener('click', () => {
        state.isDarkMode = !state.isDarkMode;
        document.body.classList.toggle('dark-mode');
        elements.themeToggle.innerHTML = state.isDarkMode
          ? '<i class="material-icons">light_mode</i>'
          : '<i class="fas fa-moon"></i>';
        localStorage.setItem('theme', state.isDarkMode ? 'dark' : 'light');
      });
    },

    initNavigation: () => {
      const positionMenuItems = (menu, numItems) => {
        const radius = 150;
        const angleStep = 360 / numItems;
        menu.querySelectorAll('.menu-item').forEach((item, index) => {
          const angle = index * angleStep - 90;
          const rad = angle * (Math.PI / 180);
          const x = radius * Math.cos(rad);
          const y = radius * Math.sin(rad);
          item.style.left = `calc(50% + ${x}px - 20px)`;
          item.style.top = `calc(50% + ${y}px - 20px)`;
        });
      };

      positionMenuItems(elements.empMenu, elements.empMenu.querySelectorAll('.menu-item').length);
      positionMenuItems(elements.hrMenu, elements.hrMenu.querySelectorAll('.menu-item').length);

      const showMenu = (menuType) => {
        elements.empMenu.classList.remove('active');
        elements.hrMenu.classList.remove('active');
        if (menuType === 'emp') {
          elements.empMenu.classList.add('active');
        } else if (menuType === 'hr') {
          elements.hrMenu.classList.add('active');
        }
        state.currentMenu = menuType;
        elements.moduleSelector.value = menuType;
      };

      elements.moduleSelector.addEventListener('change', (event) => {
        event.stopPropagation();
        const module = event.target.value;
        showMenu(module);
      });

      [elements.empMenu, elements.hrMenu].forEach(menu => {
        menu.querySelectorAll('.menu-item').forEach(item => {
          item.addEventListener('click', (event) => {
            event.stopPropagation();
            const module = item.dataset.module;
            if (module === 'emp_logout' || module === 'hr_logout') {
              core.handleLogout();
              return;
            }
            if (config.modules[module]) {
              elements.contentFrame.style.opacity = '0.5';
              elements.contentFrame.style.transition = 'opacity 0.3s ease';
              setTimeout(() => {
                elements.contentFrame.src = config.modules[module];
                elements.contentFrame.onload = () => {
                  elements.contentFrame.style.opacity = '1';
                };
              }, 200);
            } else {
              utils.showAlert('error', `Module ${module} not found`);
            }
            elements.radialMenu.classList.add('closing');
            elements.radialMenu.classList.remove('active');
            document.body.classList.remove('menu-open');
            showMenu('emp');
            setTimeout(() => {
              elements.radialMenu.classList.remove('closing');
              elements.toggleBtn.disabled = false;
              state.isToggling = false;
            }, 1000);
          });
        });
      });

      elements.toggleBtn.addEventListener('click', (event) => {
        event.stopPropagation();
        if (state.isToggling) return;
        state.isToggling = true;
        elements.toggleBtn.disabled = true;
        elements.radialMenu.classList.toggle('active');
        document.body.classList.toggle('menu-open');
        if (elements.radialMenu.classList.contains('active')) {
          showMenu('emp');
        } else {
          elements.radialMenu.classList.add('closing');
          setTimeout(() => {
            elements.radialMenu.classList.remove('closing');
            elements.toggleBtn.disabled = false;
            state.isToggling = false;
          }, 1000);
        }
        setTimeout(() => {
          elements.toggleBtn.disabled = false;
          state.isToggling = false;
        }, 1000);
      });

      document.addEventListener('click', (event) => {
        if (elements.radialMenu.classList.contains('active') && 
            !elements.radialMenu.contains(event.target) && 
            !elements.toggleBtn.contains(event.target)) {
          if (state.isToggling) return;
          state.isToggling = true;
          elements.toggleBtn.disabled = true;
          elements.radialMenu.classList.add('closing');
          elements.radialMenu.classList.remove('active');
          document.body.classList.remove('menu-open');
          showMenu('emp');
          setTimeout(() => {
            elements.radialMenu.classList.remove('closing');
            elements.toggleBtn.disabled = false;
            state.isToggling = false;
          }, 1000);
        }
        if (!elements.searchBar.contains(event.target)) {
          elements.autocompleteDropdown.style.display = 'none';
        }
      });

      elements.moduleSelector.addEventListener('click', (event) => {
        event.stopPropagation();
      });

      const moduleNames = {
        emp_attendance: { name: 'Attendance', icon: 'https://img.icons8.com/color/24/calendar--v1.png' },
        emp_leave: { name: 'Leave', icon: 'https://img.icons8.com/color/24/beach.png' },
        emp_wfh: { name: 'WFH', icon: 'https://img.icons8.com/color/24/laptop.png' },
        emp_payslip: { name: 'Payslip', icon: 'https://img.icons8.com/color/24/money-bag.png' },
        emp_tasks: { name: 'Tasks', icon: 'https://img.icons8.com/color/24/task-completed.png' },
        emp_helpdesk: { name: 'Help Desk', icon: 'https://img.icons8.com/color/24/help.png' },
        emp_Onboarding: { name: 'Onboarding', icon: 'https://cdn-icons-png.freepik.com/256/13730/13730909.png?semt=ais_hybrid' },
        emp_benefits: { name: 'Benefits', icon: 'https://cdn-icons-png.flaticon.com/512/8655/8655563.png' },
        emp_Appraisal: { name: 'Appraisal', icon: 'https://cdn-icons-png.flaticon.com/512/12278/12278438.png' },
        emp_notifications: { name: 'Notifications', icon: 'https://cdn-icons-png.flaticon.com/512/4658/4658755.png' },
        emp_asset: { name: 'Assets', icon: 'https://cdn-icons-png.flaticon.com/512/3135/3135771.png' },
        emp_bonus: { name: 'Bonus', icon: 'https://cdn-icons-png.flaticon.com/512/6303/6303173.png' },
        emp_joblists: { name: 'Job Listings', icon: 'https://cdn-icons-png.flaticon.com/512/4116/4116684.png' },
        emp_claim: { name: 'Claims', icon: 'https://cdn-icons-png.flaticon.com/512/12194/12194787.png' },
        emp_offboarding: { name: 'Offboarding', icon: 'https://cdn-icons-png.freepik.com/256/8265/8265009.png?semt=ais_hybrid' },
        emp_jobapplication: { name: 'Job Application', icon: 'https://cdn-icons-png.flaticon.com/512/13441/13441753.png' },
        emp_offerletter: { name: 'Offer Letter', icon: 'https://cdn-icons-png.freepik.com/256/4654/4654143.png?semt=ais_hybrid' },
        hr_attendance: { name: 'Attendance', icon: 'https://img.icons8.com/color/24/calendar--v1.png' },
        hr_leave: { name: 'Leave', icon: 'https://img.icons8.com/color/24/beach.png' },
        hr_wfh: { name: 'WFH', icon: 'https://img.icons8.com/color/24/laptop.png' },
        hr_payslip: { name: 'Payslip', icon: 'https://img.icons8.com/color/24/money-bag.png' },
        hr_tasks: { name: 'Tasks', icon: 'https://img.icons8.com/color/24/task-completed.png' },
        hr_helpdesk: { name: 'Help Desk', icon: 'https://img.icons8.com/color/24/help.png' },
        hr_employeemanagement: { name: 'Employee Management', icon: 'https://img.icons8.com/color/24/conference-call.png' },
        hr_benefits: { name: 'Benefits', icon: 'https://cdn-icons-png.flaticon.com/512/11113/11113093.png' },
        hr_appraisal: { name: 'Appraisal', icon: 'https://cdn-icons-png.flaticon.com/512/11112/11112856.png' },
        hr_notifications: { name: 'Notifications', icon: 'https://img.icons8.com/color/24/appointment-reminders.png' },
        hr_asset: { name: 'Assets', icon: 'https://img.icons8.com/color/24/feedback.png' },
        hr_bonus: { name: 'Bonus', icon: 'https://img.icons8.com/color/24/document.png' },
        hr_joblists: { name: 'Job Listings', icon: 'https://img.icons8.com/color/24/training.png' },
        hr_claim: { name: 'Claims', icon: 'https://cdn-icons-png.freepik.com/256/14252/14252153.png?semt=ais_hybrid' },
        hr_offboarding: { name: 'Offboarding', icon: 'https://img.icons8.com/?size=192&id=E1XHpaUoWFxv&format=png' },
        hr_jobapplication: { name: 'Job Application', icon: 'https://cdn-icons-png.flaticon.com/512/16995/16995294.png' },
        hr_Onboarding: { name: 'Onboarding', icon: 'https://cdn-icons-png.flaticon.com/512/3862/3862949.png' }
      };

      const performSearch = (query) => {
        if (query.length < 3) {
          elements.autocompleteDropdown.style.display = 'none';
          return;
        }
        elements.autocompleteDropdown.innerHTML = '';
        const results = Object.entries(moduleNames).filter(([key, module]) => 
          module.name.toLowerCase().includes(query.toLowerCase())
        );
        if (results.length === 0) {
          const noResults = document.createElement('div');
          noResults.className = 'no-results';
          noResults.textContent = 'No module found';
          elements.autocompleteDropdown.appendChild(noResults);
          elements.autocompleteDropdown.style.display = 'block';
          return;
        }
        results.forEach(([moduleKey, module]) => {
          const item = document.createElement('div');
          item.className = 'autocomplete-item';
          item.innerHTML = `<img src="${module.icon}" alt="${module.name}"><span>${module.name}</span>`;
          item.dataset.module = moduleKey;
          item.addEventListener('click', () => {
            if (config.modules[moduleKey]) {
              elements.contentFrame.style.opacity = '0.5';
              elements.contentFrame.style.transition = 'opacity 0.3s ease';
              setTimeout(() => {
                elements.contentFrame.src = config.modules[moduleKey];
                elements.contentFrame.onload = () => {
                  elements.contentFrame.style.opacity = '1';
                };
              }, 200);
              elements.autocompleteDropdown.style.display = 'none';
              elements.searchInput.value = '';
            } else {
              utils.showAlert('error', `Module ${module.name} not found`);
            }
          });
          elements.autocompleteDropdown.appendChild(item);
        });
        elements.autocompleteDropdown.style.display = 'block';
      };

      elements.searchInput.addEventListener('input', (event) => {
        performSearch(event.target.value.trim());
      });

      elements.searchButton.addEventListener('click', () => {
        performSearch(elements.searchInput.value.trim());
      });

      elements.searchInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
          performSearch(elements.searchInput.value.trim());
        }
      });
    },

    initSessionChecker: () => {
      setInterval(async () => {
        if (state.isAuthenticated) {
          await core.verifySession();
        }
      }, config.sessionCheckInterval);
    },

    handleLogout: () => {
      fetch(`${config.apiBaseUrl}/logout`, {
        method: 'POST',
        credentials: 'include'
      })
      .then(() => {
        localStorage.removeItem('abccompanyempdetails');
        sessionStorage.removeItem('user');
        document.cookie = 'accessToken=; Max-Age=0; path=/;';
        document.cookie = 'refreshToken=; Max-Age=0; path=/;';
        state.isAuthenticated = false;
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.personnelDetails = null;
        utils.showAlert('success', 'Logged out successfully');
        core.showLoginView();
      })
      .catch(err => {
        utils.handleApiError(err);
      });
    },

    validateForm: () => {
      const email = elements.emailInput.value.trim();
      const password = elements.passwordInput.value;
      elements.errorMessage.textContent = '';
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!email) {
        elements.errorMessage.textContent = 'Email is required';
        return false;
      }
      if (!emailRegex.test(email)) {
        elements.errorMessage.textContent = 'Invalid email format';
        return false;
      }
      if (!password) {
        elements.errorMessage.textContent = 'Password is required';
        return false;
      }
      if (password.length < 8) {
        elements.errorMessage.textContent = 'Password must be at least 8 characters';
        return false;
      }

      return true;
    },

    handleLogin: async (e) => {
      e.preventDefault();
      if (!core.validateForm()) return;

      const email = elements.emailInput.value.trim();
      const password = elements.passwordInput.value;
      elements.loginButton.disabled = true;
      elements.loginButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';

      try {
        const response = await fetch(`${config.apiBaseUrl}/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
          if (data.accessToken) {
            document.cookie = `accessToken=${data.accessToken}; maxAge=900; path=/`;
            state.token = data.accessToken;
          }
          if (data.refreshToken) {
            document.cookie = `refreshToken=${data.refreshToken}; maxAge=604800; path=/`;
            state.refreshToken = data.refreshToken;
          }
          if (data.user) {
            sessionStorage.setItem('user', JSON.stringify(data.user));
            state.user = data.user;
          }
          if (data.personnel) {
            localStorage.setItem('abccompanyempdetails', JSON.stringify(data.personnel));
            state.personnelDetails = data.personnel;
          }
          state.isAuthenticated = true;
          utils.showAlert('success', 'Login successful! Redirecting...');
          await core.verifySession();
        } else {
          elements.errorMessage.textContent = data.error || 'Login failed';
          utils.showAlert('error', data.error || 'Login failed');
          elements.passwordInput.value = '';
        }
      } catch (err) {
        elements.errorMessage.textContent = 'Error connecting to server';
        utils.showAlert('error', 'Error connecting to server');
      } finally {
        elements.loginButton.disabled = false;
        elements.loginButton.textContent = 'Login';
      }
    },

    togglePassword: () => {
      if (elements.passwordInput.type === 'password') {
        elements.passwordInput.type = 'text';
        elements.eyeIcon.innerHTML = '<i class="fas fa-eye-slash"></i>';
      } else {
        elements.passwordInput.type = 'password';
        elements.eyeIcon.innerHTML = '<i class="fas fa-eye"></i>';
      }
    }
  };

  const init = async () => {
    const savedPersonnel = localStorage.getItem('abccompanyempdetails');
    if (savedPersonnel) {
      try {
        state.personnelDetails = JSON.parse(savedPersonnel);
      } catch (error) {
        console.error("Failed to parse saved personnel details:", error);
      }
    }

    const isAuthenticated = await core.verifySession();
    if (isAuthenticated) {
      utils.showAlert('success', `Welcome back, ${state.user.username || 'User'}!`);
    } else {
      core.showLoginView();
      elements.eyeIcon.addEventListener('click', core.togglePassword);
      elements.loginForm.addEventListener('submit', core.handleLogin);
    }
  };

  init();
}); 

"after logging into dashboard the details for that email is not being saved to localstorage
