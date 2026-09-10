const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_demo_jwt_secret_key_2026';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// ==========================================
// 1. SECURITY & UTILITY MIDDLEWARES
// ==========================================

// Helmet sets secure HTTP response headers while allowing cross-origin requests
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginEmbedderPolicy: false
}));

// CORS configuration - allow cross-origin requests from any frontend port or file://
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'Accept', 'X-Requested-With']
}));
app.options('*', cors());

// Body parser with payload size limit (mitigate large payload DoS attacks)
app.use(express.json({ limit: '10kb' }));

// Root & API Base Health Check Routes
app.get(['/', '/api'], (req, res) => {
    return res.status(200).json({
        success: true,
        message: 'Application Security API Server is active and operational.',
        endpoints: {
            register: 'POST /api/register',
            login: 'POST /api/login',
            dashboard: 'GET /api/dashboard',
            admin: 'GET /api/admin',
            security: 'GET /api/security'
        }
    });
});

// Global Rate Limiting: Max 200 requests per 15 minutes per IP
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many requests from this IP. Please try again later.'
    }
});
app.use(globalLimiter);

// Specific Login Rate Limiting: Max 10 login attempts per 15 minutes per IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many login attempts from this IP. Please try again after 15 minutes.'
    }
});

// ==========================================
// 2. IN-MEMORY DATA STORE (DEMO ACCOUNTS)
// ==========================================
// Initialized with bcrypt-hashed passwords (never store plain text passwords)
const users = [
    {
        id: '1',
        name: 'System Admin',
        email: 'admin@example.com',
        passwordHash: bcrypt.hashSync('Admin@123', 10),
        role: 'admin',
        createdAt: new Date().toISOString()
    },
    {
        id: '2',
        name: 'Standard User',
        email: 'user@example.com',
        passwordHash: bcrypt.hashSync('User@123', 10),
        role: 'user',
        createdAt: new Date().toISOString()
    }
];

// ==========================================
// 3. INPUT VALIDATION UTILITIES
// ==========================================
const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return typeof email === 'string' && emailRegex.test(email.trim());
};

const isValidPassword = (password) => {
    // Minimum 8 characters
    return typeof password === 'string' && password.length >= 8;
};

// ==========================================
// 4. AUTHENTICATION & AUTHORIZATION MIDDLEWARES
// ==========================================

// JWT Authentication Middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(401).json({
            success: false,
            message: 'Authentication failed: No token provided in Authorization header.'
        });
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.status(401).json({
            success: false,
            message: 'Authentication failed: Invalid token format. Format must be "Bearer <token>".'
        });
    }

    const token = parts[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({
                success: false,
                message: 'Authentication failed: Invalid or expired token.'
            });
        }

        // Attach decoded user payload to request object
        req.user = decoded;
        next();
    });
};

// Role-Based Authorization Middleware (Admin only)
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'Access forbidden: Administrator privileges are required to access this resource.'
        });
    }
    next();
};

// ==========================================
// 5. API ENDPOINTS
// ==========================================

// --- REGISTER API ---
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        // 1. Validation: Name is required
        if (!name || typeof name !== 'string' || name.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Validation error: Full name is required.'
            });
        }

        // 2. Validation: Email is required and format must be valid
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Validation error: A valid email address is required.'
            });
        }

        // 3. Validation: Password length must be at least 8 characters
        if (!password || !isValidPassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Validation error: Password must be at least 8 characters long.'
            });
        }

        // 4. Validation: Password and Confirm Password must match
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Validation error: Passwords do not match.'
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        // 5. Validation: Check for duplicate email
        const existingUser = users.find(u => u.email.toLowerCase() === normalizedEmail);
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Validation error: Email address is already registered.'
            });
        }

        // 6. Secure Password Hashing with bcryptjs (10 salt rounds)
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // 7. Store new user in memory (Default role: "user")
        const newUser = {
            id: (users.length + 1).toString(),
            name: name.trim(),
            email: normalizedEmail,
            passwordHash: passwordHash,
            role: 'user',
            createdAt: new Date().toISOString()
        };
        users.push(newUser);

        return res.status(201).json({
            success: true,
            message: 'User registered successfully! You can now log in.'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Internal server error during user registration.'
        });
    }
});

// --- LOGIN API ---
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Input validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Validation error: Email and password are required.'
            });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const user = users.find(u => u.email.toLowerCase() === normalizedEmail);

        // Generic error message for both non-existent user and wrong password
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        // Verify password using bcryptjs
        const isPasswordMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        // Generate JWT Token (payload excludes sensitive password hash)
        const tokenPayload = {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        };

        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        return res.status(200).json({
            success: true,
            message: 'Login successful.',
            token: token,
            user: tokenPayload
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Internal server error during login authentication.'
        });
    }
});

// --- DASHBOARD API (Protected: Any Authenticated User) ---
app.get('/api/dashboard', verifyToken, (req, res) => {
    return res.status(200).json({
        success: true,
        data: {
            welcome: `Welcome to the Secure Portal, ${req.user.name}!`,
            user: {
                id: req.user.id,
                name: req.user.name,
                email: req.user.email,
                role: req.user.role
            },
            securityStatus: {
                authentication: 'Authenticated via JSON Web Token (JWT)',
                passwordHashing: 'Bcrypt (10 Salt Rounds) Enforced',
                inputValidation: 'Client-side & Server-side Validation Active',
                authorization: req.user.role === 'admin' ? 'Administrator (Full Access)' : 'Standard User (Protected Access)'
            }
        }
    });
});

// --- ADMIN API (Protected: Admin Role Only) ---
app.get('/api/admin', verifyToken, requireAdmin, (req, res) => {
    // Exclude password hashes when returning registered user information
    const sanitizedUsers = users.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        createdAt: u.createdAt
    }));

    return res.status(200).json({
        success: true,
        message: 'Admin Access Granted',
        securityInfo: {
            adminUser: req.user.email,
            accessTimestamp: new Date().toISOString(),
            totalUsersCount: users.length,
            registeredUsers: sanitizedUsers,
            systemSecurityOverview: {
                helmetHeaders: 'Active (CSP, X-Content-Type-Options, HSTS)',
                rateLimiting: 'Active (Global 200/15m, Login 10/15m)',
                passwordCipher: 'Bcrypt with 10 salt rounds',
                tokenStandard: 'JSON Web Token (HMAC-SHA256)',
                authorizationEnforcement: 'Middleware Role-Based Access Control (RBAC)'
            }
        }
    });
});

// --- SECURITY RECOMMENDATIONS API ---
app.get('/api/security', (req, res) => {
    return res.status(200).json({
        success: true,
        recommendations: [
            {
                id: 1,
                title: 'Strong Password Policies',
                category: 'Authentication',
                description: 'Enforce minimum length of 8+ characters, requiring mixed case, numbers, and special symbols to withstand dictionary and brute-force attacks.'
            },
            {
                id: 2,
                title: 'Cryptographic Password Hashing',
                category: 'Data Protection',
                description: 'Never store plain-text passwords. Use adaptive hashing algorithms like Bcrypt or Argon2 with unique salts to prevent rainbow table attacks.'
            },
            {
                id: 3,
                title: 'Strict Input Validation & Sanitization',
                category: 'Injection Defense',
                description: 'Validate all inputs against whitelist schemas on both client and server sides to protect against SQL Injection, XSS, and parameter tampering.'
            },
            {
                id: 4,
                title: 'Stateless Authentication with JWT',
                category: 'Session Security',
                description: 'Sign tokens using strong cryptographic secrets, enforce short token lifespans, and transmit tokens via secure Authorization Bearer headers.'
            },
            {
                id: 5,
                title: 'Role-Based Access Control (RBAC)',
                category: 'Authorization',
                description: 'Verify permissions at every protected endpoint on the server side to prevent Broken Object Level and Function Level Authorization (BOLA/BFLA).'
            },
            {
                id: 6,
                title: 'Rate Limiting & Brute-Force Defense',
                category: 'Availability',
                description: 'Throttle repeated authentication attempts using IP-based and user-based rate limiters to prevent credential stuffing and denial of service.'
            },
            {
                id: 7,
                title: 'Secure Error Handling & Information Hiding',
                category: 'Information Disclosure',
                description: 'Return generic error messages for authentication failures. Never expose stack traces, database schemas, or internal secrets to clients.'
            },
            {
                id: 8,
                title: 'Security HTTP Headers (Helmet)',
                category: 'Browser Hardening',
                description: 'Use Helmet to set protective HTTP headers including Content-Security-Policy, X-Frame-Options (anti-clickjacking), and Strict-Transport-Security.'
            }
        ]
    });
});

// ==========================================
// 6. ERROR HANDLING & 404 CATCH-ALL
// ==========================================

// 404 Not Found Handler for undefined routes
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found: The requested API endpoint does not exist.'
    });
});

// Global 500 Error Handler
app.use((err, req, res, next) => {
    console.error('Unhandled Server Error:', err.message);
    res.status(500).json({
        success: false,
        message: 'An unexpected internal server error occurred.'
    });
});

// ==========================================
// 7. START SERVER
// ==========================================
app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(` Application Security Server running on port ${PORT}`);
    console.log(` Backend URL: http://localhost:${PORT}`);
    console.log(` Demo Accounts:`);
    console.log(`   - Admin: admin@example.com / Admin@123 (role: admin)`);
    console.log(`   - User:  user@example.com  / User@123  (role: user)`);
    console.log(`=================================================`);
});
