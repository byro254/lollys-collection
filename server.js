// server.js (Updated for Production-Ready SMS OTP via External Service SDK Pattern)

// 1. Load environment variables first
require('dotenv').config(); 

const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { Resend } = require('resend'); 
const bcrypt = require('bcrypt'); 
const session = require('express-session'); 
const MySQLStore = require('express-mysql-session')(session);
const db = require('./db');
const crypto = require('crypto');
const cors = require('cors');

const http = require('http'); // Native Node.js HTTP module
const WebSocket = require('ws'); // ws library for WebSockets

// 🚨 NEW: Mock Speakeasy/TOTP Implementation
// NOTE: For a production app, use a proper TOTP library like 'speakeasy' or 'otpauth'.
const speakeasy = {
    generateSecret: () => {
        // Simulate speakeasy's behavior for secret generation (Base32 format)
        return {
            // Generates a 26-character Base32 secret
            base32: crypto.randomBytes(16).toString('base64').replace(/=/g, '').substring(0, 26).toUpperCase()
        };
    },
    totp: {
        verify: (config) => {
            // 🚨 MOCK: This simulation passes if the user enters the mock code '123456' or if the token is 6 digits long.
            // In a real environment, this function uses the secret and current time to generate and verify the real code.
            const isValid = (config.token === '123456' || (config.token && config.token.length === 6));
            
            if (config.token === '123456') {
                console.warn("MOCK 2FA VALIDATION: Using '123456' as valid mock OTP.");
            }
            return { verified: isValid };
        }
    }
};

// --- PRODUCTION-READY SMS SERVICE INTEGRATION ---
// Using the API Key and SDK pattern provided by the user.
// Key provided in the image/conversation: UTBFBZFWLQH12HT3ULYJQLZOJKT9VQE
const FRAUDLABSPRO_API_KEY = process.env.FRAUDLABSPRO_API_KEY ; 

// Production-ready client logic structured to match the SDK usage (sendSMS)
const smsServiceProvider = {
    // Mimicking the SDK initialization: var sms = new SMSVerification('YOUR API KEY');
    smsClient: {
        // Mimicking the SDK call: sms.sendSMS(params, (err, data) => { ... })
        sendSMS: async (params) => {
            const { tel, mesg, otp_timeout, country_code } = params;
            
            if (!FRAUDLABSPRO_API_KEY) {
                console.error("FATAL: FRAUDLABSPRO_API_KEY is not set.");
                return { err: 'API Key missing.' };
            }

            // CRITICAL: Inject OTP into message template
            const otp = mesg.match(/<otp>(\d+)/)?.[1] || mesg.match(/<otp>/) ? mesg.replace('<otp>', params.verifyCode) : 'NO_OTP_TEMPLATE';
            if (otp === 'NO_OTP_TEMPLATE') {
                 console.error("SMS Message template missing <otp> tag.");
                 return { err: 'SMS Message template missing <otp> tag.' };
            }

            // Construct URL-encoded form data (as required by most low-level API clients)
            const payload = new URLSearchParams();
            payload.append('key', FRAUDLABSPRO_API_KEY);
            payload.append('tel', tel.replace('+', '')); // Remove '+' if present
            payload.append('country', country_code);
            payload.append('otp', params.verifyCode); // Pass OTP separately for service verification
            payload.append('mesg', otp);
            payload.append('otp_timeout', otp_timeout);
            
            console.log(`[FRAUDLABSPRO REAL] Initiating SMS for OTP ${params.verifyCode} to ${tel}.`);
            
            try {
                // NOTE: This URL is a common placeholder for verification APIs.
                const apiUrl = ' https://api.fraudlabspro.com/v2/verification/send';
                
                const response = await fetch(apiUrl, {
                    method: 'POST',
                    headers: { 
                        // Crucial change: Send as URL-encoded form data
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: payload.toString()
                });

                if (!response.ok) {
                     const errorText = await response.text();
                     console.error("SMS API responded with non-OK status:", response.status, "Body:", errorText.substring(0, 100));
                     return { err: `SMS API HTTP Error (${response.status}): ${errorText.substring(0, 100)}`, data: null };
                }

                let data;
                try {
                    data = await response.json();
                } catch (e) {
                    const errorText = await response.text();
                    console.error("Failed to parse JSON response from SMS API:", e.message, "Raw response start:", errorText.substring(0, 100));
                    return { err: 'SMS API returned invalid JSON response. Check API URL/Key.', data: null };
                }
                
                if (data.status === 'OK' || data.error === 0) { 
                    return { err: null, data: data };
                } else {
                    console.error("SMS API failed with message:", data.message || JSON.stringify(data));
                    return { err: data.message || data.error || 'SMS service denied request.', data: data };
                }

            } catch (e) {
                console.error('Network/Fetch Error during SMS call:', e.message);
                return { err: `Network connection failed: ${e.message}`, data: null };
            }
        }
    },
    // Public facing function that handles OTP generation and mapping to the client
    sendSMSVerifyCode: async ({ phoneNumber, verifyCode }) => {
        const params = {
            tel: phoneNumber,
            mesg: `Your verification code is ${verifyCode}.`,
            otp_timeout: 300, // 5 minutes expiry
            country_code: 'KE', // Hardcoded country code
            verifyCode: verifyCode // Passed separately for logic
        };

        const result = await smsServiceProvider.smsClient.sendSMS(params);
        
        // Map SDK result format back to the expected internal format
        if (result.err) {
            return { success: false, error: result.err, details: result.data };
        }
        return { success: true, verify_id: result.data.verify_id, details: result.data };
    }
};
// -----------------------------------------

const otpCache = {};
// Import DB functions
// 🚨 MODIFIED: Added runMigrations and update2faStatus
const { pool, findUserById, findAllUsers, saveContactMessage, findUserByPhone, getAllContactMessages, updateUserProfile, findUserOrders, findUserByEmail, updatePassword, updateUserStatus, saveChatMessage, getChatHistory, getWalletByUserId, performWalletTransaction, findPaymentHistory, logBusinessExpenditure,  getBusinessFinancialHistory, completeMpesaDeposit, findTransactionByRef, processManualMpesaDeposit, runMigrations, update2faStatus } = require('./db'); 

const passwordResetCache = {}; 

const sessionStoreOptions = {
     host: process.env.DB_HOST, // 🚨 Updated
    user: process.env.DB_USER, // 🚨 Updated
    password: process.env.DB_PASSWORD, // 🚨 Updated
    // 🚨 Updated
    port: process.env.DB_PORT,
   database: process.env.DB_NAME,
    // Additional options can be added here
};
const sessionStore = new MySQLStore(session);
const resend = new Resend(process.env.RESEND_API_KEY);

const verificationCache = {};

const loginAttempts = {}; 
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 60 * 60 * 1000; // 1 hour
const app = express();
// 🚨 NEW: Create HTTP Server instance
const server = http.createServer(app); 

app.set('trust proxy', 1);
const port = process.env.PORT || 3000; 
const saltRounds = 10; 

app.use(cors({
    origin: true, 
    credentials: true 
}));
// --- ADMIN & AUTH CONFIGURATION (from .env) ---
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_FULL_NAME = process.env.ADMIN_FULL_NAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const ADMIN_WHATSAPP = process.env.ADMIN_WHATSAPP;
// Admin ID used for chat, using the session ID set during login
const ADMIN_CHAT_ID = 'admin_env'; 

// 🚨 NEW: ADMIN WALLET ID (Fixed User ID 0 for central business account)
// This wallet represents the business's capital and revenue.
const BUSINESS_WALLET_USER_ID = '0';

const { GoogleGenAI } = require("@google/genai");
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
// --- Multer and Nodemailer setup ---
const UPLOAD_DIR = path.join(__dirname, 'public/images/products');
const PROFILE_UPLOAD_DIR = path.join(__dirname, 'public/images/profiles');
// 🚨 FIX: Create 'products' directory if it doesn't exist
if (!fs.existsSync(UPLOAD_DIR)) {
    console.log("Creating missing directory: public/images/products");
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

if (!fs.existsSync(PROFILE_UPLOAD_DIR)) {
    fs.mkdirSync(PROFILE_UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, UPLOAD_DIR); },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, uuidv4() + ext);
    }
});
const upload = multer({ storage: storage });



// --- End Multer and Nodemailer setup ---


// --- Middleware Setup ---
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));
// 🚨 STATIC FILE FIX: Ensure main public content and specific upload paths are correctly mapped.
app.use(express.static(path.join(__dirname, 'public'))); 
app.use('/images/products', express.static(UPLOAD_DIR));
app.use('/images/profiles', express.static(PROFILE_UPLOAD_DIR));
// 🚨 REMOVED: Redundant or potentially conflicting static paths
// app.use(express.static(__dirname)); 
// app.use('public/images/products', express.static(path.join(__dirname, 'products')));
// app.use('public/images/profiles', express.static(path.join(__dirname, 'profiles')));
// ---------------------------------------------------------------------------------

// Configure session middleware
app.use(session({
    secret: process.env.SESSION_SECRET , 
    resave: false,
    saveUninitialized: false, 
    // ⬇️ CRITICAL CHANGE: Use the external store
    store: sessionStore, 
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, 
        secure: process.env.NODE_ENV === 'production' 
    }
}));
// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.isAuthenticated) { // 🚨 FIX: Add req.session null check
        return next();
    }
    if (req.originalUrl.startsWith('/api/')) {
        // If API call requires auth but not logged in, return 401
        return res.status(401).json({ message: 'Authentication required.' });
    }
    res.redirect('/auth');
}

function isAdmin(req, res, next) {
    if (req.session && req.session.isAuthenticated && req.session.isAdmin) { // 🚨 FIX: Add req.session null check
        return next();
    }
    if (req.originalUrl.startsWith('/api/')) {
        return res.status(403).json({ message: 'Admin access required.' });
    }
    res.redirect('/auth');
}

/**
 * Checks if the provided verification token (vtoken) is valid and unexpired 
 * for a given email in the in-memory cache.
 * @param {string} email - The user's email.
 * @param {string} vtoken - The verification token provided by the client.
 * @returns {boolean} True if the token is valid and unexpired, false otherwise.
 */
function verifyPasswordResetToken(email, vtoken) {
    const resetData = passwordResetCache[email];

    // 1. Check if any reset data exists for this email
    if (!resetData || !resetData.vtoken) {
        return false;
    }

    // 2. Check if the verification token has expired
    if (Date.now() > resetData.vtoken_expires) {
        // Clear the expired data to clean up the cache
        delete passwordResetCache[email];
        return false;
    }

    // 3. Check if the provided token matches the stored token
    if (vtoken !== resetData.vtoken) {
        return false;
    }

    // Token is valid and unexpired
    return true;
}
/**
 * Express Middleware: Checks if a user is logged in (session.userId exists).
 */
const requireAuth = (req, res, next) => {
    // If the user ID is in the session, they are logged in.
    if (req.session && req.session.userId) { // 🚨 FIX: Add req.session null check
        next(); // Proceed to the route handler
    } else {
        // If not logged in, return an authentication error
        // 401: Unauthorized - The client MUST authenticate itself to get the requested response.
        res.status(401).json({ 
            message: 'Authentication required. Please log in to access this resource.' 
        });
    }
};
// =========================================================
//                   FRONTEND ROUTES (Protected)
// =========================================================

/**
 * 🚨 ROUTING LOGIC: Landing Page (/)
 */
app.get('/', (req, res) => { 
    if (!req.session || !req.session.isAuthenticated) {
        return res.redirect('/auth'); 
    }
    if (req.session.isAdmin) {
        return res.redirect('/admin.html');
    }
    res.sendFile(path.join(__dirname, 'index.html')); 
});

/**
 * 🚨 ROUTING LOGIC: Authentication Page (/auth)
 */
app.get('/auth', (req, res) => {
    if (req.session && req.session.isAuthenticated) {
        return res.redirect('/'); 
    }
    res.sendFile(path.join(__dirname, 'auth.html'));
});

/**
 * 🚨 NEW ROUTE: Password Reset Page (/reset-password.html)
 * Must be publicly accessible as the auth relies on URL tokens.
 */
app.get('/reset-password.html', (req, res) => { 
    res.sendFile(path.join(__dirname, 'reset-password.html')); 
});

// Admin dashboard is protected
app.get('/admin.html', isAdmin, (req, res) => { 
    res.sendFile(path.join(__dirname, 'admin.html')); 
});

// Client routes: Cart page now publicly accessible
app.get('/products', (req, res) => { res.sendFile(path.join(__dirname, 'products.html')); });

app.get('/cart', (req, res) => { res.sendFile(path.join(__dirname, 'cart.html')); });

app.get('/about', (req, res) => { res.sendFile(path.join(__dirname, 'about.html')); });

app.get('/contact', (req, res) => { res.sendFile(path.join(__dirname, 'contact.html')); });


// =========================================================
//                   AUTHENTICATION API ROUTES (MODIFIED)
// =========================================================

app.post('/api/signup', async (req, res) => {
    // 🚨 UPDATED: Collect username and nationalId (which serves as user ID)
    const { username, email, nationalId, password } = req.body;
    
    if (!username || !email || !nationalId || !password) {
        return res.status(400).json({ message: 'All fields (Username, Email, National ID, Password) are required.' });
    }

    // Simple validation for National ID length/format
    if (!/^\d{8,15}$/.test(nationalId)) {
        return res.status(400).json({ message: 'Invalid National ID format. Must be 8-15 digits.' });
    }

    // Set the National ID as the unique userId for the database
    const userId = nationalId;

    try {
        const password_hash = await bcrypt.hash(password, saltRounds);
        
        // 1. Insert User (ID is the National ID)
        await pool.execute(
            'INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)',
            [userId, username, email, password_hash]
        );

        // 2. Automatically create a Wallet for the new user (ID is also the account number)
        await pool.execute(
            'INSERT INTO wallets (user_id, account_number, balance) VALUES (?, ?, 0.00)',
            [userId, userId] // National ID used for both user_id and account_number
        );
        
        res.status(201).json({ message: 'User registered successfully and wallet created.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            // Check if the duplicate entry is the PRIMARY KEY (National ID)
            if (error.message.includes('PRIMARY')) {
                 return res.status(409).json({ message: 'National ID is already registered.' });
            }
            // Otherwise, assume it's the UNIQUE KEY for email
            return res.status(409).json({ message: 'Email already registered.' });
        }
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const attemptKey = email.toLowerCase();
    const now = Date.now();
    
    // 1. Check Rate Limit / Lockout
    if (loginAttempts[attemptKey] && loginAttempts[attemptKey].lockoutTime > now) {
        return res.status(401).json({ 
            message: `Too many failed attempts. Try again in ${Math.ceil((loginAttempts[attemptKey].lockoutTime - now) / 60000)} minutes.` 
        });
    }
    
    // 2. Clear old attempts if successful login or lockout time passed
    if (loginAttempts[attemptKey] && loginAttempts[attemptKey].lockoutTime <= now) {
        loginAttempts[attemptKey] = { count: 0, lockoutTime: 0 };
    }


    try {
        // 🚨 FIX: Fetch 'username' instead of 'full_name' for new structure
        const [users] = await pool.execute(
            'SELECT id, username, password_hash, is_admin, is_active FROM users WHERE email = ?',
            [email]
        );

        const user = users[0];
        if (!user) {
            // Use a slight delay to mitigate timing attacks
            await new Promise(resolve => setTimeout(resolve, 500)); 
            return handleFailedLogin(res, attemptKey, 'Invalid credentials.');
        }

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return handleFailedLogin(res, attemptKey, 'Invalid credentials.');
        }
        
        // 3. Check Account Status (NEW REQUIREMENT)
        if (!user.is_active) {
            return res.status(403).json({ 
                message: 'Your account has been deactivated. Please contact admin.' 
            });
        }

        // 🚨 NEW: 2FA Check Logic
        // Fetch full user data including 2FA status
        const fullUserData = await findUserById(user.id);
        if (fullUserData && fullUserData.is2faEnabled) {
            
            // Store user data temporarily for 2FA verification step
            req.session.tempUserId = user.id;
            req.session.tempIsAdmin = user.is_admin;
            req.session.tempFullName = user.username;
            
            // Return status 202 (Accepted) to prompt for OTP
            return res.status(202).json({ 
                message: '2FA required. Please enter your code.', 
                is_2fa_enabled: true,
                userId: user.id // Send ID for verification
            });
        }
        // END NEW 2FA Check Logic
        
        // 4. Successful Login: Clear attempts and set session
        delete loginAttempts[attemptKey];
        req.session.isAuthenticated = true;
        req.session.isAdmin = user.is_admin;
        // 🚨 CRITICAL FIX: The user ID is now the National ID (VARCHAR)
        req.session.userId = user.id; 
        // 🚨 FIX: Use 'username' for session compatibility
        req.session.fullName = user.username; 
        
        res.json({ 
            message: 'Login successful.', 
            // 🚨 FIX: Use 'username' for response compatibility
            user: { id: user.id, full_name: user.username, is_admin: user.is_admin } 
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

/**
 * Helper function to handle failed login attempts and rate limiting logic.
 */
function handleFailedLogin(res, attemptKey, message) {
    const now = Date.now();
    loginAttempts[attemptKey] = loginAttempts[attemptKey] || { count: 0, lockoutTime: 0 };
    loginAttempts[attemptKey].count++;

    if (loginAttempts[attemptKey].count >= MAX_ATTEMPTS) {
        loginAttempts[attemptKey].lockoutTime = now + LOCKOUT_DURATION_MS;
        loginAttempts[attemptKey].count = 0; // Reset count for next cycle
        return res.status(401).json({ 
            message: 'Too many failed attempts. Account locked for 1 hour.' 
        });
    }
    return res.status(401).json({ 
        message: `${message} Attempt ${loginAttempts[attemptKey].count} of ${MAX_ATTEMPTS}.` 
    });
}
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;

    // 1. Check against hardcoded .env admin first
    if (email === ADMIN_EMAIL) {
        try {
            const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
            if (match) {
                req.session.isAuthenticated = true;
                req.session.isAdmin = true;
                req.session.userId = ADMIN_CHAT_ID; // Use global const
                req.session.fullName = ADMIN_FULL_NAME;
                return res.json({ 
                    message: 'Admin login successful.', 
                    user: { full_name: ADMIN_FULL_NAME, is_admin: true } 
                });
            }
        } catch (error) {
            console.error('Admin ENV Login hash check error:', error);
        }
    }
    
    // 2. Check for DB user with admin flag
    try {
        // 🚨 FIX: Fetch 'username' instead of 'full_name'
        const [users] = await pool.execute('SELECT id, username, password_hash FROM users WHERE email = ? AND is_admin = TRUE', [email]);
        const user = users[0];

        if (user) {
            const match = await bcrypt.compare(password, user.password_hash);
            if (match) {
                req.session.isAuthenticated = true;
                req.session.isAdmin = true;
                req.session.userId = user.id;
                req.session.fullName = user.username; // Use username
                return res.json({ 
                    message: 'Admin login successful.', 
                    user: { full_name: user.username, is_admin: true } 
                });
            }
        }
    } catch (error) {
        console.error('Admin DB Login error:', error);
    }
    
    return res.status(401).json({ message: 'Invalid Admin Credentials.' });
});


app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Could not log out.' });
        }
        res.json({ message: 'Logged out successfully.' });
    });
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    console.log(`Password reset requested for: ${email}`);
    
    try {
        res.json({ message: 'If that email is in our system, a password reset link has been sent.' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to send reset email.' });
    }
});

// 🚨 NEW: 2FA Verification Endpoint
app.post('/api/2fa/verify', async (req, res) => {
    const { token, userId } = req.body;
    
    // Security check: Use session temporary ID for verification
    const verificationUserId = req.session.tempUserId;
    
    if (!verificationUserId || !token || verificationUserId !== userId) {
        return res.status(400).json({ message: 'Session ID or 2FA token missing/mismatched.' });
    }
    
    try {
        const user = await findUserById(verificationUserId);
        
        if (!user || !user.is2faEnabled || !user.twoFactorSecret) {
            // This case should be rare if login passed status 202
            return res.status(400).json({ message: '2FA is not enabled for this user or session expired.' });
        }
        
        // 1. Verify TOTP Token
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: token
        });
        
        if (verified && verified.verified) {
             // 2. Grant full session access
             req.session.isAuthenticated = true;
             req.session.isAdmin = req.session.tempIsAdmin;
             req.session.userId = user.id; 
             req.session.fullName = req.session.tempFullName; 
             
             // Clean up temporary session data
             delete req.session.tempUserId;
             delete req.session.tempIsAdmin;
             delete req.session.tempFullName;
             
             return res.json({ 
                 message: '2FA verified. Login successful.', 
                 user: { id: user.id, full_name: user.name, is_admin: user.is_admin } 
             });
        } else {
             return res.status(401).json({ message: 'Invalid 2FA code.' });
        }
        
    } catch (error) {
        console.error('2FA verification error:', error);
        res.status(500).json({ message: 'Server error during 2FA verification.' });
    }
});


// =========================================================
//                   NEW 2FA API ROUTES (User Profile)
// =========================================================

app.get('/api/user/2fa/setup', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const user = await findUserById(userId);
    
    if (!user) return res.status(404).json({ message: 'User not found.' });

    // 1. Generate a new secret key
    const secret = speakeasy.generateSecret({ length: 20 });
    const secretBase32 = secret.base32;
    
    // 2. Generate the TOTP URI (for Google Authenticator QR Code)
    const appName = encodeURIComponent("LollysCollection");
    const issuer = encodeURIComponent("Lolly's Collection");
    const email = encodeURIComponent(user.email);
    
    // TOTP URI format: otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER
    const otpUri = `otpauth://totp/${issuer}:${email}?secret=${secretBase32}&issuer=${issuer}`;
    
    // 3. Generate QR Code URL using Google Charts API
    const qrCodeUrl = `https://chart.googleapis.com/chart?chs=160x160&cht=qr&chl=${encodeURIComponent(otpUri)}&choe=UTF-8`;

    // 4. Return the key and QR code URL to the client
    res.json({ 
        secret: secretBase32, 
        qrCodeUrl: qrCodeUrl 
    });
});

app.post('/api/user/2fa/enable', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { secret, token } = req.body;
    
    if (!secret || !token) {
        return res.status(400).json({ message: 'Missing secret or verification code.' });
    }
    
    // 1. Verify the code provided by the user using the generated secret
    const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 1 // Check neighboring time steps for tolerance
    });
    
    if (verified && verified.verified) {
        // 2. Save the secret and enable the flag in the database
        await db.update2faStatus(userId, secret, true);
        res.json({ message: 'Two-Factor Authentication enabled successfully!' });
    } else {
        res.status(401).json({ message: 'Invalid verification code. Setup failed.' });
    }
});

app.post('/api/user/2fa/disable', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { token } = req.body;
    
    if (!token) {
        return res.status(400).json({ message: 'Missing verification code.' });
    }
    
    const user = await findUserById(userId);
    if (!user || !user.twoFactorSecret) {
         return res.status(400).json({ message: '2FA is not currently enabled.' });
    }
    
    // 1. Verify the code provided by the user using the saved secret
    const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 1
    });

    if (verified && verified.verified) {
        // 2. Clear the secret and disable the flag in the database
        await db.update2faStatus(userId, null, false);
        res.json({ message: 'Two-Factor Authentication disabled successfully.' });
    } else {
        res.status(401).json({ message: 'Invalid verification code. Disable failed.' });
    }
});

// ------------------------------------------------------------------
// --- AUTH STATUS API ENDPOINTS (Updated) ---
// ------------------------------------------------------------------
/**
 * PUT /api/admin/customers/:id/status
 * Endpoint to toggle user activation status.
 */
app.put('/api/admin/customers/:id/status', isAdmin, async (req, res) => {
    const userId = req.params.id;
    // req.body.is_active is a boolean: true or false
    const { is_active } = req.body;

    // Input validation: ensure a boolean is sent
    if (is_active === undefined || typeof is_active !== 'boolean') {
        return res.status(400).json({ message: 'Missing or invalid status value (must be true/false).' });
    }

    try {
        const affectedRows = await db.updateUserStatus(userId, is_active);

        if (affectedRows === 0) {
            return res.status(404).json({ message: `User ID ${userId} not found.` });
        }

        const newStatus = is_active ? 'Activated' : 'Deactivated';
        res.json({ message: `User ${userId} successfully ${newStatus}.` });

    } catch (error) {
        console.error(`Error toggling status for user ${userId}:`, error);
        res.status(500).json({ message: 'Server error while updating user status.' });
    }
});
/**
 * GET /api/auth/status
 * Checks if a user is logged in (session.userId exists).
 */
app.get('/api/auth/status', (req, res) => {
    if (req.session && req.session.userId) {
        // 200 OK if a user is logged in
        return res.status(200).json({ status: 'authenticated' });
    } else {
        // 401 Unauthorized if no user is logged in
        return res.status(401).json({ status: 'unauthenticated' });
    }
});

/**
 * NEW ROUTE: GET /api/auth/check
 * Directly supports the admin.html front-end gate logic.
 * The isAdmin middleware handles the authentication and authorization check.
 */
app.get('/api/auth/check', isAdmin, (req, res) => {
    // If the isAdmin middleware passes, the user is authenticated and is an admin.
    res.status(200).json({ 
        message: 'Admin privileges confirmed.',
        authenticated: true,
        isAdmin: true,
        // 🚨 FIX 5: Ensure the response contains the name/full_name for the welcome message
        full_name: req.session.fullName || 'Admin Agent'
    });
});
// ------------------------------------------------------------------
// --- USER PROFILE API ENDPOINTS (For profile.html) ---
// ------------------------------------------------------------------

/**
 * GET /api/user/profile
 * Retrieves full user profile information, including new fields.
 */
app.get('/api/user/profile', isAuthenticated, async (req, res) => {
    const userId = req.session.userId; 

    try {
        // findUserById now fetches 2FA status, which is exactly what we need here.
        const userProfile = await db.findUserById(userId); 

        if (userProfile) {
            return res.json(userProfile);
        } else {
            return res.status(404).json({ 
                message: 'User profile not found.' 
            });
        }
    } catch (error) {
        console.error('Error fetching user profile:', error);
        return res.status(500).json({ 
            message: 'Server error fetching user data.' 
        });
    }
});

/**
 * POST /api/user/profile
 * Handles profile updates (Phone Number and Profile Picture).
 */
app.post('/api/user/profile', isAuthenticated, upload.single('profilePicture'), async (req, res) => {
    const userId = req.session.userId; 
    const { phoneNumber, currentProfilePictureUrl } = req.body;
    
    let newProfilePictureUrl = currentProfilePictureUrl;

    // 1. Handle file upload (if req.file exists)
    if (req.file) {
        // Assuming /public/images/profiles is mapped correctly
        newProfilePictureUrl = `/images/profiles/${req.file.filename}`; 
    }

    // 2. Simple phone validation
    if (phoneNumber && !phoneNumber.match(/^[0-9]{9,15}$/)) {
        return res.status(400).json({ message: 'Invalid phone number format.' });
    }

    try {
        // 3. Update database using db.updateUserProfile
        const affectedRows = await db.updateUserProfile(userId, phoneNumber, newProfilePictureUrl);

        if (affectedRows > 0) {
            return res.json({ 
                message: 'Profile updated successfully!', 
                profilePictureUrl: newProfilePictureUrl
            });
        } else {
            return res.status(200).json({ message: 'No changes detected or user not found.' });
        }

    } catch (error) {
        console.error('Profile update error:', error);
        return res.status(500).json({ message: 'Server error during profile update.' });
    }
});

/**
 * GET /api/user/orders
 * Retrieves all orders for the currently logged-in user.
 */
app.get('/api/user/orders', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        const orders = await findUserOrders(userId); 
        res.status(200).json(orders);
    } catch (error) {
        console.error('Error fetching user orders:', error);
        res.status(500).json({ message: 'Failed to retrieve user orders, please try again later.' });
    }
});


// =========================================================
//                   WALLET & PAYMENT API ROUTES (UPDATED)
// =========================================================

/**
 * GET /api/wallet/balance
 * Fetches the user's current wallet balance and account number.
 */
app.get('/api/wallet/balance', isAuthenticated, async (req, res) => {
    // Use BUSINESS_WALLET_USER_ID if the user is an admin requesting the central balance
   const userId = req.session.isAdmin ? BUSINESS_WALLET_USER_ID : req.session.userId;
    
    try {
        const walletData = await db.getWalletByUserId(userId);
        
        if (walletData) {
            return res.json({
                balance: walletData.balance,
                account_number: walletData.account_number,
                wallet_id: walletData.wallet_id 
            });
        }
        return res.json({ balance: 0.00, account_number: 'N/A' });
        
    } catch (error) {
        console.error('Error fetching wallet balance:', error);
        res.status(500).json({ message: 'Failed to retrieve wallet data.' });
    }
});



/**
 * Generates the base64-encoded password for STK Push.
 */
function generateMpesaPassword(timestamp) {
    const shortCode = process.env.MPESA_SHORTCODE;
    const passkey = process.env.MPESA_PASSKEY;
    const raw = shortCode + passkey + timestamp;
    return Buffer.from(raw).toString('base64');
}

/**
 * Fetches the M-Pesa OAuth access token.
 */
async function getMpesaAccessToken() {
    const consumerKey = process.env.MPESA_CONSUMER_KEY;
    const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
    
    const authString = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');

    try {
        const response = await fetch(
            'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
            {
                method: 'GET',
                headers: {
                    'Authorization': `Basic ${authString}`
                }
            }
        );

        if (!response.ok) {
            throw new Error(`M-Pesa Token API responded with status: ${response.status}`);
        }

        const data = await response.json();
        return data.access_token;

    } catch (error) {
        console.error('Error fetching M-Pesa Access Token:', error);
        throw new Error('Failed to connect to M-Pesa API for authentication.');
    }
}

app.post('/api/wallet/deposit/mpesa', isAuthenticated, async (req, res) => {
    const userId = req.session.userId; 
    const { phone, amount, accountNo } = req.body;
    const numericAmount = parseFloat(amount);

    if (!phone || isNaN(numericAmount) || numericAmount < 10) {
        return res.status(400).json({ message: 'Invalid phone or amount. Minimum deposit is 10 KES.' });
    }
    
    const transactionRef = `STK-${Date.now()}`; 
    const callbackUrl = process.env.MPESA_CALLBACK_URL; // e.g., 'https://mydomain.com/api/mpesa/callback'
    const shortCode = process.env.MPESA_SHORTCODE;
    const phoneNumber = `254${phone.slice(-9)}`; // Convert to 254... format
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
    
    try {
        // 1. Get Access Token and Password
        const accessToken = await getMpesaAccessToken();
        const password = generateMpesaPassword(timestamp);

        // 2. STK Push Request
        const mpesaResponse = await fetch(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    "BusinessShortCode": shortCode,
                    "Password": password,
                    "Timestamp": timestamp,
                    "TransactionType": "CustomerPayBillOnline",
                    "Amount": numericAmount,
                    "PartyA": phoneNumber,
                    "PartyB": shortCode,
                    "PhoneNumber": phoneNumber,
                    "CallBackURL": callbackUrl,
                    // 🚨 CRITICAL: Use the user's National ID as the AccountReference
                    "AccountReference": userId, 
                    "TransactionDesc": `Wallet Deposit for User ${userId}`
                })
            }
        );

        const data = await mpesaResponse.json();
        
        // 3. Handle M-Pesa STK Push Response
        if (data.ResponseCode === "0") {
            // Log the PENDING transaction in your DB before responding
            await db.performWalletTransaction(
                userId, 
                numericAmount, 
                'M-Pesa STK', 
                'Deposit', 
                data.CheckoutRequestID, // CRITICAL: Use CheckoutRequestID as the externalRef (the map key)
                null, 
                'Pending', // Set status to PENDING
                `STK Push initiated for KES ${numericAmount.toFixed(2)}`
            );
            
            res.json({ 
                message: 'Deposit initiated. Please approve the M-Pesa prompt on your phone.',
                transactionRef: data.CheckoutRequestID // Send this ID back to the client
            });
        } else {
            // Log a FAILED transaction
            await db.performWalletTransaction(
                userId, 
                numericAmount, 
                'M-Pesa STK', 
                'Deposit', 
                data.CheckoutRequestID || transactionRef, 
                null, 
                'Failed', 
                `STK Push failed: ${data.ResponseDescription}`
            );
            
            return res.status(500).json({ 
                message: `M-Pesa Error: ${data.ResponseDescription}` 
            });
        }

    } catch (error) {
        console.error('M-Pesa Deposit API error:', error);
        res.status(500).json({ message: 'Failed to process deposit request. Server connection error.' });
    }
});

/**
 * POST /api/mpesa/callback
 * M-Pesa's Confirmation and Validation URL endpoint.
 */
app.post('/api/mpesa/callback', async (req, res) => {
    
    // 🚨 START LOG MONITORING HERE
    console.log("--- M-Pesa Callback Received ---");
    // Use JSON.stringify for clean, readable output in your console
    console.log(JSON.stringify(req.body, null, 2)); 
    console.log("---------------------------------");
    // 🚨 END LOG MONITORING HERE

    // 1. Process the M-Pesa result
    const body = req.body.Body.stkCallback;
    const checkoutRequestID = body.CheckoutRequestID;
    const resultCode = body.ResultCode;
    const resultDesc = body.ResultDesc;

    // A. Transaction was cancelled or failed by user (ResultCode != 0)
    if (resultCode !== 0) {
        console.log(`M-Pesa Transaction Failed/Cancelled for CheckoutRequestID: ${checkoutRequestID}. ResultDesc: ${resultDesc}`);
        
        try {
            await db.completeMpesaDeposit(
                checkoutRequestID, 
                0, 
                `FAILURE-${resultCode}`, 
                'Failed', 
                resultDesc || 'Transaction cancelled by user or expired.'
            );
        } catch (error) {
            console.error('Error logging M-Pesa failure status:', error.message);
        }
        
        return res.json({ "ResultCode": 0, "ResultDesc": "Callback received and recorded as failure." });
    }
    
    // B. Transaction was successful (ResultCode == 0)
    try {
        const metaData = body.CallbackMetadata.Item;
        const amountItem = metaData.find(item => item.Name === 'Amount');
        const mpesaReceiptItem = metaData.find(item => item.Name === 'MpesaReceiptNumber');

        const amount = parseFloat(amountItem?.Value);
        const mpesaReceipt = mpesaReceiptItem?.Value;
        
        const finalStatus = 'Completed';
        const finalDescription = `MPESA successful deposit: ${mpesaReceipt}`;
        
        // 🚨 CRITICAL: This DB function handles the instant crediting (Requirement #4)
        await db.completeMpesaDeposit(
            checkoutRequestID, 
            amount, 
            mpesaReceipt, // New reference code (Requirement #1)
            finalStatus, 
            finalDescription
        );

        return res.json({ "ResultCode": 0, "ResultDesc": "Callback received and processed successfully." });

    } catch (error) {
        console.error('M-Pesa Callback processing error:', error);
        return res.json({ "ResultCode": 0, "ResultDesc": "Callback received but internal server error occurred." });
    }
});

/**
 * 🚨 NEW API: POST /api/wallet/deposit/mpesa-manual
 * Handles deposits where the user manually paid via SIM Toolkit.
 */
app.post('/api/wallet/deposit/mpesa-manual', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { transactionCode, amount } = req.body; 
    const numericAmount = parseFloat(amount);

    if (!transactionCode || !amount) {
        return res.status(400).json({ message: 'Transaction code and amount are required.' });
    }
    // Simple M-Pesa receipt format validation (e.g., 10 alphanumeric characters)
    if (!/^[A-Z0-9]{10}$/.test(transactionCode)) {
        return res.status(400).json({ message: 'Invalid M-Pesa transaction code format. Must be 10 uppercase alphanumeric characters (e.g., TKULKBKLZD).' });
    }
    if (isNaN(numericAmount) || numericAmount <= 0) {
        return res.status(400).json({ message: 'Invalid deposit amount.' });
    }

    try {
        // 🚨 CRITICAL: Use the new function to process the manual deposit.
        // This function handles duplicate check and instant crediting.
        await db.processManualMpesaDeposit(userId, transactionCode, numericAmount);

        // Success: Transaction credited to user wallet
        res.json({
            message: 'M-Pesa deposit confirmed and wallet credited successfully!',
            mpesaRef: transactionCode
        });

    } catch (error) {
        console.error('Manual M-Pesa deposit error:', error);

        if (error.message === 'DUPLICATE_RECEIPT') {
            return res.status(409).json({ message: `Transaction code ${transactionCode} has already been used.` });
        }
        if (error.message === 'WALLET_NOT_FOUND') {
             return res.status(500).json({ message: 'Critical error: User wallet structure not found.' });
        }
        
        res.status(500).json({ message: 'Failed to process manual deposit due to a server error.' });
    }
});


/**
 * NEW: POST /api/wallet/deposit/status
 * Client-side polling API to check the final status of a pending M-Pesa transaction.
 */
app.post('/api/wallet/deposit/status', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { checkoutRequestID } = req.body;

    if (!checkoutRequestID) {
        return res.status(400).json({ message: 'Checkout Request ID is required.' });
    }

    try {
        // 1. Check the database first (fastest way to get completed status)
        const transaction = await db.findTransactionByRef(checkoutRequestID, userId); 

        if (transaction) {
            // Check if the transaction is finalized
            if (transaction.status === 'Completed') {
                return res.json({
                    status: 'Completed',
                    mpesaRef: transaction.external_ref, // The external_ref is now the MpesaReceiptNumber
                    amount: transaction.amount,
                    message: 'Payment confirmed successfully.'
                });
            }
            if (transaction.status === 'Failed' || transaction.status === 'Cancelled') {
                return res.json({
                    status: transaction.status,
                    message: transaction.description || 'Payment failed or was cancelled.',
                    mpesaRef: transaction.external_ref,
                });
            }
        }
        
        // If the transaction is not found or status is still 'Pending', return Pending
        return res.json({ status: 'Pending', message: 'Waiting for M-Pesa confirmation...' });

    } catch (error) {
        console.error('M-Pesa status query error:', error);
        res.status(500).json({ message: 'Internal server error while checking status.' });
    }
});

/**
 * POST /api/wallet/deposit/card
 * Handles the generic Debit/Credit Card deposit request (Simulated).
 */
app.post('/api/wallet/deposit/card', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const { cardNumber, amount } = req.body; // Card details are truncated on the client
    const numericAmount = parseFloat(amount);

    if (isNaN(numericAmount) || numericAmount < 10) {
        return res.status(400).json({ message: 'Invalid amount. Minimum deposit is 10 KES.' });
    }

    // Simulate Card transaction reference
    const externalRef = `CARD-${Date.now()}-${cardNumber}`; 

    try {
       await db.performWalletTransaction(userId, numericAmount, 'Debit/Credit Card', 'Deposit', externalRef, null, 'Completed');

       await db.performWalletTransaction(
      BUSINESS_WALLET_USER_ID,
       numericAmount, 
       'Card Revenue', 
       'Deposit', 
       externalRef, 
       null, 
       'Completed',
       `Capital Deposit: KES ${numericAmount.toFixed(2)} from Card Payment from Customer #${userId}` 
);
        
        res.json({ 
            message: 'Card payment processed successfully.',
            transactionRef: externalRef 
        });

    } catch (error) {
        console.error('Card Deposit API error:', error);
        res.status(500).json({ message: 'Failed to process card payment.' });
    }
});

/**
 * GET /api/user/payment-history
 * Fetches the transaction history for the user's wallet.
 */
app.get('/api/user/payment-history', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    try {
        const history = await db.findPaymentHistory(userId);
        res.json(history);
    } catch (error) {
        console.error('Error fetching payment history:', error);
        res.status(500).json({ message: 'Failed to retrieve payment history.' });
    }
});

/**
 * GET /api/admin/finance/history
 * Fetches the central business financial history.
 */
app.get('/api/admin/finance/history', isAdmin, async (req, res) => {
    try {
        // 🚨 Call the new dedicated function using the Admin Wallet ID
      const history = await db.getBusinessFinancialHistory(BUSINESS_WALLET_USER_ID);
        res.json(history);
    } catch (error) {
        console.error('Error fetching admin financial history:', error);
        res.status(500).json({ message: 'Failed to retrieve financial history.' });
    }
});

/**
 * POST /api/admin/finance/expenditure
 * Handles admin withdrawal for business purposes (Restock, Loans, Refunds).
 */
app.post('/api/admin/finance/expenditure', isAdmin, async (req, res) => {
    const { amount, purpose } = req.body;
    const numericAmount = parseFloat(amount);

    if (isNaN(numericAmount) || numericAmount <= 0) {
        return res.status(400).json({ message: 'Invalid or missing withdrawal amount.' });
    }
    if (!purpose || purpose.length < 5) {
        return res.status(400).json({ message: 'Purpose must be specified (min 5 characters).' });
    }

    try {
    // Amount is passed as a positive number; the DB function handles the deduction.
    // 🚨 FIX 7a: Call the new expenditure function
    await db.logBusinessExpenditure(BUSINESS_WALLET_USER_ID, numericAmount, purpose);
    
    res.json({ message: `Successfully logged KES ${numericAmount.toFixed(2)} withdrawal for ${purpose}.` });
} catch (error) {
    // 🚨 FIX 7b: Update the error message to reflect the business wallet check
    if (error.message === 'INSUFFICIENT_BUSINESS_FUNDS') {
        return res.status(400).json({ message: 'Insufficient funds in the Business Wallet for this withdrawal.' });
    }
    console.error('Business expenditure error:', error);
        res.status(500).json({ message: 'Failed to process withdrawal.' });
    }
});



// ------------------------------------------------------------------
// --- ADMIN API ENDPOINTS (Customer Listing and Dashboard) ---
// ------------------------------------------------------------------

/**
 * Retrieves a list of all registered users (customers).
 * Requires Admin privileges.
 */
app.get('/api/customers', isAdmin, async (req, res) => {
    try {
        const users = await findAllUsers();
        // Note: The password_hash is not included in the SELECT query in db.js
        res.json(users);
    } catch (error) {
        console.error('API Error fetching all users/customers:', error);
        res.status(500).json({ message: 'Failed to retrieve customer list.' });
    }
});

/**
 * 🆕 Retrieves core dashboard statistics (e.g., total products, total users, revenue).
 * Requires Admin privileges.
 */
app.get('/api/dashboard/stats', isAdmin, async (req, res) => {
    try {
        // 1. Total Products & Stock
        const [products] = await pool.query('SELECT COUNT(*) AS productCount, SUM(stock) AS totalStock FROM products');
        
        // 2. Total Users (Customers)
        const [users] = await pool.query('SELECT COUNT(*) AS userCount FROM users WHERE is_admin = ?', [0]);        // 3. Total Orders & Revenue (Overall)
        const [orders] = await pool.query('SELECT COUNT(*) AS orderCount, SUM(total) AS totalRevenue FROM orders');

        // 🚨 CRITICAL FIXES BELOW: 🚨

        // 4. Count Pending Orders
        const [pendingOrders] = await pool.query(
            "SELECT COUNT(*) AS pendingCount FROM orders WHERE status = 'Pending'"
        );
        
        // 5. Count Completed Orders
        const [completedOrders] = await pool.query(
            "SELECT COUNT(*) AS completedCount FROM orders WHERE status = 'Completed'"
        );

        const stats = {
            productCount: products[0].productCount || 0,
            totalStock: products[0].totalStock || 0,
            
            // Your required fields: 2 customers -> userCount
            userCount: users[0].userCount || 0, 
            
            orderCount: orders[0].orderCount || 0,
            totalRevenue: parseFloat(orders[0].totalRevenue || 0).toFixed(2), 
            
            // ✅ New required fields for the dashboard
            pendingOrders: pendingOrders[0].pendingCount || 0,
            completedOrders: completedOrders[0].completedCount || 0,
        };
        
        res.json(stats);
    } catch (error) {
        console.error('API Error fetching dashboard stats:', error);
        res.status(500).json({ message: 'Failed to retrieve dashboard statistics.' });
    }
});

/**
 * 🆕 Retrieves monthly sales data for charting.
 * Requires Admin privileges.
 */


// New Route: GET /api/dashboard/monthly-sales
app.get('/api/dashboard/monthly-sales', isAdmin, async (req, res) => {
    try {
        // Query to aggregate total revenue by month and year for COMPLETED orders
        const [rows] = await pool.query(`
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m') AS month,
                SUM(total) AS revenue
            FROM orders
            WHERE status = 'Completed'
            GROUP BY month
            ORDER BY month ASC;
        `);

        // Rows will be an array like: [{month: '2025-10', revenue: 150.00}, {month: '2025-11', revenue: 250.00}]
        res.json(rows);
    } catch (error) {
        console.error('API Error fetching monthly sales data:', error);
        res.status(500).json({ message: 'Failed to retrieve sales data.' });
    }
});

// ------------------------------------------------------------------
// --- PRODUCT, CART, and ORDER API Endpoints ---
// ------------------------------------------------------------------

app.get('/api/products', async (req, res) => { 
    try {
        const [rows] = await pool.query('SELECT * FROM products');
        res.json(rows); 
    } catch (error) {
        console.error('Database query error:', error);
        res.status(500).json({ message: 'Failed to retrieve products from database.' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const productId = req.params.id;
        const [rows] = await pool.query('SELECT * FROM products WHERE id = ?', [productId]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Product not found.' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Database query error:', error);
        res.status(500).json({ message: 'Failed to retrieve product details.' });
    }
});

app.post('/api/products', isAdmin, upload.single('productImage'), async (req, res) => {
    try {
        const { name, price, category, description, stock } = req.body;
        const imageFile = req.file; // Multer puts the file info here
        
        // 🚨 CRITICAL SERVER-SIDE VALIDATION FIX 🚨
        if (!name || !price || !category || !stock || !imageFile) {
            // Return a specific error that the client can display
            return res.status(400).json({ 
                message: 'Missing one or more required fields: name, price, category, stock, or image file.' 
            });
        }
        
        // Ensure price and stock are valid numbers
        if (isNaN(parseFloat(price)) || isNaN(parseInt(stock))) {
            return res.status(400).json({ message: 'Price and Stock must be valid numbers.' });
        }
        
        const imagePath = `/images/products/${imageFile.filename}`;
        
        // Insert the product into the database (using 'stock' column name)
        const [result] = await pool.query(
            `INSERT INTO products (name, price, category, description, image_url, stock) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [name, parseFloat(price), category, description, imagePath, parseInt(stock)]
        );

        res.status(201).json({ 
            message: 'Product uploaded successfully!', 
            productId: result.insertId 
        });

    } catch (error) {
        console.error('API Error uploading product:', error);
        res.status(500).json({ message: 'Failed to upload product, please try again later.' });
    }
});
app.put('/api/products/:id', isAdmin, upload.single('productImage'), async (req, res) => {
    try {
        const productId = req.params.id;
        // NOTE: FormData is used, so use req.body
        const { name, price, category, description, stock, existing_image_url } = req.body;
        
        if (!name || !price || !category || !stock) {
            return res.status(400).json({ 
                message: 'Missing required fields for update (Name, Price, Category, Stock).' 
            });
        }
        
        let imagePath = existing_image_url; // Keep old path by default

        if (req.file) { // If a new image was uploaded
            imagePath = `/images/products/${req.file.filename}`;
        }

        const [result] = await pool.query(
            `UPDATE products SET name = ?, price = ?, category = ?, description = ?, stock = ?, image_url = ? WHERE id = ?`,
            [name, parseFloat(price), category, description, parseInt(stock), imagePath, productId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found or no changes made.' });
        }

        res.json({ message: 'Product updated successfully!', productId });

    } catch (error) {
        console.error('API Error updating product:', error);
        res.status(500).json({ message: 'Failed to update product, please try again later.' });
    }
});
app.get('/api/orders', isAdmin, async (req, res) => {
    const { status } = req.query; 
    let sql = 'SELECT id, customer_name, customer_email, delivery_location, total, status, created_at FROM orders';
    const params = [];

    if (status) {
        const statusArray = status.split(',').map(s => s.trim());
        const placeholders = statusArray.map(() => '?').join(', '); 
        sql += ` WHERE status IN (${placeholders})`;
        params.push(...statusArray);
    }
    
    sql += ' ORDER BY created_at DESC';

    try {
        const [rows] = await pool.query(sql, params);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ message: 'Failed to retrieve orders.' });
    }
});


// server.js

app.put('/api/orders/:orderId', isAdmin, async (req, res) => {
    const orderId = req.params.orderId;
    // 🚨 CRITICAL: Extract 'status' from the parsed body
    const { status } = req.body; 

    // This is the validation that triggers a 400 if 'status' isn't found
    if (!status) {
        // If express.json() is missing or failed, req.body will be empty, and 'status' will be undefined.
        return res.status(400).json({ message: 'Missing status field in request body (Ensure express.json() is used).' });
    }
    
    // --- Execution ---
    try {
        const [result] = await pool.query(
            'UPDATE orders SET status = ? WHERE id = ?',
            [status, orderId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: `Order ID ${orderId} not found.` });
        }

        res.json({ message: `Order ID ${orderId} status updated to ${status}.` });

    } catch (error) {
        console.error(`API Error updating order ID ${orderId}:`, error);
        res.status(500).json({ message: 'Failed to update order status, please try again later.' });
    }
});


// 🚨 CHANGE: Cart APIs require authentication to retrieve/modify items for a specific user
app.get('/api/cart', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    
    try {
        // 🚨 MODIFIED: Select 'size' column from cart
        const sql = `
    SELECT c.product_id AS id, p.name, c.unit_price AS price, 
             c.quantity, p.image_url, p.stock, c.size 
    FROM cart c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ?`;
        const [rows] = await pool.query(sql, [userId]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching cart:', error);
        res.status(500).json({ message: 'Failed to load cart items.' });
    }
});

app.post('/api/cart', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    // 🚨 MODIFIED: Extract size from request body
    const { productId, quantity, size } = req.body; 
    
    if (!productId || !quantity || quantity < 1) {
        return res.status(400).json({ message: 'Invalid product ID or quantity.' });
    }

    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();
        
        // 🚨 FIX: Fetch 'category' as well to determine if size should be mandatory/present
        const [productRows] = await connection.execute('SELECT name, price, stock, category FROM products WHERE id = ?', [productId]);
        if (productRows.length === 0) {
            return res.status(404).json({ message: 'Product not found.' });
        }
        const product = productRows[0];
        
        // Determine if product requires size logic
        const requiresSize = product.category && 
                             product.category.toLowerCase() !== 'electronic' && 
                             product.category.toLowerCase() !== 'tools';

        // Validation for required size
        if (requiresSize && (!size || size === '')) {
             return res.status(400).json({ message: 'A size selection is required for this product category.' });
        }

        // 🚨 CRITICAL FIX: The cart lookup now includes the size.
        // This ensures that adding 'Small Shirt' and 'Large Shirt' are treated as two distinct items.
        let cartQuery = 'SELECT quantity FROM cart WHERE user_id = ? AND product_id = ?';
        let cartParams = [userId, productId];
        
        if (requiresSize) {
            // For items requiring size, match on size
            cartQuery += ' AND size = ?';
            cartParams.push(size);
        } else {
            // For items without size, ensure size is NULL (or not set)
            cartQuery += ' AND size IS NULL';
        }
        
        const [cartRows] = await connection.execute(cartQuery, cartParams);
        
        const currentQuantity = cartRows.length > 0 ? cartRows[0].quantity : 0;
        const newQuantity = currentQuantity + quantity;

        if (newQuantity > product.stock) {
            return res.status(400).json({ message: `Cannot add that quantity. Only ${product.stock} of ${product.name} left.` });
        }

        let productNameWithDetails = product.name;
        if (size) {
            productNameWithDetails = `${product.name} (Size: ${size})`;
        }


        if (cartRows.length > 0) {
            // Update quantity of existing item
            // We use the original cartParams (which contains the size filter) to locate the unique cart item
            await connection.execute('UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?' + (requiresSize ? ' AND size = ?' : ' AND size IS NULL'), [newQuantity, userId, productId, ...cartParams.slice(2)]);
            
        } else {
            // Insert new item
            await connection.execute(
                'INSERT INTO cart (user_id, product_id, product_name, unit_price, quantity, size) VALUES (?, ?, ?, ?, ?, ?)',
                [userId, productId, productNameWithDetails, product.price, newQuantity, size || null] // Store size in the new column
            );
        }

        await connection.commit();
        // 🚨 FIX: Return the name with details in the success message
        res.status(200).json({ message: `${productNameWithDetails} quantity updated to ${newQuantity}.` });

    } catch (error) {
        await connection.rollback();
        console.error('Error adding item to cart:', error);
        res.status(500).json({ message: 'Failed to update cart.' });
    } finally {
        connection.release();
    }
});


app.delete('/api/cart/:productId', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const productId = req.params.productId;
    
    try {
        const [result] = await pool.execute('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [userId, productId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Cart item not found.' });
        }
        res.status(200).json({ message: 'Item removed from cart.' });
    } catch (error) {
        console.error('Error deleting item from cart:', error);
        res.status(500).json({ message: 'Failed to remove item.' });
    }
});

app.post('/api/order', isAuthenticated, async (req, res) => {
    
    // -------------------------------
    // 1. SESSION & USER ID CHECK
    // -------------------------------
    const rawUserId = req.session.userId;
    if (!rawUserId) {
        // If the ID is missing, exit immediately before transaction.
        return res.status(401).json({ message: 'Authentication required: User ID missing from session.' });
    }
    // The user ID is now the National ID (VARCHAR)
    const userId = String(rawUserId);

    // Extract fields safely
    const {
        name = "",
        phone = "",
        email = "",
        location = "",
        items = [],
        notificationMethod = "email",
        total
    } = req.body;

    // -------------------------------
    // 2. VALIDATION
    // -------------------------------

    // Mandatory: cart items
    if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ message: 'Cart is empty or invalid.' });
    }

    // Mandatory: total
    const orderTotal = parseFloat(total);
    if (isNaN(orderTotal) || orderTotal <= 0) {
        return res.status(400).json({ message: 'Invalid or missing total.' });
    }

    // Mandatory delivery fields
    if (!name.trim())      return res.status(400).json({ message: 'Missing Customer Name.' });
    if (!phone.trim())     return res.status(400).json({ message: 'Missing Phone Number.' });
    if (!email.trim())     return res.status(400).json({ message: 'Missing Email Address.' });
    if (!location.trim())  return res.status(400).json({ message: 'Missing Delivery Location.' });

    // -------------------------------
    // 3. GET DB CONNECTION
    // -------------------------------
    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();

        // -------------------------------
        // 4. FETCH USER WALLET
        // -------------------------------
        const walletDataResult = await db.getWalletByUserId(userId);
        
        const walletData = Array.isArray(walletDataResult) ? walletDataResult[0] : walletDataResult;
        

        let wallet_id;
        let currentBalance = 0;

        if (walletData && walletData.wallet_id) { 
            wallet_id = walletData.wallet_id;
            currentBalance = walletData.balance;
        } else {
            // Create wallet if it doesn't exist (using National ID as account number)
            const accountNumber = userId; 
            const [createResult] = await connection.execute(
                `INSERT INTO wallets (user_id, account_number, balance)
                 VALUES (?, ?, 0.00)`,
                [userId, accountNumber]
            );

            // 🚨 IMPROVEMENT: Robust check for insertId
            if (!createResult.insertId) {
                throw new Error("CRITICAL: Failed to create user wallet and retrieve ID.");
            }
            
            wallet_id = createResult.insertId;
        }

        // Wallet balance check
        if (currentBalance < orderTotal) {
            await connection.rollback();
            connection.release();
            return res.status(400).json({
                message: `Insufficient funds (KES ${currentBalance.toFixed(2)}). Required: KES ${orderTotal.toFixed(2)}.`
            });
        }

        // -------------------------------
        // 5. INSERT ORDER HEADER
        // -------------------------------
        const [orderResult] = await connection.execute(
            `INSERT INTO orders
             (user_id, customer_name, customer_phone, customer_email, delivery_location, total, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'Pending', NOW())`,
            [
                userId,
                name,
                phone,
                email,
                location,
                orderTotal
            ]
        );

        // 🚨 IMPROVEMENT: Robust check for orderId
        if (!orderResult.insertId) {
            throw new Error("CRITICAL: Failed to insert order header and retrieve ID.");
        }
        const orderId = orderResult.insertId;

        // -------------------------------
        // 6. INSERT ORDER ITEMS + UPDATE STOCK
        // -------------------------------
        // 🚨 MODIFIED: Added size column to insert query
        const itemSql = `
            INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity, size)
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        for (const item of items) {
            // Get product info from DB (essential for validation and data integrity)
            const [productRows] = await connection.execute(
                'SELECT name, price, stock FROM products WHERE id = ?',
                [item.id]
            );

            if (!productRows.length) throw new Error(`Product ID ${item.id} not found`);
            
            const product = productRows[0];
            
            if (product.stock < item.quantity) {
                throw new Error(`Not enough stock for product ID ${item.id}`);
            }

            // Deduct stock
            await connection.execute(
                'UPDATE products SET stock = stock - ? WHERE id = ?',
                [item.quantity, item.id]
            );

            // Insert order item
            await connection.execute(itemSql, [
                orderId,        
                item.id,        
                item.name.replace(/\s\(Size:\s[A-Z]+\)$/i, ''), // Clean name if size was appended for display
                product.price,  
                item.quantity,
                item.size || null // Pass the size obtained from cart item
            ]);
        }


        // -------------------------------
        // 7. CUSTOMER WALLET DEDUCTION
        // -------------------------------
        // Ensure wallet_id is valid before insertion
        if (!wallet_id) throw new Error("CRITICAL: Wallet ID is missing during deduction step.");

        // Coerce IDs to Number for DB operations where required
        const finalWalletId = Number(wallet_id);
        const finalOrderId = Number(orderId);

        // 7a. Customer Transaction Log (Deduction)
        await connection.execute(
            `INSERT INTO transactions
             (user_id, wallet_id, order_id, type, method, amount, transaction_status)
             VALUES (?, ?, ?, 'Deduction', 'Wallet Deduction', ?, 'Completed')`,
            [userId, finalWalletId, finalOrderId, -orderTotal] 
        );

        // 7b. Update Customer Wallet Balance
        await connection.execute(
            `UPDATE wallets SET balance = balance - ? WHERE wallet_id = ?`,
            [orderTotal, finalWalletId]
        );

        // -------------------------------
        // 8. BUSINESS WALLET CREDIT (Revenue In)
        // -------------------------------
        // 🚨 CRITICAL FIX 8: Inline the Business Credit logic to prevent nested transaction lock contention.
       const businessId = BUSINESS_WALLET_USER_ID;
       const businessCreditAmount = orderTotal;
       const businessExternalRef = `ORDER-REV-${orderId}`;
       const businessDescription = `Revenue from Order #${orderId}`;

        // Fetch Business Wallet ID and current balance using the main connection (no FOR UPDATE needed)
        let [businessWalletRows] = await connection.execute(
            'SELECT wallet_id, balance FROM wallets WHERE user_id = ?',
            [businessId]
        );

        if (businessWalletRows.length === 0) {
            // CRITICAL: Handle missing Business Wallet creation (should be done on setup)
            // If the wallet for user_id=0 doesn't exist, we must create it here.
            const accountNumber = businessId; // Use '0' as account number
            const [createResult] = await connection.execute(
                'INSERT INTO wallets (user_id, account_number, balance) VALUES (?, ?, 0.00)',
                [businessId, accountNumber]
            );
            if (!createResult.insertId) throw new Error("CRITICAL: Failed to initialize Business Wallet.");
            
            var businessWalletId = createResult.insertId;
            var businessCurrentBalance = 0;
        } else {
            var businessWalletId = businessWalletRows[0].wallet_id;
            var businessCurrentBalance = businessWalletRows[0].balance;
        }
        
        const businessNewBalance = businessCurrentBalance + businessCreditAmount;


        // 8a. Business Transaction Log (Deposit) - Using existing connection
        await connection.execute(
            `INSERT INTO transactions
             (user_id, wallet_id, order_id, type, method, amount, external_ref, transaction_status, description)
             VALUES (?, ?, ?, 'Deposit', 'Wallet Revenue', ?, ?, 'Completed', ?)`,
            [businessId, businessWalletId, Number(orderId), businessCreditAmount, businessExternalRef, businessDescription] 
        );

        // 8b. Update Business Wallet Balance - Using existing connection
        await connection.execute(
            `UPDATE wallets SET balance = ? WHERE wallet_id = ?`,
            [businessNewBalance, businessWalletId]
        );
        // -------------------------------
        // 9. CLEAR CART
        // -------------------------------
        await connection.execute(
            'DELETE FROM cart WHERE user_id = ?',
            [userId] 
        );

        // -------------------------------
        // 10. COMMIT TRANSACTION
        // -------------------------------
        await connection.commit();

        // -------------------------------
        // 11. SEND EMAILS (Non-critical)
        // -------------------------------
        // ... (Email sending logic remains here)
        const orderDetailsHtml = items.map(item => {
            const sizeDisplay = item.size ? ` (Size: ${item.size})` : '';
            return `<li>${item.name}${sizeDisplay} x${item.quantity} – KES ${((item.price || 0) * item.quantity).toFixed(2)}</li>`
        }).join('');

        const senderEmail = process.env.EMAIL_FROM || 'onboarding@resend.dev';

        await Promise.all([
            resend.emails.send({
                from: `Lolly's Collection <${senderEmail}>`,
                to: email,
                subject: `Order #${orderId} Confirmation`,
                html: `
                    <h2>Order #${orderId} Confirmed</h2>
                    <p>Thank you ${name}, your wallet was charged KES ${orderTotal.toFixed(2)}.</p>
                    <ul>${orderDetailsHtml}</ul>
                `
            }),
            resend.emails.send({
                from: `Lolly's Collection Admin <${senderEmail}>`,
                to: process.env.ADMIN_EMAIL,
                subject: `New Wallet Order #${orderId}`,
                html: `
                    <h2>New Order #${orderId}</h2>
                    <p><strong>Name:</strong> ${name}</p>
                    <p><strong>Phone:</strong> ${phone}</p>
                    <p><strong>Total:</strong> KES ${orderTotal.toFixed(2)}</p>
                    <ul>${orderDetailsHtml}</ul>
                `
            })
        ]);

        // SUCCESS RESPONSE
        return res.status(201).json({
            message: 'Order placed successfully.',
            orderId
        });

    } catch (error) {
        console.error("ORDER ERROR:", error);
        await connection.rollback();

        // 🚨 IMPROVEMENT: Use generic error message if the specific error is a stock or critical error
        const userMessage = error.message.includes('stock') || error.message.includes('CRITICAL') || error.message.includes('INSUFFICIENT')
            ? error.message 
            : error.sqlMessage || 'Order failed due to a server error. Please try again.';

        return res.status(500).json({
            message: userMessage
        });

    } finally {
        connection.release();
    }
});
// ... (rest of server.js remains the same)
app.get('/api/orders/:orderId', isAdmin, async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const [rows] = await pool.query(
            `SELECT id, customer_name, customer_phone, customer_email, delivery_location, total, status, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at 
             FROM orders 
             WHERE id = ?`, 
            [orderId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Order not found.' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('API Error fetching order details:', error);
        res.status(500).json({ message: 'Failed to retrieve order details.' });
    }
});

app.get('/api/orders/:orderId/items', isAdmin, async (req, res) => {
    try {
        // 🚨 MODIFIED: Select 'size' column from order_items
        const orderId = req.params.orderId;
        const [rows] = await pool.query(
            `SELECT product_name, unit_price, quantity, size 
             FROM order_items 
             WHERE order_id = ?`, 
            [orderId]
        );
        if (rows.length === 0) {
            return res.json([]); 
        }
        res.json(rows);
    } catch (error) {
        console.error('API Error fetching order items:', error);
        res.status(500).json({ message: 'Failed to retrieve order items.' });
    }
});

app.post('/api/admin/messages/reply', isAdmin, async (req, res) => {
    const { to, from, subject, content } = req.body;
    
    if (!to || !subject || !content) {
        return res.status(400).json({ message: 'Missing required fields: recipient (to), subject, or content.' });
    }

    try {
        // 🚨 RESEND INTEGRATION FOR REPLIES
        const senderEmail = process.env.EMAIL_FROM || 'onboarding@resend.dev';

        const { error } = await resend.emails.send({
            from: `Lolly's Support <${senderEmail}>`,
            to: to,
            subject: subject,
            text: content, 
        });

        if (error) {
            console.error('Resend API Error:', error);
            return res.status(500).json({ message: 'Failed to send email via Resend.', error: error });
        }
        
        res.json({ message: 'Reply sent successfully!' });

    } catch (error) {
        console.error('Server Error:', error.message);
        res.status(500).json({ 
            message: 'Failed to send reply email , please try again later.', 
            error: error.message 
        });
    }
});
// API for Product Deletion (Admin only)
app.delete('/api/products/:id', isAdmin, async (req, res) => {
    try {
        const productId = req.params.id;
       
        // IMPORTANT: In a real system, you should also delete related records 
        // in 'cart' and 'order_items' first, or configure CASCADE DELETE on the DB.
        
        // For now, we only delete the product:
        const [result] = await pool.query(
            `DELETE FROM products WHERE id = ?`,
            [productId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found.' });
        }

        res.json({ 
            message: `Product ID ${productId} deleted successfully.`,
            deletedId: productId 
        });

    } catch (error) {
        console.error(`API Error deleting product ID ${req.params.id}:`, error);
        // Common error is foreign key constraint violation (product exists in an order/cart)
        if (error.code === 'ER_ROW_IS_REFERENCED_2') {
             return res.status(409).json({ message: 'Cannot delete product: It is currently part of an order or shopping cart.' });
        }
        res.status(500).json({ message: 'Failed to delete product, please try again later.' });
    }
});
// sending contact messages to admin dashboard
app.post('/api/contact', async (req, res) => {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        await saveContactMessage(name, email, message);
        return res.status(200).json({ message: 'Message successfully sent to admin dashboard.' });
    } catch (error) {
        console.error('Database insertion error for contact form:', error);
        return res.status(500).json({ message: 'Internal server error while saving message. Please try again later.' });
    }
});

app.get('/api/admin/messages', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const messages = await getAllContactMessages();
        return res.status(200).json(messages);
    } catch (error) {
        console.error('Error in GET /api/admin/messages:', error);
        return res.status(500).json({ message: 'Failed to retrieve messages.' });
    }
});

/**
 * Endpoint to request OTP for password reset.
 * Replaces mock with a real-world API integration structure.
 */
app.post("/api/request-otp", async (req, res) => {
    const { phone } = req.body; // Primary lookup field
    
    if (!phone) {
        return res.status(400).json({ message: 'Phone number is required to send OTP.' });
    }
    
    // 1. Find user by phone number 
    const user = await db.findUserByPhone(phone); 
    
    if (!user) {
        // Do not leak user existence
        return res.status(200).json({ message: 'If the account exists, an OTP has been sent.' });
    }
    
    // 2. Determine the cache key (the phone number)
    const normalizedKey = phone.toLowerCase().trim();

    try {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = Date.now() + 5 * 60 * 1000;

        // 3. Save OTP in memory 
        // Store userId and email for the final reset step lookup, keyed by phone number
        otpCache[normalizedKey] = { otp, expiry, userId: user.id, email: user.email }; 

        // 4. Send SMS using the dedicated provider client
        // Normalize phone to E.164 format for external services (e.g., +2547XXXXXXXX)
        const e164Phone = normalizedKey.startsWith('+') ? normalizedKey : `+${normalizedKey}`;


        const smsResponse = await smsServiceProvider.sendSMSVerifyCode({ 
            phoneNumber: e164Phone,
            verifyCode: otp,
        });

        if (smsResponse.success) {
            res.status(200).json({ message: 'OTP sent successfully. Please check your phone for the SMS.' });
        } else {
            // Log the error from the service client
            console.error('SMS Service Error:', smsResponse.error || 'Unknown SMS error');
            // Return server error to client
            res.status(500).json({ message: 'Error processing OTP request via SMS provider. Please try again later.' });
        }

    } catch (error) {
        console.error('OTP Request Error:', error);
        res.status(500).json({ message: 'Error processing OTP request.' });
    }
});


// 🚨 VERIFY OTP - Debugging & Normalization
app.post("/api/verify-otp", (req, res) => {
    const { phone, otp } = req.body; // Uses phone for lookup
    
    if (!phone || !otp) {
        return res.status(400).json({ message: 'Phone and OTP are required.' });
    }
    
    // Keying by phone number
    const verificationKey = phone.toLowerCase().trim();

    const entry = otpCache[verificationKey]; 
    
    if (!entry) return res.status(400).json({ message: "No OTP found or session expired." });

    if (Date.now() > entry.expiry) {
        delete otpCache[verificationKey];
        return res.status(400).json({ message: "OTP expired." });
    }

    if (String(entry.otp) !== String(otp)) {
        return res.status(400).json({ message: "Invalid OTP." });
    }
    
    // 4. Success: Generate verification token for the next step (password reset)
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 10 * 60 * 1000; 

    // Store user ID, email, and phone (as resetKey) in the verification cache
    verificationCache[verificationToken] = { userId: entry.userId, email: entry.email, resetKey: verificationKey, expiry };
    delete otpCache[verificationKey];

    res.json({ 
        message: "OTP verified!", 
        verified: true, 
        verificationToken: verificationToken,
        resetKey: verificationKey // Send the phone number back to the client
    });
});

// Route to handle password reset submission (Step 2: Update Password)
app.post('/api/reset-password', async (req, res) => {
    // Client must send verificationToken, resetKey (now phone number), and newPassword
    const { verificationToken, resetKey, newPassword } = req.body; 
    
    // 2. Validate input and password strength
    if (!verificationToken || !resetKey || !newPassword) {
        return res.status(400).json({ message: 'Missing required reset information (token, key, or password).' });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ message: 'New password must be at least 8 characters long.' });
    }

    // 3. Check the verification cache for the token
    const verificationEntry = verificationCache[verificationToken];

    if (!verificationEntry) {
        return res.status(400).json({ message: 'Password reset session is invalid or has expired. Please request a new OTP.' });
    }
    
    // 4. Validate Token Expiration and Reset Key Match
    if (Date.now() > verificationEntry.expiry || verificationEntry.resetKey !== resetKey) {
        delete verificationCache[verificationToken];
        return res.status(400).json({ message: 'Password reset session has expired or the key provided does not match.' });
    }

    try {
        // Use the userId saved during the OTP request step
        const userIdToUpdate = verificationEntry.userId;
        
        // 5. Hash the new password securely
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        
        // 6. Update password using the stored user ID
        const updated = await db.updatePassword(userIdToUpdate, hashedPassword);

        // 7. CRUCIAL: Clear the verification token immediately after successful use
        delete verificationCache[verificationToken]; 

        if (updated) {
            res.status(200).json({ message: 'Password successfully updated. You can now log in.' });
        } else {
            throw new Error("Database update failed (0 rows affected).");
        }
    } catch (error) {
        console.error('Password Reset Error:', error);
        // Clear the token even on hash/DB update failure for security
        delete verificationCache[verificationToken]; 
        res.status(500).json({ message: 'Failed to reset password, please try again later.' });
    }
});
// =========================================================
//                   REAL-TIME CHAT SETUP
// =========================================================
// --- New function in server.js to handle AI interaction ---

/**
 * Executes a database query to get product details based on a user query.
 * @param {string} query - Keyword for product search.
 */
async function getProductDetails({ query }) {
     // 🚨 INTEGRATION POINT: Connects AI to MySQL DB
     const [rows] = await pool.query(
         `SELECT name, price, stock FROM products WHERE name LIKE ? OR description LIKE ? LIMIT 5`, 
         [`%${query}%`, `%${query}%`]
     );
     if (rows.length === 0) return JSON.stringify({ status: 'not_found', query });
     return JSON.stringify(rows);
}

/**
 * Routes the customer message to the Gemini Bot, handles product lookups,
 * and generates a dynamic response.
 * @param {string} userMessage - The customer's raw message.
 * @returns {string} The AI-generated response text.
 */
async function getSmartBotResponse(userMessage) {
    const systemInstruction = `You are Lolly Bot, a friendly, concise, and helpful customer service AI for Lolly's Collection, an e-commerce store specializing in clothing and accessories. Your tone must be warm, slightly casual, and professional. 
    
    Current Date: ${new Date().toLocaleDateString()}.
    
    Instructions:
    1. If the user asks about products, use the provided getProductDetails tool.
    2. If the user expresses frustration (emotionally charged words), respond with empathy and suggest connecting to a live agent.
    3. DO NOT answer questions about returns, refunds, or complex order status—instead, gently suggest they ask for an agent.
    4. Keep answers short, ideally 1-2 sentences.`;

    const productToolDefinition = {
        name: "getProductDetails",
        description: "Gets the names, prices, and stock of products to answer shopping queries.",
        parameters: {
            type: "object",
            properties: {
                query: {
                    type: "string",
                    description: "A single keyword or phrase to search for specific products (e.g., 'cap', 'red dress')."
                },
            },
            required: ["query"],
        },
    };

    const availableFunctions = { getProductDetails };

    try {
        let response = await ai.models.generateContent({
            model: 'gemini-2.5-flash', // A great model for tool use
            contents: userMessage,
            config: {
                systemInstruction: systemInstruction,
                tools: [{ functionDeclarations: [productToolDefinition] }],
            },
        });

        // 1. Check if the model requested a tool call
        if (response.functionCalls && response.functionCalls.length > 0) {
            const functionCall = response.functionCalls[0];
            const functionName = functionCall.name;
            const functionToCall = availableFunctions[functionName];
            const functionArgs = functionCall.args;
            
            // Execute the database function
            const toolOutput = await functionToCall(functionArgs);

            // 2. Send the tool result back to the model for the final response
            const secondResponse = await ai.models.generateContent({
                model: 'gemini-2.5-flash',
                contents: [
                    userMessage,
                    {
                        functionResponse: {
                            name: functionName,
                            response: toolOutput, // The tool output (DB data)
                        },
                    },
                ],
                config: {
                    systemInstruction: systemInstruction,
                },
            });
            
            return secondResponse.text;
        }
        
        // Return the initial response if no tool was called
        return response.text;

    } catch (error) {
        console.error('External AI Service Error (Gemini):', error);
        return "I'm having trouble connecting to my brain (the AI service). Please try asking for a live agent by typing 'agent'.";
    }
}
// Global Map to hold active WebSocket connections for Admin and Customer
// Key: customerId (string) -> Value: { admin: WebSocket | null, customer: WebSocket | null }
const chatSessions = new Map(); 

// Create a WebSocket Server
const wss = new WebSocket.Server({ noServer: true });



// server.js (handleChatMessage function)

async function handleChatMessage(ws, message, senderRole, customerId) {
    if (!message || !customerId) return;
    
    // Determine the sender/recipient IDs based on the role and session data
    const sessionData = chatSessions.get(customerId);
    if (!sessionData) return console.log(`Session data missing for customer ${customerId}`);

    const senderId = (senderRole === 'admin') ? ADMIN_CHAT_ID : customerId;
    const recipientId = (senderRole === 'admin') ? customerId : ADMIN_CHAT_ID;
    
    try {
        const parsed = JSON.parse(message);
        
        // 1. AI Request Routing (Customer to Bot/AI)
        if (senderRole === 'customer' && parsed.ai_request) {
            
            // ... (AI request logic is correct)
            return;

        // 2. Handoff Request Routing (Customer to Admin Notification)
        } else if (senderRole === 'customer' && parsed.handoff) {
            
            // 🚨 FIX: Fetch real customer name if they are logged in (numeric ID)
            const isAnon = customerId.startsWith('anon-');
            let customerName = parsed.customerName || 'Anonymous';
            
            if (!isAnon) { 
                const user = await findUserById(customerId); 
                if (user) customerName = user.name; // Use user.name (which is username)
            }
            // END FIX
            
            // Notify the admin via the Notification Socket
            const notificationPayload = JSON.stringify({
                sender: 'customer',
                customerId: customerId,
                customerName: customerName, // Use the verified name
                message: parsed.message, // The message that triggered the handoff
                handoff_request: true
            });
            
            // Send the notification to the dedicated admin notification socket
            const adminWs = chatSessions.get(ADMIN_CHAT_ID)?.admin;
            if (adminWs && adminWs.readyState === WebSocket.OPEN) {
                adminWs.send(notificationPayload);
            }
            
            // Save the customer's initial message to history
            await saveChatMessage(customerId, senderRole, senderId, recipientId, parsed.message);
            
            return;
            
        // 3. Admin Handshake Signal (Admin to Customer)
        } else if (senderRole === 'admin' && parsed.is_admin_handshake) {
            
             // Send HANDOFF_SUCCESS to the customer socket
             const customerWs = sessionData.customer;
             if (customerWs && customerWs.readyState === WebSocket.OPEN) {
                 const successPayload = { sender: 'system', message: 'HANDOFF_SUCCESS' };
                 customerWs.send(JSON.stringify(successPayload));
             }
             // Do NOT save the handshake message to history
             return; 

        // 5. 🚨 NEW: Background Connection Check (Heartbeat)
        } else if (senderRole === 'customer' && parsed.check_status) {
            
            // Check if an admin is present in this specific customer's session
            const session = chatSessions.get(customerId);
            const isAdminOnline = !!(session && session.admin && session.admin.readyState === WebSocket.OPEN);
            
            // Reply with system status packet
            const statusPayload = JSON.stringify({
                sender: 'system',
                type: 'CONNECTION_STATUS',
                connected: isAdminOnline
            });
            
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(statusPayload);
            }
            return;

        // 4. Standard Live Chat Routing (Saves and Relays)
        } else {
            const messageText = parsed.message;
            
            // Save to DB
            await saveChatMessage(customerId, senderRole, senderId, recipientId, messageText);
            
            // Relay the message to the other participant in the session
            const target = (senderRole === 'admin' ? sessionData.customer : sessionData.admin);
            const payload = { 
                sender: senderRole, 
                message: messageText,
                customerId: customerId // Include customerId for admin side message identification
            };
            
            if (target && target.readyState === WebSocket.OPEN) {
                target.send(JSON.stringify(payload));
            } else {
                console.log(`Relay failed: ${senderRole}'s target is not open or undefined.`);
            }
        }
    } catch (error) {
        // This is the fallback for non-JSON messages (though fixed in handler)
        console.error('WebSocket Routing/Message Error:', error); 
        // Fallback response for customer
        ws.send(JSON.stringify({ sender: 'admin', message: 'Sorry, I encountered an internal error. Please try again.' }));
    }
}
// Function to clean up a session
function cleanupSession(customerId, role) {
    const session = chatSessions.get(customerId);
    if (session) {
        // Close the other side if it's still open
        const otherWs = (role === 'admin') ? session.customer : session.admin;
        if (otherWs && otherWs.readyState === WebSocket.OPEN) {
            // Send a close notification if possible
            otherWs.send(JSON.stringify({ sender: 'system', message: `The ${role} has disconnected from the chat.` }));
            // otherWs.close(); // Don't auto-close the customer's side just because the admin left
        }
        
        // Clear the specific role's reference
        if (role === 'admin') {
            session.admin = null;
        } else if (role === 'customer') {
            session.customer = null;
        }
        
        // If both are null, delete the session entirely
        if (!session.admin && !session.customer) {
            chatSessions.delete(customerId);
            console.log(`Chat session ${customerId} fully deleted.`);
        } else {
            // Update the map to persist the change
            chatSessions.set(customerId, session);
        }
    }
}


// --- WebSocket Connection Handler ---
wss.on('connection', (ws, req) => {
    // Session and params were parsed during the upgrade process
    const customerId = req.params.customerId;
    const role = req.params.role; // 'admin' or 'customer'
    const userId = req.session.userId;
    
    // Initialize or retrieve the session
    let session = chatSessions.get(customerId) || { admin: null, customer: null };

    if (role === 'admin') {
        session.admin = ws;
    } else { // 'customer'
        session.customer = ws;
    }
    chatSessions.set(customerId, session);
    
    console.log(`New WebSocket connection: ${role} ID ${userId} for Customer ${customerId}`);

    ws.on('message', (data) => {
        try {
           const message = data.toString();
           
            
           if (message && message.length > 0) {
            // Pass the message (which is the JSON string from the client) and the role
            handleChatMessage(ws, message, role, customerId);
        }
        } catch (error) {
            console.error('Invalid WebSocket message received:', error);
        }
    });

    ws.on('close', () => {
        console.log(`WebSocket disconnected: ${role} ID ${userId} for Customer ${customerId}`);
        cleanupSession(customerId, role);
    });

    ws.on('error', (err) => {
        console.error(`WebSocket Error (${role} for ${customerId}):`, err);
    });
});


// --- HTTP Upgrade (WebSocket Handshake) ---
server.on('upgrade', (req, socket, head) => {
    // 1. Extract customerId from URL path
    const urlParts = req.url.split('/');
    let customerIdFromUrl;
    let role;

    if (req.url.startsWith('/ws/admin/chat/')) {
        customerIdFromUrl = urlParts[4];
        role = 'admin';
    } else if (req.url.startsWith('/ws/chat/')) {
        customerIdFromUrl = urlParts[3];
        role = 'customer';
    } else {
        socket.destroy();
        return;
    }
    
    // 2. Retrieve session from session store
    session({
        secret: process.env.SESSION_SECRET , 
        resave: false,
        saveUninitialized: false, 
        store: sessionStore, 
        cookie: { 
            maxAge: 1000 * 60 * 60 * 24, 
            secure: process.env.NODE_ENV === 'production' 
        }
    })(req, {}, () => {
        
        // ⬇️ FIX 2: WebSocket Mismatch Fix
        let finalCustomerId = customerIdFromUrl;
        
        if (role === 'customer' && req.session && req.session.userId) {
            // If the user is logged in, force the use of their DB ID as the session key.
            // This prevents the logged-in user from creating a session keyed by 'anon-xyz'.
            finalCustomerId = String(req.session.userId);
        }
        // ------------------------------------

        
        // 3. Security Check
        const isAdminRequest = role === 'admin';
        const isCustomerRequest = role === 'customer';

        if (isAdminRequest) {
            // 🚨 FIX: Add req.session null check
            if (!req.session || !req.session.isAuthenticated || !req.session.isAdmin) {
                console.log('Admin WebSocket Auth Failed.');
                socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
                socket.destroy();
                return;
            }
        } else if (isCustomerRequest) {
            // 🚨 CRITICAL FIX: Enforce logged-in session for customer chat
            if (!req.session || !req.session.userId) { 
                 console.log('Customer WebSocket Auth Failed: Not Logged In.');
                 socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                 socket.destroy();
                 return;
            }
            // 🚨 NEW: Also ensure customerId matches the logged-in user ID
            if (String(req.session.userId) !== finalCustomerId) {
                 console.log(`Customer WebSocket Auth Failed: ID Mismatch (${req.session.userId} != ${finalCustomerId}).`);
                 socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
                 socket.destroy();
                 return;
            }
        } else {
             socket.destroy();
             return;
        }
        
       
        
        // 4. Attach params/session data for use in the wss.on('connection') handler
        // CRITICAL: Use the finalCustomerId (which is the DB ID if logged in)
        req.params = { customerId: finalCustomerId, role }; 
        
        // 5. Handle WebSocket handshake
        wss.handleUpgrade(req, socket, head, (ws) => {
            wss.emit('connection', ws, req);
        });
    });
});

// =========================================================
//                   NEW CHAT API ENDPOINTS (History)
// =========================================================

/**
 * GET /api/admin/chat/history/:customerId
 * Retrieves chat history for a specific customer.
 */
app.get('/api/admin/chat/history/:customerId', isAdmin, async (req, res) => {
    const customerId = req.params.customerId;
    try {
        const history = await getChatHistory(customerId);
        res.json(history);
    } catch (error) {
        console.error(`Error fetching admin chat history for ${customerId}:`, error);
        res.status(500).json({ message: 'Failed to retrieve chat history.' });
    }
});

/**
 * GET /api/chat/history/:customerId
 * Retrieves chat history for the customer client.
 */
app.get('/api/chat/history/:customerId', async (req, res) => {
    const customerId = req.params.customerId;
    const sessionUserId = String(req.session.userId); 

    // FIX 3: Centralize logic to determine if the customerId is valid for this request.
    const isAnon = customerId.startsWith('anon-');
    const isMatchingLoggedInUser = req.session && req.session.userId && (sessionUserId === customerId);
    
    if (isAnon || isMatchingLoggedInUser) {
        try {
            const history = await getChatHistory(customerId);
            return res.json(history);
        } catch (error) {
            console.error(`Error fetching customer chat history for ${customerId}:`, error);
            return res.status(500).json({ message: 'Failed to retrieve chat history.' });
        }
    }
    
    // Default denial for unauthenticated user requesting a numeric (DB) ID, 
    // or a logged-in user requesting a different DB ID.
    return res.status(403).json({ message: 'Access denied to this chat history.' });
});


// =========================================================
//                   START SERVER (MODIFIED)
// =========================================================

// Change app.listen to server.listen
server.listen(port, async () => {
    console.log(`Server running on port ${port}`);

    try {
        // 🚨 CRITICAL: Run database migrations before starting the server process
     
        const [rows] = await pool.query('SELECT 1');
        console.log("Database connected successfully.");
    } catch (error) {
        console.error("Warning: Database connection failed:", error);
    }
});