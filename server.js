// server.js (Updated to handle sent_to_id and received_from_id)

// 1. Load environment variables first
require('dotenv').config(); 

const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
// 🚨 RESEND INTEGRATION
const { Resend } = require('resend'); 
const bcrypt = require('bcrypt'); 
const session = require('express-session'); 
const MySQLStore = require('express-mysql-session')(session);
const db = require('./db');
const crypto = require('crypto');
const cors = require('cors');
// 🚨 NEW: WebSocket Dependencies
const http = require('http'); // Native Node.js HTTP module
const WebSocket = require('ws'); // ws library for WebSockets

// Import DB functions
// NOTE: saveChatMessage signature must now match the updated function in db.js
const { pool, findUserById, findAllUsers, saveContactMessage, getAllContactMessages, updateUserProfile, findUserOrders, findUserByEmail, updatePassword, updateUserStatus, saveChatMessage, getChatHistory } = require('./db'); 

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
const sessionStore = new MySQLStore(sessionStoreOptions);
const resend = new Resend(process.env.RESEND_API_KEY);

const verificationCache = {};
const otpCache = {};
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
app.use(express.static(path.join(__dirname, 'public'))); 
app.use(express.static(__dirname)); 
app.use('public/images/products', express.static(path.join(__dirname, 'products')));
app.use('public/images/profiles', express.static(path.join(__dirname, 'profiles')));
app.use('/images/products', express.static(UPLOAD_DIR));
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
    if (req.session.isAuthenticated) {
        return next();
    }
    if (req.originalUrl.startsWith('/api/')) {
        // If API call requires auth but not logged in, return 401
        return res.status(401).json({ message: 'Authentication required.' });
    }
    res.redirect('/auth');
}

function isAdmin(req, res, next) {
    if (req.session.isAuthenticated && req.session.isAdmin) {
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
    if (req.session.userId) {
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
//                   FRONTEND ROUTES (Protected)
// =========================================================

/**
 * 🚨 ROUTING LOGIC: Landing Page (/)
 */
app.get('/', (req, res) => { 
    if (!req.session.isAuthenticated) {
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
    if (req.session.isAuthenticated) {
        return res.redirect('/'); 
    }
    res.sendFile(path.join(__dirname, 'auth.html'));
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
//                   AUTHENTICATION API ROUTES (MODIFIED)
// =========================================================

app.post('/api/signup', async (req, res) => {
    const { full_name, email, password } = req.body;
    if (!full_name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const password_hash = await bcrypt.hash(password, saltRounds);
        // NOTE: is_active column defaults to TRUE in the DB schema, no need to specify here
        await pool.execute(
            'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
            [full_name, email, password_hash]
        );
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
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
        const [users] = await pool.execute(
            'SELECT id, full_name, password_hash, is_admin, is_active FROM users WHERE email = ?',
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
        
        // 4. Successful Login: Clear attempts and set session
        delete loginAttempts[attemptKey];
        req.session.isAuthenticated = true;
        req.session.isAdmin = user.is_admin;
        req.session.userId = user.id;
        req.session.fullName = user.full_name;
        
        res.json({ 
            message: 'Login successful.', 
            user: { id: user.id, full_name: user.full_name, is_admin: user.is_admin } 
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
        const [users] = await pool.execute('SELECT id, full_name, password_hash FROM users WHERE email = ? AND is_admin = TRUE', [email]);
        const user = users[0];

        if (user) {
            const match = await bcrypt.compare(password, user.password_hash);
            if (match) {
                req.session.isAuthenticated = true;
                req.session.isAdmin = true;
                req.session.userId = user.id;
                req.session.fullName = user.full_name;
                return res.json({ 
                    message: 'Admin login successful.', 
                    user: { full_name: user.full_name, is_admin: true } 
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
    if (req.session.userId) {
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
        isAdmin: true
    });
});
// ------------------------------------------------------------------
// --- NEW USER PROFILE API ENDPOINT (For Autofill) ---
// ------------------------------------------------------------------

/**
 * Retrieves the full_name and email of the logged-in user for autofilling the checkout form.
 */
app.get('/api/user/profile', isAuthenticated, async (req, res) => {
    const userId = req.session.userId; 

    try {
        // Use the new function from db.js
        const userProfile = await findUserById(userId); 

        if (userProfile) {
            // Returns { name, email }
            return res.json(userProfile);
        } else {
            // Safety check: User is logged in but profile not found in DB (unlikely)
            return res.status(404).json({ 
                message: 'User profile not found in database. Cannot autofill.' 
            });
        }
    } catch (error) {
        console.error('Error fetching user profile for autofill:', error);
        return res.status(500).json({ 
            message: 'Server error fetching user data for autofill.' 
        });
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
// server.js

// =========================================================
//                   USER PROFILE API ROUTES (NEW/MODIFIED)
// =========================================================

/**
 * GET /api/user/profile
 * Retrieves full user profile information, including new fields.
 */
app.get('/api/user/profile', isAuthenticated, async (req, res) => {
    const userId = req.session.userId; 

    try {
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
            "SELECT COUNT(id) AS pendingCount FROM orders WHERE status = 'Pending'"
        );
        
        // 5. Count Completed Orders
        const [completedOrders] = await pool.query(
            "SELECT COUNT(id) AS completedCount FROM orders WHERE status = 'Completed'"
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
        const sql = `
    SELECT c.product_id AS id, p.name, c.unit_price AS price, 
             c.quantity, p.image_url, p.stock 
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
    const { productId, quantity } = req.body;
    
    if (!productId || !quantity || quantity < 1) {
        return res.status(400).json({ message: 'Invalid product ID or quantity.' });
    }

    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();
        
        const [productRows] = await connection.execute('SELECT name, price, stock FROM products WHERE id = ?', [productId]);
        if (productRows.length === 0) {
            return res.status(404).json({ message: 'Product not found.' });
        }
        const product = productRows[0];
        
        const [cartRows] = await connection.execute('SELECT quantity FROM cart WHERE user_id = ? AND product_id = ?', [userId, productId]);
        
        const currentQuantity = cartRows.length > 0 ? cartRows[0].quantity : 0;
        const newQuantity = currentQuantity + quantity;

        if (newQuantity > product.stock) {
            return res.status(400).json({ message: `Cannot add that quantity. Only ${product.stock_quantity} of ${product.name} left.` });
        }

        if (cartRows.length > 0) {
            await connection.execute('UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?', [newQuantity, userId, productId]);
        } else {
            await connection.execute(
                'INSERT INTO cart (user_id, product_id, product_name, unit_price, quantity) VALUES (?, ?, ?, ?, ?)',
                [userId, productId, product.name, product.price, newQuantity]
            );
        }

        await connection.commit();
        res.status(200).json({ message: `${product.name} quantity updated to ${newQuantity}.` });

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
    const userId = req.session.userId;
    const { name, phone, email, location, items, notificationMethod, total } = req.body;
    
    const customerName = name; 
    const customerPhone = phone;
    const customerEmail = email;
    const deliveryLocation = location;
    const orderTotal = total;

    const numericTotal = parseFloat(total);
    if (!name || !phone || !email || !location || !items || items.length === 0) {
        return res.status(400).json({ message: 'Missing required delivery or item information.' });
    }

    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();

        const [orderResult] = await connection.execute(
            `INSERT INTO orders (user_id, customer_name, customer_phone, customer_email, delivery_location, total, status) 
             VALUES (?, ?, ?, ?, ?, ?, 'Pending')`,
            [userId, customerName, customerPhone, customerEmail, deliveryLocation, orderTotal]
        );
        const orderId = orderResult.insertId;

        const itemSql = `INSERT INTO order_items (order_id, product_name, unit_price, quantity) VALUES (?, ?, ?, ?)`;
        
        for (const item of items) {
            await connection.execute('UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?', [item.quantity, item.id, item.quantity]);
            await connection.execute(itemSql, [orderId, item.name, item.price, item.quantity]);
        }
        
        await connection.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

        await connection.commit();

        const orderDetailsHtml = items.map(item => 
            `<li>${item.name} (x${item.quantity}) - $${(item.price * item.quantity).toFixed(2)}</li>`
        ).join('');
        
        const adminEmailBody = `
            <h2>🚨 NEW ORDER #${orderId} Received!</h2>
            <p><strong>Customer:</strong> ${name}</p>
            <p><strong>Phone:</strong> ${phone}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Location:</strong> ${location}</p>
           <p><strong>Total:</strong> $${numericTotal.toFixed(2)}</p>
            <h3>Items Ordered:</h3>
            <ul>${orderDetailsHtml}</ul>
            <p>Preferred Contact: ${notificationMethod}</p>
        `;
        
        const userConfirmationBody = `
            <h2>🛍️ Order #${orderId} Confirmation - Lolly's Collection</h2>
            <p>Hello ${name},</p>
            <p>Thank V you for your order! We have successfully received it. You will be contacted shortly on ${phone} or ${email} to confirm delivery.</p>
            <p><strong>Total:</strong> $${numericTotal.toFixed(2)}</p>
            <h3>Your Items:</h3>
            <ul>${orderDetailsHtml}</ul>
        `;

        // 🚨 RESEND INTEGRATION FOR ORDERS
        const senderEmail = process.env.EMAIL_FROM || 'onboarding@resend.dev';

        await Promise.all([
            resend.emails.send({
                from: `Lolly's Collection <${senderEmail}>`,
                to: email,
                subject: `Order #${orderId} Received`,
                html: userConfirmationBody
            }),
            resend.emails.send({
                from: `Lolly's Collection Admin <${senderEmail}>`,
                to: process.env.ADMIN_EMAIL,
                subject: `NEW ORDER ALERT: #${orderId}`,
                html: adminEmailBody
            })
        ]);

        console.log(`Order #${orderId} processed, cart cleared, stock updated, emails sent via Resend.`);
        res.status(201).json({ 
            message: 'Order placed successfully. Confirmation email sent.', 
            orderId: orderId 
        });

    } catch (error) {
        await connection.rollback();
        console.error('Order processing failed:', error);
        const errorMessage = error.sqlMessage || 'Order failed to process , please try again later.';
        res.status(500).json({ message: errorMessage });
    } finally {
        connection.release();
    }
});

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
        const orderId = req.params.orderId;
        const [rows] = await pool.query(
            `SELECT product_name, unit_price, quantity 
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

// Route to handle password reset request (Step 1: Send Email)


app.post('/api/request-otp', async (req, res) => {
    const { email } = req.body;
    
    // Normalize
    const normalizedEmail = email.toLowerCase().trim();

    const user = await db.findUserByEmail(email); 
    if (!user) {
        return res.status(200).json({ message: 'If the account exists, an OTP has been sent to your email.' });
    }

    try {
        const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
        const expiry = Date.now() + 5 * 60 * 1000; 

        // Store with normalized key
        otpCache[normalizedEmail] = { otp, expiry };
        
        // 🚨 RESEND INTEGRATION FOR OTP
        const senderEmail = process.env.EMAIL_FROM || 'onboarding@resend.dev';

        // ⬇️ FIX 1: TEMPORARILY OVERRIDE RECIPIENT FOR RESEND TESTING
        const testingRecipient = 'oyoookoth42@gmail.com'; 
        // ------------------------------------------------------------------

        const { error } = await resend.emails.send({
            from: `Lolly's Security <${senderEmail}>`,
            to: testingRecipient, // Use the verified testing email
            subject: 'Lollys Collection Password Reset OTP',
            text: `Your One-Time Password (OTP) for password reset is: ${otp}\n\nThis OTP is valid for 5 minutes. Please enter it on the website to proceed.`
        });

        if (error) {
            console.error('Resend OTP Error:', error);
            // It's crucial not to send the real error status to the client, 
            // especially if the account doesn't exist (timing attack mitigation).
            // However, since the error is a 403 due to the recipient, log it.
        }

        res.status(200).json({ message: 'OTP sent successfully. Please check your email and submit the OTP.' });

    } catch (error) {
        console.error('OTP Request Error:', error);
        res.status(500).json({ message: 'Error processing OTP request.' });
    }
});

// 🚨 VERIFY OTP - Debugging & Normalization
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    // 1. Basic Validation
    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and OTP are required.' });
    }

    // 2. Normalize Inputs
    const normalizedEmail = email.toLowerCase().trim();
    const inputOtp = String(otp).trim(); 

    // 3. Retrieve from Cache
    const cacheEntry = otpCache[normalizedEmail];
    
    // --- DEBUGGING LOGS ---
    console.log(`DEBUG VERIFY: Checking email: [${normalizedEmail}]`);
    console.log(`DEBUG VERIFY: Input OTP: [${inputOtp}]`);
    console.log(`DEBUG VERIFY: Stored Cache:`, cacheEntry);
    
    // 4. Check Logic
    if (!cacheEntry) {
        console.log('DEBUG FAIL: No cache entry found.');
        return res.status(400).json({ message: 'Invalid or expired OTP (Session not found).' });
    }

    if (cacheEntry.otp !== inputOtp) {
        console.log(`DEBUG FAIL: OTP Mismatch.`);
        delete otpCache[normalizedEmail]; 
        return res.status(400).json({ message: 'Invalid OTP provided.' });
    }

    if (Date.now() > cacheEntry.expiry) {
        console.log('DEBUG FAIL: OTP Expired.');
        delete otpCache[normalizedEmail];
        return res.status(400).json({ message: 'OTP has expired.' });
    }
    
    // 5. Success
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 10 * 60 * 1000; 

    verificationCache[verificationToken] = { email: normalizedEmail, expiry };
    delete otpCache[normalizedEmail];

    res.status(200).json({ 
        message: 'OTP verified successfully.',
        verificationToken: verificationToken
    });
});
// Route to handle password reset submission (Step 2: Update Password)
app.post('/api/reset-password', async (req, res) => {
    // 1. Accept the verification token (vtoken), email, and new password
    const { verificationToken, email, newPassword } = req.body; 

    // 2. Validate input and password strength
    if (!verificationToken || !email || !newPassword) {
        return res.status(400).json({ message: 'Missing required reset information.' });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ message: 'New password must be at least 8 characters long.' });
    }

    // 3. Check the verification cache for the token and validate its integrity
    const verificationEntry = verificationCache[verificationToken];

    if (!verificationEntry) {
        // Token doesn't exist (never issued, already used, or expired)
        return res.status(400).json({ message: 'Password reset session is invalid or has expired. Please request a new OTP.' });
    }

    // Validate Token Expiration and Email Match
    if (Date.now() > verificationEntry.expiry || verificationEntry.email !== email) {
        // Clear the invalid or expired entry
        delete verificationCache[verificationToken];
        return res.status(400).json({ message: 'Password reset session has expired or is invalid. Please request a new OTP.' });
    }

    try {
        // 4. Find the user by email (ensures account still exists)
        const user = await db.findUserByEmail(email);

        if (!user) {
            // Account may have been deleted between OTP verification and reset.
            // Clear the token and notify the user.
            delete verificationCache[verificationToken]; 
            return res.status(400).json({ message: 'Password reset session is invalid or has expired. Please request a new OTP.' });
        }
        
        // 5. Hash the new password securely
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        
        // 6. Update password in the database
        const updated = await db.updatePassword(user.id, hashedPassword);

        // 7. CRUCIAL: Clear the verification token immediately after successful use
        delete verificationCache[verificationToken]; 

        if (updated) {
            // 8. Send success response
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
//                   REAL-TIME CHAT SETUP
// =========================================================

// Global Map to hold active WebSocket connections for Admin and Customer
// Key: customerId (string) -> Value: { admin: WebSocket | null, customer: WebSocket | null }
const chatSessions = new Map(); 

// Create a WebSocket Server
const wss = new WebSocket.Server({ noServer: true });

// Function to handle message saving and relaying
async function handleChatMessage(ws, message, senderRole, customerId) {
    if (!message || !customerId) return;
    
    // Determine the sender/recipient IDs based on the role and session data
    const sessionData = chatSessions.get(customerId);
    if (!sessionData) return console.log(`Session data missing for customer ${customerId}`);

    // The user's ID is the session key (customerId). The admin ID is the constant.
    const senderId = (senderRole === 'admin') ? ADMIN_CHAT_ID : customerId;
    const recipientId = (senderRole === 'admin') ? customerId : ADMIN_CHAT_ID;
    
    const payload = {
        sender: senderRole,
        message: message
    };
    
    // 1. Save to Database (using the updated function signature)
    try {
        await saveChatMessage(customerId, senderRole, senderId, recipientId, message);
    } catch (dbError) {
        console.error(`DB Save Error for ${customerId}:`, dbError);
        // Optionally send a notification back to the sender that the message failed to save
    }

    // 2. Relay the message to the other participant in the session
    const target = (senderRole === 'admin' ? sessionData.customer : sessionData.admin);
    
    if (target && target.readyState === WebSocket.OPEN) {
        target.send(JSON.stringify(payload));
    } else {
        console.log(`Relay failed: ${senderRole}'s target is not open or undefined.`);
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
            const parsed = JSON.parse(data);
            const message = parsed.message ? String(parsed.message).trim() : null;
            
            if (message && message.length > 0) {
                // Pass the message and the role of the sender
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
        
        if (role === 'customer' && req.session.userId) {
            // If the user is logged in, force the use of their DB ID as the session key.
            // This prevents the logged-in user from creating a session keyed by 'anon-xyz'.
            finalCustomerId = String(req.session.userId);
        }
        // ------------------------------------

        // 3. Security Check
        const isAdminRequest = role === 'admin';
        const isCustomerRequest = role === 'customer';

        if (isAdminRequest) {
            if (!req.session.isAuthenticated || !req.session.isAdmin) {
                console.log('Admin WebSocket Auth Failed.');
                socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
                socket.destroy();
                return;
            }
        } else if (isCustomerRequest) {
            // Note: Customer chat doesn't strictly need login. The ID is for tracking history.
            if (!finalCustomerId) { // Use finalCustomerId for validation
                 console.log('Customer WebSocket Missing ID.');
                 socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
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
//                   NEW CHAT API ENDPOINTS (History)
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
    const isMatchingLoggedInUser = req.session.userId && (sessionUserId === customerId);
    
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
//                   START SERVER (MODIFIED)
// =========================================================

// Change app.listen to server.listen
server.listen(port, async () => {
    console.log(`Server running on port ${port}`);

    try {
        // Try simple DB connection instead of initializing tables
        const [rows] = await pool.query('SELECT 1');
        console.log("Database connected successfully.");
    } catch (error) {
        console.error("Warning: Database connection failed:", error);
    }
});