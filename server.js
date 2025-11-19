// server.js (Final Production Build with Routing Logic)

// 1. Load environment variables first
require('dotenv').config(); 

const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt'); 
const session = require('express-session'); 
const db = require('./db');
const crypto = require('crypto');
const cors = require('cors');

// 🚨 UPDATE: Import findAllUsers for the new customer listing endpoint
const { pool, findUserById, findAllUsers, saveContactMessage, getAllContactMessages,updateUserProfile, findUserOrders, findUserByEmail, updatePassword, updateUserStatus} = require('./db'); 
const passwordResetCache = {}; 

/**
 * Helper function to generate secure, temporary tokens (vtoken).
 * @param {number} length - The length of the token in bytes.
 * @returns {string} The hexadecimal token.
 */
function generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}
const verificationCache = {};
const otpCache = {};
const loginAttempts = {}; 
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 60 * 60 * 1000; // 1 hour
const app = express();
const port = process.env.PORT || 3000; 
const saltRounds = 10; 
app.use(cors()); // Enable CORS for all origins
// --- ADMIN & AUTH CONFIGURATION (from .env) ---
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_FULL_NAME = process.env.ADMIN_FULL_NAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const ADMIN_WHATSAPP = process.env.ADMIN_WHATSAPP;

// --- Multer and Nodemailer setup ---
const UPLOAD_DIR = path.join(__dirname, 'public/images/products');
const PROFILE_UPLOAD_DIR = path.join(__dirname, 'public/images/profiles');
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



const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false, // TLS
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: true
    },

 waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

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
    secret: process.env.SESSION_SECRET || 'a_secure_emergency_fallback_secret', 
    resave: false,
    saveUninitialized: false,
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
                req.session.userId = 'admin_env'; 
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
// admin.html <script> tag (Global Scope)
let salesChartInstance = null;


// --- Sales Data Fetching Function ---
async function fetchAndRenderSalesChart() {
    try {
        // Corrected URL: /api/dashboard/monthly-sales
        const response = await fetch(`${API_BASE_URL}/dashboard/monthly-sales`); 
        
        if (!response.ok) {
            console.error('Failed to fetch sales data:', response.statusText);
            throw new Error('Failed to fetch sales data.');
        }
        
        const data = await response.json();

        // Check for empty data and display a message
        if (data.length === 0) {
            document.getElementById('salesChartContainer').innerHTML = '<p style="text-align: center; color: var(--color-text-subtle);">No completed orders yet to display sales trend.</p>';
            return;
        }

        const labels = data.map(item => item.month); 
        // 🚨 CRITICAL FIX: Ensure mapping uses 'revenue' (from server) and is parsed as float
        const chartData = data.map(item => parseFloat(item.revenue)); 
        
        // 🚀 CALL TO RENDERER: Invoke the rendering function with the processed data
        renderSalesChart(labels, chartData); 

    } catch (error) {
        console.error('Chart data fetch failed:', error);
        // Display an error message if the container exists
        const container = document.getElementById('salesChartContainer');
        if (container) {
             container.innerHTML = '<p style="text-align: center; color: red;">Error loading sales trend data.</p>';
        }
    }
}

// admin.html <script> tag

// --- Sales Chart Rendering Function ---
function renderSalesChart(labels, data) {
    // Destroy existing chart instance if it exists
    if (salesChartInstance) {
        salesChartInstance.destroy();
    }
    
    const ctxElement = document.getElementById('salesChart');
    if (!ctxElement) {
        console.error('Canvas element with ID "salesChart" not found.');
        return;
    }
    
    const ctx = ctxElement.getContext('2d');
    
    salesChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Monthly Sales ($)',
                data: data,
                borderColor: 'rgb(194, 24, 91)', 
                backgroundColor: 'rgba(233, 30, 99, 0.2)', 
                tension: 0.3,
                fill: true,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    // 💰 FIX 1: Set suggested minimum and step size to improve visibility
                    suggestedMin: 0, // Ensure it always starts at 0
                    // Note: If you have sales > $1000, you might want stepSize: 500
                    ticks: {
                        stepSize: 100, // Forces steps of 100 (0, 100, 200, 300...)
                        callback: function(value, index, values) {
                            return '$' + value; // Format the tick label
                        }
                    },
                    title: {
                        display: true,
                        text: 'Sales Amount ($)'
                    }
                },
                x: {
                    // 📅 FIX 2: Format the month labels for better readability
                    ticks: {
                        callback: function(value, index) {
                            // Converts 'YYYY-MM' format to readable 'Month YYYY'
                            const date = new Date(labels[index] + '-01'); // Append -01 for valid date parsing
                            return date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
                        }
                    },
                    title: {
                        display: true,
                        text: 'Month'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.parsed.y !== null) {
                                label += new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(context.parsed.y);
                            }
                            return label;
                        }
                    }
                }
            }
        }
    });
}
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
        res.status(500).json({ message: 'Failed to upload product due to server error.' });
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
        res.status(500).json({ message: 'Failed to update order status due to a server error.' });
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
    const orderTotal = total; // Rename total to orderTotal for clarity

    const numericTotal = parseFloat(total);
    if (!name || !phone || !email || !location || !items || items.length === 0) {
        return res.status(400).json({ message: 'Missing required delivery or item information.' });
    }

    // --- Start Transaction ---
    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();

        // 1. INSERT INTO orders (CLEANED SQL STRING)
        // Note: The variable orderSql is defined but not used. The SQL is executed directly below.
        // We ensure the SQL string passed to execute is clean.
        const [orderResult] = await connection.execute(
            `
            INSERT INTO orders 
            (user_id, customer_name, customer_phone, customer_email, delivery_location, total, status) 
            VALUES (?, ?, ?, ?, ?, ?, 'Pending')
            `,
            [
                userId, 
                customerName, 
                customerPhone, 
                customerEmail, 
                deliveryLocation, 
                orderTotal
            ]
        );
        const orderId = orderResult.insertId;

        // 2. INSERT INTO order_items (CLEANED SQL STRING)
        // THIS WAS THE CAUSE OF THE ERROR. It has been completely retyped.
        const itemSql = `
            INSERT INTO order_items 
            (order_id, product_name, unit_price, quantity) 
            VALUES (?, ?, ?, ?)
        `;
        
        for (const item of items) {
            
            // Minor correction: Your comment suggests using 'stock_quantity' instead of 'stock'.
            // I'm assuming 'stock' is the current correct column name to keep it running.
            // If the column name is 'stock_quantity', update 'stock' to 'stock_quantity' here.
            await connection.execute('UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?', [item.quantity, item.id, item.quantity]);
            
            // Insert order item using the cleaned SQL
            await connection.execute(
                itemSql, 
                [
                    orderId, 
                    item.name, 
                    item.price, 
                    item.quantity
                ]
            );
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
            <p>Thank you for your order! We have successfully received it. You will be contacted shortly on ${phone} or ${email} to confirm delivery.</p>
            <p><strong>Total:</strong> $${numericTotal.toFixed(2)}</p>
            <h3>Your Items:</h3>
            <ul>${orderDetailsHtml}</ul>
        `;

        await Promise.all([
            transporter.sendMail({ from: ADMIN_EMAIL, to: email, subject: `Order #${orderId} Received`, html: userConfirmationBody }),
            transporter.sendMail({ from: ADMIN_EMAIL, to: ADMIN_EMAIL, subject: `NEW ORDER ALERT: #${orderId}`, html: adminEmailBody })
        ]);

        console.log(`Order #${orderId} processed, cart cleared, stock updated.`);
        res.status(201).json({ 
            message: 'Order placed successfully. Confirmation email sent.', 
            orderId: orderId 
        });

    } catch (error) {
        await connection.rollback();
        console.error('Order processing failed:', error);
        // Important: Use the specific error message from the database if available, 
        // otherwise default to a generic message.
        const errorMessage = error.sqlMessage || 'Order failed to process due to a server or database error.';
        res.status(500).json({ 
            message: errorMessage
        });
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
            // It's possible for a valid order to have no items (though unlikely/bad data)
            return res.json([]); 
        }
        res.json(rows);
    } catch (error) {
        console.error('API Error fetching order items:', error);
        res.status(500).json({ message: 'Failed to retrieve order items.' });
    }
});

app.put('/api/orders/:orderId', isAdmin, async (req, res) => {
    const orderId = req.params.orderId;
    // Assuming the client sends the new status in the request body, e.g., { status: 'Completed' }
    const { status } = req.body; 

    // 🚨 CRITICAL: Validation check that causes the 400 error if the status field is missing
    if (!status) {
        return res.status(400).json({ message: 'Missing status field in request body.' });
    }

    // You should probably check if the status is a valid value here too (e.g., 'Completed', 'Canceled', 'Processing')

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
        res.status(500).json({ message: 'Failed to update order status.' });
    }
});

// server.js (Add this new route)

/**
 * GET /api/user/orders
 * Fetches all orders for the currently logged-in user from the orders table.
 * Requires: checkAuth middleware for user session validation.
 */
app.get('/api/user/orders', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId; // Get the user ID from the session
        
        // 1. Call the database function to fetch orders by user ID
        const orders = await findUserOrders(userId); 

        // 2. Respond with the array of orders
        res.status(200).json(orders);
    } catch (error) {
        console.error('Error fetching user orders:', error);
        res.status(500).json({ message: 'Internal server error while retrieving orders.' });
    }
});

app.post('/api/admin/messages/reply', isAdmin, async (req, res) => {
    // Client-side payload: { to, from, subject, content }
    const { to, from, subject, content } = req.body;
    
    // 2. Simple validation
    if (!to || !subject || !content) {
        return res.status(400).json({ message: 'Missing required fields: recipient (to), subject, or content.' });
    }

    try {
        // 3. Construct the email message
        const mailOptions = {
            // Ensure the 'from' field uses the authenticated admin email from .env
            from: process.env.EMAIL_USER, 
            to: to,
            subject: subject,
            text: content,
            // Optional: Use HTML for richer text formatting if needed
            // html: `<p>${content.replace(/\n/g, '<br>')}</p>`, 
        };

        await transporter.sendMail(mailOptions);

        
        // Success response
        res.json({ message: 'Reply sent successfully!' });

    } catch (error) {
        console.error('Nodemailer Error:', error.message);
        // Respond with a 500 status on failure
        res.status(500).json({ 
            message: 'Failed to send reply email due to server configuration or Nodemailer error.', 
            error: error.message 
        });
    }
});
// Route to handle product updates (PUT request)
app.put('/api/products/:id', isAdmin, upload.single('productImage'), async (req, res) => {
    // Multer (upload.single) runs here, successfully populating req.body and req.file.
    
    const productId = req.params.id;

    // 1. Determine the image URL for the database
    let imageUrl = req.body.image_url_current; // Fallback to the existing URL (sent via hidden field)
    
    // Check if a new file was uploaded (req.file exists)
    if (req.file) {
        // Construct the public URL path: 
        // UPLOAD_DIR is 'public/images/products', so the URL starts at '/images/products'
        imageUrl = `/images/products/${req.file.filename}`;
    }

    // 2. Construct the data object for the database update
    const updatedData = {
        // req.body is now populated by Multer
        name: req.body.name,
        description: req.body.description,
        // Ensure numeric types are correctly parsed
        price: parseFloat(req.body.price), 
        stock: parseInt(req.body.stock, 10), 
        category: req.body.category,
        image_url: imageUrl, // Use the determined URL
    };
    
    // 3. Perform the database update
    try {
        const affectedRows = await db.updateProduct(productId, updatedData); 

        if (affectedRows > 0) { 
            // Success: one row was updated
            res.status(200).json({ 
                message: `Product ${productId} updated successfully!`
            });
        } else {
            // Failure: product ID not found or no changes submitted
            res.status(404).json({ 
                message: `Product with ID ${productId} not found or no new changes were provided.`,
            });
        }
    } catch (error) {
        // Handle any database or server-side execution errors
        console.error("Product Update Error:", error);
        res.status(500).json({ 
            message: 'Internal server error during product update.',
            details: error.message
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
        res.status(500).json({ message: 'Failed to delete product due to server error.' });
    }
});
// sending contact messages to admin dashboard
app.post('/api/contact', async (req, res) => {
    const { name, email, message } = req.body;

    // Basic validation
    if (!name || !email || !message) {
        // Returns a proper JSON error response
        return res.status(400).json({ 
            message: 'All fields are required.' 
        });
    }

    try {
        // Use the new function from db.js to save the message
        await saveContactMessage(name, email, message);

        // Success response (sent back as JSON)
        return res.status(200).json({ 
            message: 'Message successfully sent to admin dashboard.' 
        });

    } catch (error) {
        console.error('Database insertion error for contact form:', error);
        // Returns a proper JSON error response
        return res.status(500).json({ 
            message: 'Internal server error while saving message. Please try again later.' 
        });
    }
});
app.get('/api/admin/messages', isAuthenticated, isAdmin, async (req, res) => {
    try {
        // Fetch data using the function from db.js
        const messages = await getAllContactMessages();
        
        // Success: send the array of messages as JSON
        return res.status(200).json(messages);

    } catch (error) {
        console.error('Error in GET /api/admin/messages:', error);
        // Server Error: Returns a proper JSON error response
        return res.status(500).json({ 
            message: 'Failed to retrieve messages from the database due to a server error.' 
        });
    }
});



// Route to handle password reset request (Step 1: Send Email)


app.post('/api/request-otp', async (req, res) => {
    const { email } = req.body;
    
    // 1. Check if user exists (Requires db.findUserByEmail)
    const user = await db.findUserByEmail(email); 

    if (!user) {
        // Secure response: always return success to prevent leaking account existence
        return res.status(200).json({ message: 'If the account exists, an OTP has been sent to your email.' });
    }

    try {
        // 2. Generate OTP (6-digit number) and 5-minute expiry
        const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
        const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes in milliseconds

        // 3. Store OTP in memory
        otpCache[email] = { otp, expiry };
        
        // 4. Send OTP via email
        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Lollys Collection Password Reset OTP',
            text: `Your One-Time Password (OTP) for password reset is: ${otp}\n\n`
                + `This OTP is valid for 5 minutes. Please enter it on the website to proceed.\n`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'OTP sent successfully. Please check your email and submit the OTP.' });

    } catch (error) {
        console.error('OTP Request Error:', error);
        res.status(500).json({ message: 'Error processing OTP request.' });
    }
});

// server.js (Requires 'crypto' to be imported at the top)

app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    const cacheEntry = otpCache[email];
    
    // 1. Check if the entry exists, OTP matches, and has not expired
    if (!cacheEntry || cacheEntry.otp !== otp || Date.now() > cacheEntry.expiry) {
        // Clear the entry if it's expired or wrong
        delete otpCache[email];
        return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }
    
    // 2. OTP is valid. Generate a temporary, single-use verification token.
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 10 * 60 * 1000; // Allow 10 minutes to finish the reset

    // 3. Store the verification token linked to the user's email
    verificationCache[verificationToken] = { email, expiry };
    
    // 4. Clear the OTP cache entry immediately (OTP is single use)
    delete otpCache[email];

    // 5. Send the verification token back to the client
    res.status(200).json({ 
        message: 'OTP verified successfully. Proceed to password reset.',
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
        res.status(500).json({ message: 'Internal server error while resetting password.' });
    }
});
app.listen(port, async () => {
    console.log(`Server running on port ${port}`);

    try {
        // Try simple DB connection instead of initializing tables
        const [rows] = await pool.query('SELECT 1');
        console.log("Database connected successfully.");
    } catch (error) {
        console.error("Warning: Database connection failed:", error);
    }
});