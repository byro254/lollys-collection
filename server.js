// server.js (Final Production Build with Resend & Upload Fixes)

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

// Import DB functions
const { pool, findUserById, findAllUsers, saveContactMessage, getAllContactMessages, updateUserProfile, findUserOrders, findUserByEmail, updatePassword, updateUserStatus} = require('./db'); 

const passwordResetCache = {}; 

// Session Store Options
const sessionStoreOptions = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
};

const sessionStore = new MySQLStore(sessionStoreOptions);

// 🚨 INITIALIZE RESEND
const resend = new Resend(process.env.RESEND_API_KEY);

const verificationCache = {};
const otpCache = {};
const loginAttempts = {}; 
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 60 * 60 * 1000; // 1 hour
const app = express();

app.set('trust proxy', 1);
const port = process.env.PORT || 3000; 
const saltRounds = 10; 

app.use(cors({
    origin: true, 
    credentials: true 
}));

// --- ADMIN & AUTH CONFIGURATION ---
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_FULL_NAME = process.env.ADMIN_FULL_NAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

// --- Multer setup (FILE UPLOAD FIX) ---
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

// =========================================================
//                   FRONTEND ROUTES 
// =========================================================

app.get('/', (req, res) => { 
    if (!req.session.isAuthenticated) {
        return res.redirect('/auth'); 
    }
    if (req.session.isAdmin) {
        return res.redirect('/admin.html');
    }
    res.sendFile(path.join(__dirname, 'index.html')); 
});

app.get('/auth', (req, res) => {
    if (req.session.isAuthenticated) {
        return res.redirect('/'); 
    }
    res.sendFile(path.join(__dirname, 'auth.html'));
});

app.get('/admin.html', isAdmin, (req, res) => { 
    res.sendFile(path.join(__dirname, 'admin.html')); 
});

app.get('/products', (req, res) => { res.sendFile(path.join(__dirname, 'products.html')); });
app.get('/cart', (req, res) => { res.sendFile(path.join(__dirname, 'cart.html')); });
app.get('/about', (req, res) => { res.sendFile(path.join(__dirname, 'about.html')); });
app.get('/contact', (req, res) => { res.sendFile(path.join(__dirname, 'contact.html')); });


// =========================================================
//                   AUTHENTICATION API ROUTES
// =========================================================

app.post('/api/signup', async (req, res) => {
    const { full_name, email, password } = req.body;
    if (!full_name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const password_hash = await bcrypt.hash(password, saltRounds);
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
    
    // Rate Limit Check
    if (loginAttempts[attemptKey] && loginAttempts[attemptKey].lockoutTime > now) {
        return res.status(401).json({ 
            message: `Too many failed attempts. Try again in ${Math.ceil((loginAttempts[attemptKey].lockoutTime - now) / 60000)} minutes.` 
        });
    }
    
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
            await new Promise(resolve => setTimeout(resolve, 500)); 
            return handleFailedLogin(res, attemptKey, 'Invalid credentials.');
        }

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return handleFailedLogin(res, attemptKey, 'Invalid credentials.');
        }
        
        if (!user.is_active) {
            return res.status(403).json({ 
                message: 'Your account has been deactivated. Please contact admin.' 
            });
        }
        
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

function handleFailedLogin(res, attemptKey, message) {
    const now = Date.now();
    loginAttempts[attemptKey] = loginAttempts[attemptKey] || { count: 0, lockoutTime: 0 };
    loginAttempts[attemptKey].count++;

    if (loginAttempts[attemptKey].count >= MAX_ATTEMPTS) {
        loginAttempts[attemptKey].lockoutTime = now + LOCKOUT_DURATION_MS;
        loginAttempts[attemptKey].count = 0; 
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


// =========================================================
//                USER PROFILE & STATUS API
// =========================================================

app.put('/api/admin/customers/:id/status', isAdmin, async (req, res) => {
    const userId = req.params.id;
    const { is_active } = req.body;

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

app.get('/api/auth/status', (req, res) => {
    if (req.session.userId) {
        return res.status(200).json({ status: 'authenticated' });
    } else {
        return res.status(401).json({ status: 'unauthenticated' });
    }
});

app.get('/api/auth/check', isAdmin, (req, res) => {
    res.status(200).json({ 
        message: 'Admin privileges confirmed.',
        authenticated: true,
        isAdmin: true
    });
});

app.get('/api/user/profile', isAuthenticated, async (req, res) => {
    const userId = req.session.userId; 

    try {
        const userProfile = await findUserById(userId); 
        if (userProfile) {
            return res.json(userProfile);
        } else {
            return res.status(404).json({ message: 'User profile not found.' });
        }
    } catch (error) {
        console.error('Error fetching user profile:', error);
        return res.status(500).json({ message: 'Server error fetching user data.' });
    }
});

app.post('/api/user/profile', isAuthenticated, upload.single('profilePicture'), async (req, res) => {
    const userId = req.session.userId; 
    const { phoneNumber, currentProfilePictureUrl } = req.body;
    
    let newProfilePictureUrl = currentProfilePictureUrl;

    if (req.file) {
        newProfilePictureUrl = `/images/profiles/${req.file.filename}`; 
    }

    if (phoneNumber && !phoneNumber.match(/^[0-9]{9,15}$/)) {
        return res.status(400).json({ message: 'Invalid phone number format.' });
    }

    try {
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

// =========================================================
//                 ADMIN DASHBOARD API
// =========================================================

app.get('/api/customers', isAdmin, async (req, res) => {
    try {
        const users = await findAllUsers();
        res.json(users);
    } catch (error) {
        console.error('API Error fetching all users/customers:', error);
        res.status(500).json({ message: 'Failed to retrieve customer list.' });
    }
});

app.get('/api/dashboard/stats', isAdmin, async (req, res) => {
    try {
        const [products] = await pool.query('SELECT COUNT(*) AS productCount, SUM(stock) AS totalStock FROM products');
        const [users] = await pool.query('SELECT COUNT(*) AS userCount FROM users WHERE is_admin = ?', [0]);
        const [orders] = await pool.query('SELECT COUNT(*) AS orderCount, SUM(total) AS totalRevenue FROM orders');
        const [pendingOrders] = await pool.query("SELECT COUNT(id) AS pendingCount FROM orders WHERE status = 'Pending'");
        const [completedOrders] = await pool.query("SELECT COUNT(id) AS completedCount FROM orders WHERE status = 'Completed'");

        const stats = {
            productCount: products[0].productCount || 0,
            totalStock: products[0].totalStock || 0,
            userCount: users[0].userCount || 0, 
            orderCount: orders[0].orderCount || 0,
            totalRevenue: parseFloat(orders[0].totalRevenue || 0).toFixed(2), 
            pendingOrders: pendingOrders[0].pendingCount || 0,
            completedOrders: completedOrders[0].completedCount || 0,
        };
        
        res.json(stats);
    } catch (error) {
        console.error('API Error fetching dashboard stats:', error);
        res.status(500).json({ message: 'Failed to retrieve dashboard statistics.' });
    }
});

app.get('/api/dashboard/monthly-sales', isAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m') AS month,
                SUM(total) AS revenue
            FROM orders
            WHERE status = 'Completed'
            GROUP BY month
            ORDER BY month ASC;
        `);
        res.json(rows);
    } catch (error) {
        console.error('API Error fetching monthly sales data:', error);
        res.status(500).json({ message: 'Failed to retrieve sales data.' });
    }
});

// =========================================================
//             PRODUCT, CART, & ORDER API
// =========================================================

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
        const imageFile = req.file;
        
        // Enhanced Validation & Logging
        if (!name || !price || !category || !stock || !imageFile) {
            console.error("Product Upload Failed: Missing fields", req.body);
            return res.status(400).json({ 
                message: 'Missing one or more required fields: name, price, category, stock, or image file.' 
            });
        }
        
        if (isNaN(parseFloat(price)) || isNaN(parseInt(stock))) {
            console.error("Product Upload Failed: Invalid number format", { price, stock });
            return res.status(400).json({ message: 'Price and Stock must be valid numbers.' });
        }
        
        const imagePath = `/images/products/${imageFile.filename}`;
        
        const [result] = await pool.query(
            `INSERT INTO products (name, price, category, description, image_url, stock) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [name, parseFloat(price), category, description, imagePath, parseInt(stock)]
        );

        console.log("Product uploaded successfully, ID:", result.insertId);

        res.status(201).json({ 
            message: 'Product uploaded successfully!', 
            productId: result.insertId 
        });

    } catch (error) {
        console.error('API Error uploading product:', error); // This will show DB errors
        res.status(500).json({ message: 'Failed to upload product. Check server console for details.' });
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

app.put('/api/orders/:orderId', isAdmin, async (req, res) => {
    const orderId = req.params.orderId;
    const { status } = req.body; 

    if (!status) {
        return res.status(400).json({ message: 'Missing status field in request body.' });
    }
    
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
            <p>Thank you for your order! We have successfully received it. You will be contacted shortly on ${phone} or ${email} to confirm delivery.</p>
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

app.put('/api/products/:id', isAdmin, upload.single('productImage'), async (req, res) => {
    const productId = req.params.id;
    let imageUrl = req.body.image_url_current; 
    
    if (req.file) {
        imageUrl = `/images/products/${req.file.filename}`;
    }

    const updatedData = {
        name: req.body.name,
        description: req.body.description,
        price: parseFloat(req.body.price), 
        stock: parseInt(req.body.stock, 10), 
        category: req.body.category,
        image_url: imageUrl, 
    };
    
    try {
        const affectedRows = await db.updateProduct(productId, updatedData); 

        if (affectedRows > 0) { 
            res.status(200).json({ message: `Product ${productId} updated successfully!` });
        } else {
            res.status(404).json({ message: `Product with ID ${productId} not found or no new changes were provided.` });
        }
    } catch (error) {
        console.error("Product Update Error:", error);
        res.status(500).json({ message: 'Failed to update product, please try again later.', details: error.message });
    }
});

app.delete('/api/products/:id', isAdmin, async (req, res) => {
    try {
        const productId = req.params.id;
        const [result] = await pool.query('DELETE FROM products WHERE id = ?', [productId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found.' });
        }
        res.json({ message: `Product ID ${productId} deleted successfully.`, deletedId: productId });

    } catch (error) {
        console.error(`API Error deleting product ID ${req.params.id}:`, error);
        if (error.code === 'ER_ROW_IS_REFERENCED_2') {
             return res.status(409).json({ message: 'Cannot delete product: It is currently part of an order or shopping cart.' });
        }
        res.status(500).json({ message: 'Failed to delete product, please try again later.' });
    }
});

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

// 🚨 REQUEST OTP - Normalized Email
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

        const { error } = await resend.emails.send({
            from: `Lolly's Security <${senderEmail}>`,
            to: user.email,
            subject: 'Lollys Collection Password Reset OTP',
            text: `Your One-Time Password (OTP) for password reset is: ${otp}\n\nThis OTP is valid for 5 minutes. Please enter it on the website to proceed.`
        });

        if (error) {
            console.error('Resend OTP Error:', error);
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

app.post('/api/reset-password', async (req, res) => {
    const { verificationToken, email, newPassword } = req.body; 

    if (!verificationToken || !email || !newPassword) {
        return res.status(400).json({ message: 'Missing required reset information.' });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ message: 'New password must be at least 8 characters long.' });
    }

    const verificationEntry = verificationCache[verificationToken];

    if (!verificationEntry) {
        return res.status(400).json({ message: 'Password reset session is invalid or has expired. Please request a new OTP.' });
    }

    if (Date.now() > verificationEntry.expiry || verificationEntry.email !== email) {
        delete verificationCache[verificationToken];
        return res.status(400).json({ message: 'Password reset session has expired or is invalid. Please request a new OTP.' });
    }

    try {
        const user = await db.findUserByEmail(email);

        if (!user) {
            delete verificationCache[verificationToken]; 
            return res.status(400).json({ message: 'Password reset session is invalid or has expired. Please request a new OTP.' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        const updated = await db.updatePassword(user.id, hashedPassword);
        delete verificationCache[verificationToken]; 

        if (updated) {
            res.status(200).json({ message: 'Password successfully updated. You can now log in.' });
        } else {
            throw new Error("Database update failed (0 rows affected).");
        }
    } catch (error) {
        console.error('Password Reset Error:', error);
        delete verificationCache[verificationToken]; 
        res.status(500).json({ message: 'Failed to reset password, please try again later.' });
    }
});

app.listen(port, async () => {
    console.log(`Server running on port ${port}`);

    try {
        const [rows] = await pool.query('SELECT 1');
        console.log("Database connected successfully.");
    } catch (error) {
        console.error("Warning: Database connection failed:", error);
    }
});