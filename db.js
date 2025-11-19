// db.js
const mysql = require('mysql2/promise');
require('dotenv').config(); // Load ENV variables for connection

const pool = mysql.createPool({
    host: process.env.DB_HOST, // 🚨 Updated
    user: process.env.DB_USER, // 🚨 Updated
    password: process.env.DB_PASSWORD, // 🚨 Updated
    database: process.env.DB_DATABASE, // 🚨 Updated
    port: process.env.DB_PORT,
   database: process.env.DB_NAME,
   waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,

    ssl: {
        // 🚨 CRITICAL: Set to true to bypass validation
        rejectUnauthorized: false 
    }
});




// ---------------------------------------------------------------- //

/**
 * Retrieves a list of all registered users (customers).
 * This is intended for the admin panel listing.
 * @returns {Promise<Array<{id: number, full_name: string, email: string, is_admin: boolean, created_at: Date}>>} - List of users.
 */
async function findAllUsers() {
    try {
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, is_admin, is_active, created_at FROM users ORDER BY created_at DESC'
        );
        return rows;
    } catch (error) {
        console.error('Database error fetching all users (customers):', error);
        throw error;
    }
}
/**
 * Saves a new contact message to the database.
 * @param {string} name - Sender's name.
 * @param {string} email - Sender's email.
 * @param {string} message - The content of the message.
 * @returns {Promise<object>} The result of the database query.
 */
async function saveContactMessage(name, email, message) {
    const query = `
        INSERT INTO messages (sender_name, sender_email, message_content)
        VALUES (?, ?, ?);
    `;
    // Assumes your pool.query function is ready for use
    const [result] = await pool.query(query, [name, email, message]);
    return result;
}
/**
 * Fetches all contact messages, sorted by most recent first.
 * @returns {Promise<Array<object>>} List of message objects.
 */
async function getAllContactMessages() {
    const query = `
        SELECT id, sender_name, sender_email, message_content, received_at
        FROM messages
        ORDER BY received_at DESC;
    `;
    // Assumes pool.query is available and returns a format like [rows, fields]
    const [rows] = await pool.query(query); 
    return rows;
}
/**
 * Updates an existing product in the database.
 * @param {number} productId - The ID of the product to update.
 * @param {object} updatedData - Object containing product fields to update (e.g., name, price, description, etc.).
 * @returns {Promise<number>} - The number of affected rows (0 or 1).
 */
async function updateProduct(productId, updatedData) {
    // Dynamically build the SET clause and the values array
    const fields = [];
    const values = [];

    // Iterate over the data to build the query components securely
    for (const [key, value] of Object.entries(updatedData)) {
        // Exclude 'id' and any null/undefined values from the update
        if (value !== undefined && value !== null && key !== 'id') { 
            // Use prepared statement placeholder '?'
            fields.push(`${key} = ?`);
            values.push(value);
        }
    }

    if (fields.length === 0) {
        // No valid fields to update, treat as a successful operation with 0 rows affected
        return 0;
    }

    // Add the productId to the end of the values array for the WHERE clause
    values.push(productId);

    const query = `
        UPDATE products 
        SET ${fields.join(', ')}
        WHERE id = ?;
    `;
    
    try {
        // Execute the UPDATE query
        const [result] = await pool.execute(query, values);
        // result.affectedRows tells you how many rows were updated (should be 0 or 1)
        return result.affectedRows; 
    } catch (error) {
        console.error('Database error updating product:', error);
        throw error;
    }
}
/**
 * Retrieves a user object (with all essential fields for login/reset) by their email address.
 * This function is crucial for both login and the new OTP request step.
 * @param {string} email - The email address of the user.
 * @returns {Promise<object | null>} - User object including full_name, password_hash, and is_admin, or null.
 */
async function findUserByEmail(email) {
    try {
        // Updated to fetch all fields needed for login/auth/reset email sending
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, password_hash,is_admin FROM users WHERE email = ?',
            [email]
        );
        
        return rows.length > 0 ? rows[0] : null;
    } catch (error) {
        console.error('Database error fetching user by email:', error);
        throw error;
    }
}

/**
 * Resets the user's password. The token clearing logic is removed 
 * as the password reset flow now uses an in-memory cache for verification.
 * @param {number} userId - The ID of the user.
 * @param {string} hashedPassword - The new, securely hashed password.
 * @returns {Promise<boolean>} True if the password was successfully updated.
 */
async function updatePassword(userId, hashedPassword) {
    try {
        const [result] = await pool.execute(
            `UPDATE users 
             SET password_hash = ?
             WHERE id = ?`,
            [hashedPassword, userId]
        );
        return result.affectedRows > 0;
    } catch (error) {
        console.error('Database error updating password:', error);
        throw error;
    }
}

// db.js (New function to append and export)

/**
 * Fetches all orders for a specific user, with all nested items.
 * Queries both the 'orders' and 'order_items' tables.
 */
// db.js

/**
 * Fetches all orders for a specific user, with all nested items (MySQL syntax).
 */
// db.js

/**
 * Fetches all orders for a specific user, with all nested items (MySQL syntax).
 * FIX: Using 'id' instead of 'order_id' for the primary key.
 */
async function findUserOrders(userId) {
    // 1. Fetch all orders for the given user ID
    const orderSql = `
        SELECT 
            id, created_at , total, status, delivery_location,  customer_name 
        FROM orders 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    `;
    const [orders] = await pool.execute(orderSql, [userId]);

    // 2. For each order, fetch its associated items
    const ordersWithItems = await Promise.all(orders.map(async (order) => {
        const itemSql = `
            SELECT 
                product_id as id, product_name as name, unit_price as price, quantity as quantity
            FROM order_items 
            WHERE order_id = ? 
        `;
        // Use order.id (the corrected primary key name) to fetch items
        const [items] = await pool.execute(itemSql, [order.id]);
        
        return {
            // Map the returned 'id' column to 'orderId' for the frontend
            orderId: order.id, 
            date: order.created_at,
            total: order.total,
            status: order.status,
            location: order.delivery_location,
            
            customerName: order.customer_name,
            items: items,
        };
    }));

    return ordersWithItems;
}
// ---------------------------------------------------------------- //
// REMOVED OBSOLETE FUNCTIONS: savePasswordResetToken, findUserByResetToken
// ---------------------------------------------------------------- //
/**
 * Retrieves the name and email of a user by their ID.
 * @param {number} userId - The ID of the user.
 * @returns {Promise<{name: string, email: string} | null>} - User profile or null.
 */
async function findUserById(userId) {
    try {
        const [rows] = await pool.execute(
            'SELECT full_name, email, phone_number, profile_picture_url, is_active FROM users WHERE id = ?',
            [userId]
        );
        
        if (rows.length === 0) {
            return null;
        }

        return {
            name: rows[0].full_name,
            email: rows[0].email,
            phoneNumber: rows[0].phone_number,
            profilePictureUrl: rows[0].profile_picture_url,
            isActive: rows[0].is_active,
        };

    } catch (error) {
        console.error('Database error fetching user profile:', error);
        throw error;
    }
}

/**
 * Updates the editable profile fields (phone number and profile picture URL). (NEW)
 */
async function updateUserProfile(userId, phoneNumber, profilePictureUrl) {
    const fields = [];
    const values = [];

    // Only update if value is provided and valid
    if (phoneNumber !== undefined) {
        fields.push('phone_number = ?');
        values.push(phoneNumber);
    }
    if (profilePictureUrl !== undefined) {
        fields.push('profile_picture_url = ?');
        values.push(profilePictureUrl);
    }
    
    if (fields.length === 0) return 0;

    values.push(userId);
    
    const query = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
    
    try {
        const [result] = await pool.execute(query, values);
        return result.affectedRows;
    } catch (error) {
        console.error('Database error updating user profile:', error);
        throw error;
    }
}

/**
 * Updates the active status of a user. (NEW)
 */
async function updateUserStatus(userId, newStatus) {
    try {
        const [result] = await pool.execute(
            'UPDATE users SET is_active = ? WHERE id = ?',
            [newStatus, userId]
        );
        return result.affectedRows;
    } catch (error) {
        console.error('Database error updating user status:', error);
        throw error;
    }
}
module.exports = {
    pool,
  
    findUserById, 
    findAllUsers,
    saveContactMessage,
    getAllContactMessages,
    updateProduct,
    updatePassword,
    findUserByEmail, // Now returns more fields for login/reset
    findUserOrders, // New function to fetch all orders with items for a user
    updateUserProfile, // New function to update user profile fields
    updateUserStatus, // New function to update user active status
    };
