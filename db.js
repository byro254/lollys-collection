// db.js
const mysql = require('mysql2/promise');
require('dotenv').config(); // Load ENV variables for connection

const pool = mysql.createPool({
    host: process.env.DB_HOST, // 🚨 Updated
    user: process.env.DB_USER, // 🚨 Updated
    password: process.env.DB_PASSWORD, // 🚨 Updated
    // 🚨 Updated
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



// db.js - Corrected findUserOrders function

/**
 * Fetches all orders for a specific user, with all nested items.
 */
async function findUserOrders(userId) {
    // 1. Fetch all orders for the given user ID (OrderSql remains unchanged)
    const orderSql = `
        SELECT 
            id, created_at , total, status, delivery_location, customer_name 
        FROM orders 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    `;
    const [orders] = await pool.execute(orderSql, [userId]);

    // 2. For each order, fetch its associated items
    const ordersWithItems = await Promise.all(orders.map(async (order) => {
        const itemSql = `
            SELECT 
                id AS itemId,  -- Use the unique ID from order_items table and alias it
                product_name as name, 
                unit_price as price, 
                quantity as quantity
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
/**
 * Retrieves a user object by their phone number.
 * This is crucial for OTP-based password reset lookup.
 * @param {string} phone - The phone number of the user.
 * @returns {Promise<object | null>} - User object including id, full_name, email, password_hash, is_admin, and is_active, or null.
 */
async function findUserByPhone(phone) {
    try {
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, password_hash, is_admin, is_active FROM users WHERE phone_number = ?',
            [phone]
        );
        
        return rows.length > 0 ? rows[0] : null;
    } catch (error) {
        console.error('Database error fetching user by phone:', error);
        throw error;
    }
}
// ---------------------------------------------------------------- //
// --- Profile Management Functions (Used by profile.html) ---
// ---------------------------------------------------------------- //
/**
 * Retrieves a user object by their ID.
 * @param {number} userId - The ID of the user.
 * @returns {Promise<{id: number, name: string, email: string, ...} | null>} - User profile or null.
 */
async function findUserById(userId) {
    try {
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, phone_number, profile_picture_url, is_active FROM users WHERE id = ?',
            [userId]
        );
        
        if (rows.length === 0) {
            return null;
        }

        return {
            id: rows[0].id, 
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

// ---------------------------------------------------------------- //
// --- Wallet & Transaction Functions (NEW) ---
// ---------------------------------------------------------------- //

/**
 * Fetches the current wallet balance and account number for a user.
 * @param {number} userId - The ID of the user.
 * @returns {Promise<{balance: number, account_number: string, wallet_id: number} | null>}
 */
async function getWalletByUserId(userId) {
    try {
        const [rows] = await pool.execute(
            // 🚨 FIX: Add wallet_id to the SELECT clause
            'SELECT wallet_id, balance, account_number FROM wallets WHERE user_id = ?',
            [userId]
        );
        return rows.length > 0 ? rows[0] : null;
    } catch (error) {
        console.error('Database error fetching wallet:', error);
        throw error;
    }
}


/**
 * Fetches a user's payment history from the transactions table.
 * @param {number} userId - The ID of the user.
 * @returns {Promise<Array<object>>} List of transaction objects.
 */
async function findPaymentHistory(userId) {
    try {
        const [rows] = await pool.execute(
            `SELECT 
                transaction_date as date, 
                type, 
                amount, 
                transaction_status as status
            FROM transactions 
            WHERE user_id = ?
            ORDER BY transaction_date DESC`,
            [userId]
        );
        return rows;
    } catch (error) {
        console.error('Database error fetching payment history:', error);
        throw error;
    }
}

/**
 * Logs an expenditure from the Business's central operating account.
 * This function performs an internal wallet transaction (deduction).
 * @param {number | string} businessId - The ID associated with the business wallet (should be '0').
 * @param {number} amount - The positive amount being withdrawn (stored as negative in DB).
 * @param {string} purpose - The reason for withdrawal (Restock, Loan, Refund, etc.).
 * @returns {Promise<boolean>} True if the deduction succeeded.
 */
// 🚨 FIX 9a: Renamed function
async function logBusinessExpenditure(businessId, amount, purpose) { 
    const connection = await pool.getConnection();
    const deductionAmount = -Math.abs(amount); // Ensure amount is negative for deduction
    const method = 'Withdrawal'; 
    const type = 'Expenditure'; 
    const transactionStatus = 'Completed';
    const externalRef = `EXP-${Date.now()}`;

    try {
        await connection.beginTransaction();

        // 1. Get Wallet ID and current balance (with FOR UPDATE lock)
        let [walletRows] = await connection.execute(
            'SELECT wallet_id, balance FROM wallets WHERE user_id = ? FOR UPDATE',
            [businessId] // Use the businessId
        );

        let wallet_id;
        let currentBalance;

        if (walletRows.length === 0) {
            // 🚨 FIX 9b: Initialize Business wallet
            const accountNumber = `BIZ-${businessId}`; 
            const [createResult] = await connection.execute(
                'INSERT INTO wallets (user_id, account_number, balance) VALUES (?, ?, 0.00)',
                [businessId, accountNumber]
            );
            if (!createResult.insertId) throw new Error('Failed to initialize Business Wallet.');
            wallet_id = createResult.insertId;
            currentBalance = 0;
        } else {
            wallet_id = walletRows[0].wallet_id;
            currentBalance = walletRows[0].balance;
        }

        // 2. Validate balance for expenditure
        // 🚨 FIX 9c: Updated error message
        if (currentBalance + deductionAmount < 0) { 
             throw new Error('INSUFFICIENT_BUSINESS_FUNDS');
        }

        const newBalance = currentBalance + deductionAmount;

        // 3. Log Transaction (Use 'purpose' for the description column if available)
        const transactionSql = `
            INSERT INTO transactions (user_id, wallet_id, type, method, amount, external_ref, description, transaction_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        `;
        await connection.execute(transactionSql, [adminId, wallet_id, type, method, deductionAmount, externalRef, purpose, transactionStatus]);

        // 4. Update Wallet Balance
        await connection.execute(
            'UPDATE wallets SET balance = ? WHERE wallet_id = ?',
            [newBalance, wallet_id]
        );

        await connection.commit();
        return true;

    } catch (error) {
        await connection.rollback();
        console.error(`Database error during Admin Expenditure transaction:`, error);
        throw error;
    } finally {
        connection.release();
    }
}


/**
 * Fetches all transactions related to the central Business Account.
 * @param {string | number} businessId - The ID associated with the business wallet (should be '0').
 * @returns {Promise<Array<object>>} List of all relevant transaction records.
 */
// 🚨 FIX 10a: Renamed function
async function getBusinessFinancialHistory(businessId) {
    try {
       
        const [rows] = await pool.execute(
            `SELECT 
                transaction_date as date, 
                type, 
                amount, 
                order_id,
                external_ref, 
                method,
                description,
                transaction_status as status
            FROM transactions 
            WHERE user_id = ?
            ORDER BY transaction_date DESC`,
           [businessId]
        );
        return rows;
    } catch (error) {
       console.error('Database error fetching business financial history:', error); 
        throw error;
    }
}


// ---------------------------------------------------------------- //
// --- CHAT FUNCTIONS ---
// ---------------------------------------------------------------- //

/**
 
 * @param {string} customerId - The ID of the primary chat session owner (key).
 * @param {('admin'|'customer')} senderRole - Role of the sender.
 * @param {string} senderId - The actual ID of the user who sent the message.
 * @param {string} recipientId - The actual ID of the user who should receive the message.
 * @param {string} message - The content of the message.
 * @returns {Promise<object>} The result of the database query.
 */
async function saveChatMessage(customerId, senderRole, senderId, recipientId, message) {
    const query = `
        INSERT INTO chat_messages (customer_id, sender_role, sender_id, received_from_id, recipient_id, sent_to_id, message_content)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    `;
    // The values now include the recipientId twice to satisfy both recipient_id AND sent_to_id columns.
    // Order: customerId, senderRole, senderId(1), senderId(2), recipientId(1), recipientId(2), message
    const [result] = await pool.query(query, [customerId, senderRole, senderId, senderId, recipientId, recipientId, message]);
    return result;
}

/**
 * Fetches the entire chat history for a specific customer.
 * @param {string} customerId - The ID of the customer (or user ID) for the chat session.
 * @returns {Promise<Array<object>>} List of chat message objects, ordered by time.
 */
async function getChatHistory(customerId) {
    // Note: We are selecting 'recipient_id' here, but the server.js might expect 'sent_to_id'
    // It's safest to match the database's column name here for successful query execution.
    const query = `
        SELECT sender_role, sender_id, recipient_id, message_content, created_at
        FROM chat_messages
        WHERE customer_id = ?
        ORDER BY created_at ASC;
    `;
    const [rows] = await pool.query(query, [customerId]); 
    return rows;
}

// db.js (Wallet & Transaction Functions section)

/**
 * Executes an atomic wallet transaction (Deposit or Deduction).
 * @param {number} userId - The user ID.
 * @param {number} amount - The amount to transact (positive for Deposit, negative for Deduction/Withdrawal).
 * @param {string} method - Payment method ('M-Pesa', 'Card', 'Wallet Deduction', 'Wallet Revenue').
 * @param {string} type - Transaction type ('Deposit', 'Deduction').
 * @param {string} externalRef - Transaction ID/Reference (for deposits).
 * @param {number | null} orderId - The ID of the order if this is a deduction for an order.
 * @param {string} transactionStatus - 'Completed' or 'Pending'.
 * @param {string | null} description - The description/purpose for the transaction. 🚨 NEW PARAMETER
 * @returns {Promise<boolean>} True if transaction and balance update succeeded.
 */


// db.js (performWalletTransaction - Final Corrected Version)

async function performWalletTransaction(userId, amount, method, type, externalRef, orderId = null, transactionStatus = 'Completed', description = null) {
    // 1. Setup and User ID Coercion
    const connection = await pool.getConnection();
    const dbUserId = Number(userId); // Coerce userId to a Number for database matching
    
    let wallet_id;
    let currentBalance; 
    let newBalance; // Declare newBalance here to ensure it's available for the final return

    try {
        await connection.beginTransaction();
        
        // 2. Get Wallet ID and current balance (with CRITICAL FOR UPDATE lock)
        let [walletRows] = await connection.execute(
            'SELECT wallet_id, balance FROM wallets WHERE user_id = ? FOR UPDATE',
            [dbUserId]
        );
        
        if (walletRows.length === 0) {
            // Wallet not found, create it with a starting balance of 0
            const accountNumber = `U${dbUserId}`; 
            
            const [createResult] = await connection.execute(
                'INSERT INTO wallets (user_id, account_number, balance) VALUES (?, ?, 0.00)',
                [dbUserId, accountNumber]
            );
            
            wallet_id = createResult.insertId;
            currentBalance = 0; 
            
        } else {
            // Wallet found
            wallet_id = walletRows[0].wallet_id;
            // Use parseFloat to ensure balance is treated as a number
            currentBalance = parseFloat(walletRows[0].balance);
        }

        // 3. Validation and Calculation
        newBalance = currentBalance + amount;

        if (amount < 0 && newBalance < 0) { 
             throw new Error('INSUFFICIENT_FUNDS');
        }

        // 4. Log Transaction (Must happen before updating the wallet for audit integrity)
        const transactionSql = `
            INSERT INTO transactions (user_id, wallet_id, order_id, type, method, amount, external_ref, transaction_status, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        `;
        await connection.execute(transactionSql, [dbUserId, wallet_id, orderId, type, method, amount, externalRef, transactionStatus, description]);

        // 5. Update Wallet Balance (Only if transaction is completed)
        if (transactionStatus === 'Completed') {
            const [updateResult] = await connection.execute(
                'UPDATE wallets SET balance = ? WHERE wallet_id = ?',
                [newBalance, wallet_id]
            );
            
            // Critical Check: Ensures the update actually happened
            if (updateResult.affectedRows === 0) {
                 throw new Error(`CRITICAL: Wallet balance update failed for user ${dbUserId} and wallet ID ${wallet_id}.`);
            }
        }

        // 6. Commit and Return Final Balance
        await connection.commit();
        
        // Return the final balance, which is the most useful piece of information for the client side.
        return newBalance; 
        
    } catch (error) {
        // 7. Rollback on Error
        await connection.rollback();
        console.error(`Database error during ${type} transaction:`, error);
        throw error;
    } finally {
        // 8. Release Connection
        connection.release();
    }
}
// ---------------------------------------------------------------- //
// --- MODULE EXPORTS (Updated to include new functions) ---
// ---------------------------------------------------------------- //
module.exports = {
    pool,
  
    findUserById, 
    findAllUsers,
    saveContactMessage,
    getAllContactMessages,
    updateProduct,
    updatePassword,
    findUserByEmail, 
    findUserOrders, 
    updateUserProfile, 
    updateUserStatus, 
    findUserByPhone, 
    
    // 🚨 NEW Wallet & Transaction functions
    getWalletByUserId,
    findPaymentHistory,
    performWalletTransaction, 
    // 🚨 NEW Admin Wallet functions
    logBusinessExpenditure,
    getBusinessFinancialHistory,
    // Chat functions
    saveChatMessage, 
    getChatHistory,
};