// backend/routes/adminLogin.js

const express = require('express');
const bcrypt = require('bcryptjs'); // For password hashing comparison
const jwt = require('jsonwebtoken'); // For creating JWT tokens
const db = require('../db'); // Importing the database connection

const router = express.Router();

// Admin login route
router.post('/', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    // Query to get the admin data based on the username (case-sensitive column name fix)
    const query = 'SELECT * FROM Admin WHERE UserName = ?';

    db.query(query, [username], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error while retrieving admin.' });
        }

        if (results.length === 0) {
            console.log('Admin not found for username:', username);
            return res.status(404).json({ error: 'Admin not found.' });
        }

        const admin = results[0];
        console.log('Admin found:', admin.UserName);

        // Compare the password with the stored hash (case-sensitive fix for column name)
        bcrypt.compare(password, admin.Password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing password:', err);
                return res.status(500).json({ error: 'Error comparing password.' });
            }

            if (!isMatch) {
                console.log('Incorrect password for username:', username);
                return res.status(401).json({ error: 'Incorrect password.' });
            }

            // Generate a JWT token for the admin
            const token = jwt.sign({ adminId: admin.AdminID, username: admin.UserName }, '7f5e8Fh2mB!gZ5#9JdQwA1n9zLsP3eR&J', {
                expiresIn: '1h' // Token expires in 1 hour
            });

            console.log('Admin login successful for:', username);
            res.json({ message: 'Admin logged in successfully!', token });
        });
    });
});

module.exports = router;
