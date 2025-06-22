const db = require('./db');
const bcrypt = require('bcryptjs');

// Function to hash passwords using bcrypt
const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

// Function to update password in the database
const updatePassword = async (userId, hashedPassword) => {
  return new Promise((resolve, reject) => {
    db.query('UPDATE Users SET password = ? WHERE UserID = ?', [hashedPassword, userId], (err) => {
      if (err) {
        console.error(`Error updating password for UserID ${userId}:`, err);
        return reject(err);
      }
      console.log(`Password updated for UserID ${userId}`);
      resolve();
    });
  });
};

// Main function to hash and update passwords
const hashAndUpdatePasswords = async () => {
  try {
    // Fetch all users
    const query = 'SELECT UserID, password FROM Users';
    db.query(query, async (err, users) => {
      if (err) {
        console.error('Error fetching users:', err);
        return;
      }

      const updatePromises = [];

      for (const user of users) {
        // Check if the password is already hashed
        if (user.password.startsWith('$2a$') || user.password.startsWith('$2b$')) {
          console.log(`Password for UserID ${user.UserID} is already hashed. Skipping.`);
          continue;
        }

        try {
          // Hash and update the password
          const hashedPassword = await hashPassword(user.password);
          console.log(`Hashed password for UserID ${user.UserID}`);
          updatePromises.push(updatePassword(user.UserID, hashedPassword));
        } catch (error) {
          console.error(`Error hashing password for UserID ${user.UserID}:`, error);
        }
      }

      // Wait for all updates to finish
      await Promise.all(updatePromises);
      console.log('All passwords hashed and updated.');
      db.end(); // Close connection after completing all tasks
    });
  } catch (error) {
    console.error('Unexpected error:', error);
  }
};

// Run the function
hashAndUpdatePasswords();
