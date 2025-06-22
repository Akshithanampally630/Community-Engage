const bcrypt = require('bcryptjs');

const plainPassword = 'securepass'; // Replace with actual password
const storedHash = '$2b$10$r.hUSrrzZuXiccHeBgZJcOZ6na03yaVBAr4Gj.Gh5N/MuXpEGN4Ne'; // Copy the hashed password from your database

bcrypt.compare(plainPassword, storedHash, (err, isMatch) => {
  if (err) {
    console.error('Error during bcrypt.compare:', err);
  } else {
    console.log('Password Match:', isMatch ? '✅ Yes' : '❌ No');
  }
});
