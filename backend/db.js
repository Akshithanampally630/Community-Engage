const mysql = require('mysql2');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root', // Replace with your username
  password: 'akshitha@630', // Replace with your password
  database: 'CommunityEngage'
});

db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log('Connected to the database');
  }
});

// module.exports = db;

db.query('SELECT 1 + 1 AS result', (err, results) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected. Test query result:', results[0].result);
  }
});


module.exports = db;