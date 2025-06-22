const express = require('express');
const cors = require('cors');
const db = require('./db'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const axios = require("axios");


const SECRET_KEY = '7f5e8Fh2mB!gZ5#9JdQwA1n9zLsP3eR&J';
const app = express();
const port = 5000;

app.use(express.json());
app.use(cors()); // Enable CORS for all routes
// const cors = require('cors');
// app.use(cors());

// ✅ Check Database Connection
db.query('SELECT 1', (err) => {
  if (err) {
    console.error('Database connection failed:', err.message);
  } else {
    console.log('✅ Connected to the database');
  }
});


// ✅ Welcome Route
app.get('/', (req, res) => {
    res.send('Welcome to Community Engage!');
});

// ✅ Unified Login Route
app.post('/api/login', (req, res) => {
  const { UserName, Password, Role } = req.body;

  if (!UserName || !Password || !Role) {
    return res.status(400).json({ error: 'Username, password, and role are required.' });
  }

  const query = 'SELECT * FROM Users WHERE UserName = ?';

  db.query(query, [UserName], (err, results) => {
    if (err) {
      console.error('Database Error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = results[0];

    // ✅ Check if the role matches
    if (user.Role !== Role) {
      return res.status(403).json({ error: `Access denied! You are not authorized as ${Role}.` });
    }

    // ✅ Compare password using bcrypt
    bcrypt.compare(Password, user.Password, (err, isMatch) => {
      if (err) {
        console.error('Password Comparison Error:', err);
        return res.status(500).json({ error: 'Error comparing password' });
      }

      if (!isMatch) {
        return res.status(401).json({ error: 'Incorrect password' });
      }

      // ✅ Generate JWT Token
      const token = jwt.sign(
        { userId: user.UserID, UserName: user.UserName, Role: user.Role },
        '7f5e8Fh2mB!gZ5#9JdQwA1n9zLsP3eR&J',
        { expiresIn: '1h' }
      );

      res.json({ message: `${Role} logged in successfully!`, token });
    });
  });
});



// ✅ Volunteers Table
app.get('/volunteer', (req, res) => {
    db.query('SELECT * FROM Volunteers', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// ✅ Event Participation Table
app.get('/eventparticipation', (req, res) => {
    db.query('SELECT * FROM EventParticipation', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// ✅ Feedback Table - GET Request
app.get('/feedback', (req, res) => {
    db.query('SELECT * FROM Feedback', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// ✅ Submit Feedback (POST request)
app.post('/feedback', (req, res) => {
    const { userId, eventName, likes, complaints, suggestions, rating } = req.body;

    if (!userId || !eventName || !rating) {
        return res.status(400).json({ error: 'UserId, EventName, and Rating are required.' });
    }

    // Step 1: Get EventID using EventName
    const findEventQuery = 'SELECT EventID FROM Events WHERE EventName = ?';

    db.query(findEventQuery, [eventName], (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            return res.status(500).json({ error: 'Database error while finding EventID.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Event not found.' });
        }

        const eventId = results[0].EventID;

        // Step 2: Insert feedback
        const insertFeedbackQuery = `
            INSERT INTO Feedback (UserID, EventID, EventName, Liked, Complaints, Suggestions, Rating, FeedbackDate)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
        `;

        db.query(insertFeedbackQuery, [userId, eventId, eventName, likes, complaints, suggestions, rating], (err) => {
            if (err) {
                console.error('Database Error:', err.message);
                return res.status(500).json({ error: 'Failed to submit feedback.' });
            }
            res.json({ message: 'Feedback submitted successfully!' });
        });
    });
});

// ✅ Donations Table
app.get('/donations', (req, res) => {
    db.query('SELECT * FROM Donations', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// ✅ Messages Table
app.get('/messages', (req, res) => {
    db.query('SELECT * FROM Messages', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// ✅ PhotoHub Table
app.get('/photohub', (req, res) => {
    db.query('SELECT * FROM PhotoHub', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// ✅ NoticeBoard Table
app.get('/noticeboard', (req, res) => {
    db.query('SELECT * FROM NoticeBoard', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// ✅ Event Requests Table
app.get('/eventrequests', (req, res) => {
    db.query('SELECT * FROM EventRequests', (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
});

// API to fetch only necessary event details
app.get('/api/events', (req, res) => {
    const query = `SELECT EventName,EventID, Date AS EventDate, Time AS EventTime, DurationInHours AS Duration, EventFrequency, EventDay,
                    (SELECT UserName FROM Users WHERE Users.UserID = Events.OrganizerID) AS OrganizerName,
                    MaxParticipants, RemainingParticipants, LastDateToRegister
                    FROM Events
                    WHERE Status = 'Upcoming'`;
  
    db.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching events:', err);
        res.status(500).json({ error: 'Error fetching events' });
      } else {
        res.json(results);
      }
    });
  });

  app.post('/api/eventregister', (req, res) => {
    const { userID, eventID } = req.body;
  
    // Step 1: Check if already registered
    const checkQuery = `SELECT * FROM EventParticipation WHERE UserID = ? AND EventID = ?`;
  
    db.query(checkQuery, [userID, eventID], (err, results) => {
      if (err) {
        console.error('Error checking registration:', err);
        return res.status(500).json({ error: 'Database error' });
      }
  
      if (results.length > 0) {
        return res.status(400).json({ error: 'You have already registered for this event' });
      }
  
      // Step 2: Get Event info + RemainingParticipants
      const eventQuery = `SELECT EventFrequency, EventName, RemainingParticipants FROM Events WHERE EventID = ?`;
  
      db.query(eventQuery, [eventID], (err, eventResults) => {
        if (err || eventResults.length === 0) {
          console.error('Error fetching event:', err);
          return res.status(500).json({ error: 'Event not found' });
        }
  
        const { EventFrequency, EventName, RemainingParticipants } = eventResults[0];
  
        if (RemainingParticipants <= 0) {
          return res.status(400).json({ error: 'You cannot register for this event as the max participants have already registered.' });
        }
  
        const pointsEarned = EventFrequency === 'Once' ? 100 : 300;
  
        // Step 3: Register user in EventParticipation
        const insertParticipationQuery = `
          INSERT INTO EventParticipation (UserID, EventID, PointsEarned)
          VALUES (?, ?, ?)
        `;
  
        db.query(insertParticipationQuery, [userID, eventID, pointsEarned], (err) => {
          if (err) {
            console.error('Error inserting participation:', err);
            return res.status(500).json({ error: 'Could not register user' });
          }
  
          // Step 4: Update Users table
          const updateUserQuery = `
            UPDATE Users
            SET 
              points = points + ?,
              EventsInvolvedIn = 
                CASE 
                  WHEN EventsInvolvedIn IS NULL OR EventsInvolvedIn = '' THEN ?
                  ELSE CONCAT(EventsInvolvedIn, ',', ?)
                END
            WHERE UserID = ?
          `;
  
          db.query(updateUserQuery, [pointsEarned, EventName, EventName, userID], (err) => {
            if (err) {
              console.error('Error updating user:', err);
              return res.status(500).json({ error: 'Could not update user info' });
            }
  
            // Step 5: Reduce RemainingParticipants in Events table
            const updateRemainingQuery = `
              UPDATE Events
              SET RemainingParticipants = RemainingParticipants - 1
              WHERE EventID = ?
            `;
  
            db.query(updateRemainingQuery, [eventID], (err) => {
              if (err) {
                console.error('Error updating event capacity:', err);
                return res.status(500).json({ error: 'Error updating event participant count' });
              }
  
              // All done!
              return res.status(200).json({
                message: 'Registration successful',
                pointsEarned
              });
            });
          });
        });
      });
    });
  });
  
// API to fetch leaderboard data
app.get("/api/leaderboard", (req, res) => {
    const sql = "SELECT UserName, points FROM users WHERE Role IN ('User', 'Organizer') ORDER BY points DESC LIMIT 10";
    
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching leaderboard data:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.json(results);
    });
});


// API to fetch dashboard stats
app.get("/api/dashboard-stats", (req, res) => {
    const statsQuery = `
        SELECT 
            (SELECT COUNT(*) FROM users) AS totalParticipants,
            (SELECT COUNT(DISTINCT UserID) FROM eventparticipation) AS activeMembers,
            (SELECT COUNT(*) FROM events WHERE Status = 'Completed') AS activitiesCompleted,
            (SELECT COUNT(*) FROM events WHERE Status = 'Upcoming') AS activitiesOngoing,
            (SELECT COUNT(*) FROM events WHERE EventFrequency = 'Once') AS oneTimeEvents,
            (SELECT COUNT(*) FROM events WHERE EventFrequency = 'Weekly') AS weeklyEvents,
            (SELECT COUNT(*) FROM volunteers) AS totalVolunteers
    `;

    db.query(statsQuery, (err, results) => {
        if (err) {
            console.error("Error fetching dashboard stats:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.json(results[0]);
    });
});

app.get('/api/top-performers', (req, res) => {
    console.log('Fetching top performers...');
    
    db.query('SELECT UserName, points FROM users WHERE Role = "User" OR Role = "Organizer" ORDER BY points DESC LIMIT 5', (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            res.status(500).json({ message: 'Internal Server Error' });
            return;
        }
        console.log('Top performers fetched:', results);
        res.json(results); // Respond with the results in JSON
    });
});





app.post("/api/eventrequests", (req, res) => {
    const {
        eventName, description, proposedDate, proposedTime, requestorID,
        organiserName, maxParticipants, maxVolunteers, lastDateToRegister,
        eventDate, eventTime, location, durationInHours, eventFrequency, eventDay
    } = req.body;

    // SQL Query to Insert Data
    const query = `
        INSERT INTO eventrequests 
        (EventName, Description, ProposedDate, ProposedTime, RequestorID, 
        Status, OrganiserName, MaxParticipants, MaxVolunteers, 
        LastDateToRegister, EventDate, EventTime, Location, 
        DurationInHours, EventFrequency, EventDay) 
        VALUES (?, ?, ?, ?, ?, 'Pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
        eventName, description, proposedDate, proposedTime, requestorID,
        organiserName, maxParticipants, maxVolunteers, lastDateToRegister,
        eventDate, eventTime, location, durationInHours, eventFrequency, eventDay
    ];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error("Database Insert Error:", err);  // Log error for debugging
            return res.status(500).json({ error: "Database error", details: err.message });
        }
        res.json({ message: "Event request submitted successfully!", requestID: result.insertId });
    });
});
const moment = require('moment');

// Route to fetch upcoming events and their details for volunteer page
app.get('/events/upcoming', (req, res) => {
    // Query to fetch events with upcoming status
    const query = `
        SELECT e.EventID, e.EventName, e.Date AS EventDate, e.Time AS EventTime, e.EventFrequency, e.EventDay, 
               e.DurationInHours, e.Location, e.MaxVolunteers, e.RemainingVolunteers, e.CurrentNumberOfVolunteers, 
               e.Status, e.OrganizerID
        FROM events e
        WHERE e.Status = 'Upcoming'
    `;

    // Fetch events from the database
    db.query(query, (err, events) => {
        if (err) {
            return res.status(500).json({ error: 'Error fetching events' });
        }

        // Fetch organizer names for each event
        const eventDetailsPromises = events.map(event => {
            return new Promise((resolve, reject) => {
                // Fetch the organizer's name from the users table using the OrganizerID
                const organizerQuery = `SELECT UserName FROM users WHERE UserID = ?`;
                db.query(organizerQuery, [event.OrganizerID], (err, result) => {
                    if (err) {
                        return reject(err);
                    }

                    event.OrganizerName = result[0] ? result[0].UserName : 'Unknown';  // Default to 'Unknown' if no organizer found

                    // Format the EventDate and EventTime using moment
                    event.EventDate = moment(event.EventDate).format('YYYY-MM-DD');
                    event.EventTime = moment(event.EventTime, 'HH:mm:ss').format('hh:mm A');  // Formatting time to 12-hour format

                    resolve(event);  // Resolve the promise with event details
                });
            });
        });

        // Wait for all event details to be populated (including organizer name)
        Promise.all(eventDetailsPromises)
            .then(eventsWithOrganizer => {
                res.json(eventsWithOrganizer);  // Send the events data to the client
            })
            .catch(error => {
                res.status(500).json({ error: 'Error fetching organizer names' });
            });
    });
});


app.post('/volunteers', (req, res) => {
    const { eventID, userId } = req.body;

    // Check if the user is already a volunteer for the event
    const checkVolunteerQuery = `SELECT * FROM volunteers WHERE UserID = ? AND EventID = ?`;
    db.query(checkVolunteerQuery, [userId, eventID], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Error checking existing volunteer' });
        }

        if (result.length > 0) {
            return res.status(400).json({ error: 'You have already signed up as a volunteer for this event.' });
        }

        // Check if there are remaining volunteer slots
        const checkSlotsQuery = `SELECT RemainingVolunteers, CurrentNumberOfVolunteers, EventFrequency, EventName FROM events WHERE EventID = ?`;
        db.query(checkSlotsQuery, [eventID], (err, eventResult) => {
            if (err) {
                return res.status(500).json({ error: 'Error checking volunteer slots' });
            }

            const event = eventResult[0];
            if (event.RemainingVolunteers <= 0) {
                return res.status(400).json({ error: 'No volunteer slots available' });
            }

            // Insert the volunteer into the volunteers table
            const insertVolunteerQuery = `INSERT INTO volunteers (UserID, EventID) VALUES (?, ?)`;
            db.query(insertVolunteerQuery, [userId, eventID], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Error inserting volunteer' });
                }

                // Determine points based on event frequency
                const pointsEarned = event.EventFrequency === 'Once' ? 200 : 500;

                // Update the event details: decrease remaining volunteers and increase current volunteers
                const updateEventQuery = `
                    UPDATE events
                    SET RemainingVolunteers = RemainingVolunteers - 1,
                        CurrentNumberOfVolunteers = CurrentNumberOfVolunteers + 1
                    WHERE EventID = ?
                `;

                db.query(updateEventQuery, [eventID], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Error updating event' });
                    }

                    // Update VolunteerStatus and points in the users table
                    const updateUserQuery = `
                        UPDATE users
                        SET points = points + ?,
                            VolunteerStatus = CASE 
                                WHEN VolunteerStatus IS NULL OR VolunteerStatus = '' THEN ?
                                ELSE CONCAT(VolunteerStatus, ', ', ?)
                            END
                        WHERE UserID = ?
                    `;

                    db.query(updateUserQuery, [pointsEarned, event.EventName, event.EventName, userId], (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Error updating user' });
                        }

                        res.status(200).json({ message: `Successfully signed up as a volunteer. Points Earned: ${pointsEarned}` });
                    });
                });
            });
        });
    });
});

// Registration Endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, password, flatNumber, phone, email, age, gender, skills, bio } = req.body;

        // Hash the password for security
        const hashedPassword = await bcrypt.hash(password, 10);

        // Default values for missing fields
        const volunteerStatus = null;
        const role = 'User';
        const points = 0;
        const eventsInvolvedIn = null;
        const eventsOrganized = null;

        // Insert user data into MySQL
        const sql = `
            INSERT INTO users (UserName, Password, FlatNumber, PhoneNumber, Email, Age, Gender, SkillsAndInterests, Bio, VolunteerStatus, Role, points, EventsInvolvedIn, EventsOrganized) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [username, hashedPassword, flatNumber, phone, email, age, gender, skills, bio, volunteerStatus, role, points, eventsInvolvedIn, eventsOrganized];

        db.query(sql, values, (err, result) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            res.status(201).json({ message: 'User registered successfully' });
        });
    } catch (error) {
        console.error('Error in registration:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ✅ Middleware to Verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access Denied. No token provided.' });

    try {
        const verified = jwt.verify(token.split(" ")[1], SECRET_KEY);
        req.user = verified; // Store decoded token
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid Token' });
    }
};

// ✅ API: Fetch Logged-in User Profile
app.get('/api/profile', authenticateToken, (req, res) => {
    const userId = req.user.userId; // Extract user ID from JWT

    const sql = `SELECT 
                    UserID, UserName, Email, PhoneNumber, Age, Gender, FlatNumber, 
                    SkillsAndInterests, VolunteerStatus, Role, Bio, points, 
                    EventsInvolvedIn, EventsOrganized 
                 FROM users WHERE UserID = ?`;

    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error('Database Error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (result.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Replace empty values with "Null"
        const userData = result[0];
        Object.keys(userData).forEach(key => {
            if (userData[key] === null || userData[key] === "") {
                userData[key] = "Null";
            }
        });

        res.json(userData);
    });
});

// Update user profile
app.put("/api/updateProfile", authenticateToken, async (req, res) => {
    const { userID, password, phone, age, gender, flat, skills, bio } = req.body;

    let query = "UPDATE users SET PhoneNumber=?, Age=?, Gender=?, FlatNumber=?, SkillsAndInterests=?, Bio=?";
    let values = [phone, age, gender, flat, skills, bio];

    if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        query += ", Password=?";
        values.push(hashedPassword);
    }

    query += " WHERE UserID=?";
    values.push(userID);

    db.query(query, values, (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        res.json({ success: true, message: "Profile updated successfully" });
    });
});


  
  // Mark feedback as reviewed
  app.put('/api/feedback/:id/reviewed', async (req, res) => {
    const feedbackId = req.params.id;
    try {
      db.query('UPDATE feedback SET Status = "Reviewed" WHERE FeedbackID = ?', [feedbackId]);
      res.json({ message: 'Feedback marked as reviewed' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  // Get username from UserID
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    db.query('SELECT UserName FROM Users WHERE UserID = ?', [userId], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(404).json({ error: 'User not found' });
      res.json({ userName: results[0].UserName });
    });
  });
  
// ✅ GET all event requests
app.get('/api/event-requests', (req, res) => {
    db.query('SELECT * FROM eventrequests', (err, results) => {
      if (err) return res.status(500).json(err);
  
      // Format the date and time for better readability
      results = results.map(event => ({
        ...event,
        ProposedDate: moment(event.ProposedDate).format('YYYY-MM-DD'),
        ProposedTime: moment(event.ProposedTime, 'HH:mm:ss').format('hh:mm A'),
        EventDate: moment(event.EventDate).format('YYYY-MM-DD'),
        EventTime: moment(event.EventTime, 'HH:mm:ss').format('hh:mm A'),
        LastDateToRegister: moment(event.LastDateToRegister).format('YYYY-MM-DD')
      }));
  
      res.json(results);
    });
  });
  
  // ✅ REJECT a request
  app.post('/api/event-requests/:id/reject', (req, res) => {
    const requestID = req.params.id;
    db.query('UPDATE eventrequests SET Status = "Rejected" WHERE RequestID = ?', [requestID], (err) => {
      if (err) return res.status(500).json(err);
      res.sendStatus(200);
    });
  });
  
  // ✅ APPROVE a request
  app.post('/api/event-requests/:id/approve', (req, res) => {
    const requestID = req.params.id;
  
    db.query('SELECT * FROM eventrequests WHERE RequestID = ?', [requestID], (err, results) => {
      if (err || results.length === 0) return res.status(500).json(err || { message: 'Not found' });
  
      const event = results[0];
      const {
        EventName, Description, Location, EventDate, EventTime, RequestorID,
        MaxParticipants, MaxVolunteers, LastDateToRegister,
        DurationInHours, EventFrequency, EventDay
      } = event;
  
      const insertQuery = `
        INSERT INTO events (
          EventName, Description, Location, Date, Time, OrganizerID,
          MaxParticipants, RemainingParticipants, MaxVolunteers, RemainingVolunteers,
          Status, LastDateToRegister, DurationInHours,
          EventFrequency, EventDay, CurrentNumberOfVolunteers
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Upcoming', ?, ?, ?, ?, 0)
      `;
  
      db.query(insertQuery, [
        EventName, Description, Location, EventDate, EventTime, RequestorID,
        MaxParticipants, MaxParticipants, MaxVolunteers, MaxVolunteers,
        LastDateToRegister, DurationInHours, EventFrequency, EventDay
      ], (err2) => {
        if (err2) return res.status(500).json(err2);
  
        db.query('SELECT EventsOrganized, Points FROM users WHERE UserID = ?', [RequestorID], (err3, userResult) => {
          if (err3) return res.status(500).json(err3);
  
          const user = userResult[0];
          const newEventList = user.EventsOrganized ? user.EventsOrganized + ', ' + EventName : EventName;
          const newPoints = user.Points + (EventFrequency === 'Once' ? 500 : 1000);
  
          db.query('UPDATE users SET EventsOrganized = ?, Points = ? WHERE UserID = ?', [newEventList, newPoints, RequestorID], (err4) => {
            if (err4) return res.status(500).json(err4);
  
            db.query('UPDATE eventrequests SET Status = "Approved" WHERE RequestID = ?', [requestID], (err5) => {
              if (err5) return res.status(500).json(err5);
              res.sendStatus(200);
            });
          });
        });
      });
    });
  });

//get all events
  app.get('/events', (req, res) => {
    const query = `
      SELECT e.*, u.UserName AS OrganizerName
      FROM events e
      JOIN users u ON e.OrganizerID = u.UserID
    `;
  
    db.query(query, (err, results) => {
      if (err) {
        console.error('Database Error:', err.message);
        res.status(500).json({ error: err.message });
      } else {
        // Format the date
        const formattedResults = results.map(event => ({
          ...event,
          Date: moment(event.Date).format('YYYY-MM-DD'),
          Time: moment(event.Time, 'HH:mm:ss').format('hh:mm A'),
        }));
  
        res.json(formattedResults);
      }
    });
  });

app.get('/participation/:id', (req, res) => {
  const eventID = req.params.id;

  const query = `
    SELECT u.UserID, u.UserName 
    FROM users u
    JOIN eventparticipation ep ON u.UserID = ep.UserID
    WHERE ep.EventID = ?
  `;

  db.query(query, [eventID], (err, results) => {
    if (err) {
      console.error('Error fetching participants:', err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});
app.get('/volunteers/:id', (req, res) => {
  const eventID = req.params.id;

  const query = `
    SELECT u.UserID, u.UserName 
    FROM users u
    JOIN volunteers ev ON u.UserID = ev.UserID
    WHERE ev.EventID = ?
  `;

  db.query(query, [eventID], (err, results) => {
    if (err) {
      console.error('Error fetching volunteers:', err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// ✅ Mark an event as completed
app.put('/events/:eventId/complete', async (req, res) => {
  const eventId = req.params.eventId;
  try {
    db.query('UPDATE Events SET Status = "Completed" WHERE EventID = ?', [eventId]);
    res.json({ message: 'Event marked as completed' });
  } catch (error) {
    console.error('Error updating event status:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//for Users list for Admin

// 🔹 Get all users
app.get('/users', (req, res) => {
  const query = 'SELECT * FROM users';
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Error fetching users' });
    res.json(results);
  });
});

// 🔹 Get specific user by ID
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = 'SELECT * FROM users WHERE UserID = ?';
  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error fetching user' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(results[0]);
  });
});

// 🔹 Update user score using POST
app.post('/update-score', (req, res) => {
  const { userId, points } = req.body;

  if (typeof points !== 'number' || !userId) {
    return res.status(400).json({ error: 'Invalid data' });
  }

  const query = 'UPDATE users SET points = ? WHERE UserID = ?';
  db.query(query, [points, userId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Error updating score' });
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Score updated successfully' });
  });
});
  // Serve static files
  app.use(express.static('public'));
// ✅ Start the Server
app.listen(port, () => {
    console.log(`✅ Server running on http://localhost:${port}`);
});
