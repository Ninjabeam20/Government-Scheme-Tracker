require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.SESSION_SECRET || 'secret_key_change_this';

// 1. Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('❌ Database Connection Failed:', err.stack);
        return;
    }
    console.log('✅ Connected to MySQL Database');
});

// 2. Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json()); // To parse JSON bodies
app.use(bodyParser.urlencoded({ extended: true })); // To parse form data
app.use(cookieParser());
app.use(passport.initialize());

// Helper Function: Generate JWT
const generateToken = (user) => {
    return jwt.sign(
        { id: user.UserID, role: user.Role, name: user.Name }, 
        JWT_SECRET, 
        { expiresIn: '1h' }
    );
};

// ---------------------------------------------------------
// 3. AUTHENTICATION ROUTES (Manual)
// ---------------------------------------------------------

// POST /register (Handle Sign Up Form)
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    // 1. Check if user already exists
    const checkQuery = 'SELECT * FROM Beneficiaries WHERE Email = ?';
    db.query(checkQuery, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        if (results.length > 0) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        // 2. Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Insert into Database
        const insertQuery = 'INSERT INTO Beneficiaries (Name, Email, Password, Status) VALUES (?, ?, ?, ?)';
        db.query(insertQuery, [name, email, hashedPassword, 'Active'], (err, result) => {
            if (err) {
                console.error("Insert Error:", err);
                return res.status(500).json({ error: 'Failed to register user' });
            }
            console.log("✅ New User Registered:", name);
            
            // 4. Auto-Login: Generate Token
            const token = generateToken({ UserID: result.insertId, Role: 'Beneficiary', Name: name });
            res.cookie('auth_token', token, { httpOnly: true });
            res.json({ success: true, message: 'Registration Successful' });
        });
    });
});

// POST /login (Handle Login Form)
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // We need to check 3 tables: Admins, Officers, Beneficiaries. 
    // For simplicity, we check Beneficiaries first (since that's the main issue).
    // In a full app, you'd chain these checks.
    
    const query = 'SELECT * FROM Beneficiaries WHERE Email = ?';
    
    db.query(query, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }

        const user = results[0];

        // If user registered with Google, they have no password
        if (!user.Password) {
            return res.status(400).json({ error: 'Please login with Google' });
        }

        // Check Password
        const isMatch = await bcrypt.compare(password, user.Password);
        
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid Credentials' });
        }

        console.log("✅ User Logged In:", user.Name);

        // Generate JWT
        const token = generateToken({ UserID: user.BeneficiaryID, Role: 'Beneficiary', Name: user.Name });
        
        // Send Token in HTTP-Only Cookie
        res.cookie('auth_token', token, { httpOnly: true });
        res.json({ success: true });
    });
});

// ---------------------------------------------------------
// 4. GOOGLE OAUTH STRATEGY (Updated for JWT)
// ---------------------------------------------------------
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
      const email = profile.emails[0].value;
      const googleId = profile.id;
      const name = profile.displayName;

      db.query('SELECT * FROM Beneficiaries WHERE Email = ?', [email], (err, results) => {
          if (err) return done(err);

          if (results.length > 0) {
              // User Exists
              const user = results[0];
              if (!user.GoogleID) {
                  db.query('UPDATE Beneficiaries SET GoogleID = ? WHERE Email = ?', [googleId, email]);
              }
              return done(null, user);
          } else {
              // Create New User
              const newUser = { Name: name, Email: email, GoogleID: googleId, Status: 'Active' };
              db.query('INSERT INTO Beneficiaries SET ?', newUser, (err, res) => {
                  if (err) return done(err);
                  newUser.BeneficiaryID = res.insertId;
                  return done(null, newUser);
              });
          }
      });
  }
));

// Google Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { session: false, failureRedirect: '/' }),
    (req, res) => {
        // Generate JWT for Google User
        const user = req.user;
        const token = generateToken({ UserID: user.BeneficiaryID, Role: 'Beneficiary', Name: user.Name });
        
        res.cookie('auth_token', token, { httpOnly: true });
        res.redirect('/dashboard');
    }
);

// ---------------------------------------------------------
// 5. PROTECTED ROUTES
// ---------------------------------------------------------

// Middleware to Verify JWT
const verifyToken = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.redirect('/');

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.redirect('/');
        req.user = decoded;
        next();
    });
};

app.get('/dashboard', verifyToken, (req, res) => {
    res.send(`
        <h1 style="font-family:sans-serif">Welcome to Dashboard, ${req.user.name}</h1>
        <p>Your Role: ${req.user.role}</p>
        <a href="/logout">Logout</a>
    `);
});

app.get('/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.redirect('/');
});

// Serve HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------
// NEW DASHBOARD ROUTES
// ---------------------------------------------------------

// 1. Route to serve the Dashboard HTML
app.get('/dashboard', verifyToken, (req, res) => {
    // This sends the file we just created
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// 2. API Endpoint: Get Current User Info
// The frontend calls this to know "Who am I?" (Citizen? Officer?)
app.get('/api/user-info', verifyToken, (req, res) => {
    // req.user comes from the 'verifyToken' middleware we wrote earlier
    res.json({ 
        success: true, 
        user: req.user 
    });
});


app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});