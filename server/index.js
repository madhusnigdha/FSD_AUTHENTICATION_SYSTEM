const dotenv = require('dotenv');
dotenv.config(); // Must be at the very top

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const csrf = require('csurf');
const axios = require('axios'); // <-- Our new http client
const { protect, admin } = require('./middleware/authMiddleware');
const User = require('./models/User');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 5000;

// --- Middlewares ---
app.use(cors({
  origin: 'http://localhost:3000', 
  credentials: true 
}));
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());
// --- Removed passport.initialize() ---

// General rate limiter for most routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP, please try again after 15 minutes',
});

// Stricter rate limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 10, // Limit each IP to 10 auth-related requests per window
  message: 'Too many authentication attempts, please try again after 30 minutes',
});

// Apply the general limiter to all routes starting with /api
app.use('/api', apiLimiter);

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Successfully connected to MongoDB!"))
  .catch((error) => console.error("❌ Error connecting to MongoDB:", error.message));

// --- Basic Test Route ---
app.get('/api', (req, res) => {
  res.json({ message: "Hello from the Nimbus server!" });
});


// ===================================
// ===     MANUAL PKCE AUTH        ===
// ===================================
const googleAuthValidation = [
  authLimiter,
  body('code').notEmpty().isString().withMessage('Authorization code must be a non-empty string'),
  body('verifier').notEmpty().isString().withMessage('PKCE verifier must be a non-empty string'),
  body('nonce').notEmpty().isString().withMessage('Nonce must be a non-empty string') // <-- ADD THIS
];

app.post('/auth/google', googleAuthValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { code, verifier, nonce } = req.body;

  if (!code || !verifier || !nonce) { // <-- 2. Update check
    return res.status(400).json({ message: 'Code, verifier, and nonce are required.' });
  }

  try {
    // --- 1. Exchange the code for tokens (Same as before) ---
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', null, {
      params: {
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code: code,
        code_verifier: verifier,
        grant_type: 'authorization_code',
        redirect_uri: 'http://localhost:3000/auth/callback',
      },
    });

    const { id_token } = tokenResponse.data;

    // --- 2. Get user profile (Same as before) ---
    const profile = jwt.decode(id_token);
    if (!profile) {
      return res.status(400).json({ message: 'Invalid ID token' });
    }

    // --- 3. VALIDATE NONCE (CRITICAL!) ---
    if (profile.nonce !== nonce) {
      return res.status(401).json({ message: 'Invalid nonce. Replay attack suspected.' });
    }

    // --- 4. Find or Create User (Same as before) ---
    let user = await User.findOne({ 'providers.googleId': profile.sub });
    if (!user) {
      user = new User({
        email: profile.email,
        name: profile.name,
        providers: { googleId: profile.sub }
      });
      await user.save();
    }

    // --- 5. CREATE *TWO* JWTs (This is the new part) ---
    const userPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    };
    
    // Create the Access Token (15 minutes)
    const accessToken = jwt.sign(
      userPayload, 
      process.env.JWT_ACCESS_SECRET, 
      { expiresIn: process.env.JWT_ACCESS_EXPIRATION }
    );

    // Create the Refresh Token (7 days)
    const refreshToken = jwt.sign(
      userPayload, // You can have a simpler payload for the refresh token
      process.env.JWT_REFRESH_SECRET, 
      { expiresIn: process.env.JWT_REFRESH_EXPIRATION }
    );

    // --- 6. Set the REFRESH token as an httpOnly cookie ---
    // We rename the cookie to 'refreshToken'
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false, // Set to true if on HTTPS
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days (must match token expiry)
    });

    // --- 7. Send the ACCESS token in the JSON response ---
    res.status(200).json({ 
      message: 'Login successful',
      accessToken: accessToken // Send the access token to the client
    });

  } catch (err) {
    console.error('Error during Google auth:', err.response ? err.response.data : err.message);
    res.status(500).json({ message: 'Authentication failed.' });
  }
});


// ===================================
// ===   CSRF & PROTECTED ROUTES   ===
// ===================================
// We initialize CSRF protection *after* our /auth/google route
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// --- 3. The "Me" (Check Auth) Route ---
// This route is protected by 'protect' and 'csrfProtection'
app.get('/api/user/me', protect, (req, res) => {
  res.status(200).json({
    id: req.user.id,
    email: req.user.email,
    name: req.user.name,
    role: req.user.role,
    csrfToken: req.csrfToken() // Send the CSRF token
  });
});

// ===================================
// ===     REFRESH TOKEN ROUTE     ===
// ===================================
// This route is protected by CSRF but not 'protect'
// It does its own JWT verification.
app.post('/auth/refresh', authLimiter, (req, res) => {
  // 1. Get the refresh token from the httpOnly cookie
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided.' });
  }

  try {
    // 2. Verify the refresh token
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET
    );

    // 3. The token is valid, so create a new *access* token
    const userPayload = {
      id: decoded.id,
      email: decoded.email,
      name: decoded.name,
      role: decoded.role
    };

    const newAccessToken = jwt.sign(
      userPayload,
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRATION }
    );

    // 4. Send the new access token (and a new CSRF token)
    // The client will need a new CSRF token for its *next* request
    res.status(200).json({
      message: 'Access token refreshed',
      accessToken: newAccessToken,
      csrfToken: req.csrfToken() // Send a new CSRF token
    });

  } catch (err) {
    // If the refresh token is invalid or expired
    console.error('Error refreshing token:', err.message);
    return res.status(403).json({ message: 'Invalid refresh token.' });
  }
});

// --- 4. The "Admin-Only" Route ---
// Also protected by both
app.get('/api/admin/users', protect, admin, async (req, res) => {
  try {
    const users = await User.find({});
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json({ message: 'Server Error' });
  }
});

// --- 5. The "Logout" Route ---
app.post('/auth/logout', authLimiter, protect, (req, res) => {
  // --- UPDATE THIS LINE ---
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
  });
  res.status(200).json({ message: 'Logged out successfully' });
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});