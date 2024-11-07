const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const winston = require('winston');
const path = require('path');

const app = express();
const port = process.env.PORT; // Use Azure-provided PORT only

// In-memory database for users (for demo purposes)
const users = [];

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Set up session
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key', // Use environment variable for session secret
  resave: false,
  saveUninitialized: true
}));

// Set up winston logger
const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.Console({
      format: winston.format.simple(),
    }),
    new winston.transports.File({ filename: 'logs/app.log' }) // Optional: Log to file
  ],
});

// Middleware to log requests
app.use((req, res, next) => {
  logger.info(`Request received: ${req.method} ${req.url}`);
  next();
});

// Home route
app.get('/', (req, res) => {
  res.render('index', { loggedIn: req.session.user });
});

// Register route
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if user already exists
  const userExists = users.some(user => user.username === username);
  if (userExists) {
    logger.error(`Registration failed: User ${username} already exists`);
    return res.send('User already exists');
  }

  // Hash the password and save the user
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  logger.info(`User registered: ${username}`);

  res.redirect('/login');
});

// Login route
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Find the user
  const user = users.find(u => u.username === username);
  if (!user) {
    logger.error(`Login failed: User ${username} not found`);
    return res.send('User not found');
  }

  // Compare password with the hashed one
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    logger.error(`Login failed: Incorrect password for user ${username}`);
    return res.send('Invalid credentials');
  }

  // Save session and log successful login
  req.session.user = username;
  logger.info(`User logged in successfully: ${username}`);
  
  res.redirect('/profile');
});

// Profile route
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const user = users.find(u => u.username === req.session.user);
  res.render('profile', { username: user.username, password: user.password });
});

// Logout route
app.get('/logout', (req, res) => {
  const username = req.session.user;
  req.session.destroy((err) => {
    if (err) {
      logger.error(`Logout error for user ${username}`);
      return res.send('Error logging out');
    }
    logger.info(`User logged out: ${username}`);
    res.redirect('/');
  });
});

// Start the server using only the Azure-provided port
app.listen(port, () => {
  logger.info(`Server running on port ${port}`);
});
