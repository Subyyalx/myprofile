const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const winston = require('winston');

const app = express();
const port = 3000;

// In-memory database for users (for demo purposes)
const users = [];

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Set up session
app.use(session({
  secret: 'secret-key',
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
    return res.send('User not found');
  }

  // Compare password with the hashed one
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.send('Invalid credentials');
  }

  // Save session
  req.session.user = username;
  logger.info(`User logged in: ${username}`);
  
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
  req.session.destroy((err) => {
    if (err) {
      return res.send('Error logging out');
    }
    res.redirect('/');
  });
});

// Start the server
app.listen(port, () => {
  logger.info(`Server running on http://localhost:${port}`);
});
