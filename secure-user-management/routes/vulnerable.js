import express from 'express';
import { vulnerableDb } from '../config/db.js';

const router = express.Router();

// Vulnerable login - SQL Injection vulnerability
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Simulating SQL injection vulnerability
  // In a real SQL database with a query like:
  // SELECT * FROM users WHERE username = '{username}' AND password = '{password}'
  console.log(`Vulnerable query: SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`);
  
  // Simulating SQL injection bypass
  if (username.includes("' --")) {
    const injectedUsername = username.split("'")[0];
    const user = vulnerableDb.findUser(injectedUsername);
    
    if (user) {
      // Create session (insecurely)
      const sessionId = vulnerableDb.createSession(user.id, user.username, user.role);
      
      return res.json({ 
        success: true, 
        message: 'SQL injection successful!', 
        sessionId,
        username: user.username,
        role: user.role
      });
    }
  }
  
  // Normal login flow
  const user = vulnerableDb.findUser(username);
  if (!user) {
    return res.json({ success: false, message: 'Invalid username or password' });
  }
  
  // Weak password verification using MD5
  const passwordHash = require('crypto').createHash('md5').update(password).digest('hex');
  if (user.passwordHash !== passwordHash) {
    return res.json({ success: false, message: 'Invalid username or password' });
  }
  
  // Create session (insecurely)
  const sessionId = vulnerableDb.createSession(user.id, user.username, user.role);
  
  res.json({ 
    success: true, 
    sessionId,
    username: user.username,
    role: user.role
  });
});

// Vulnerable register - weak password storage
router.post('/register', (req, res) => {
  const { username, password } = req.body;
  
  // Check if username exists
  const existingUser = vulnerableDb.findUser(username);
  if (existingUser) {
    return res.json({ success: false, message: 'Username already exists' });
  }
  
  // Create user with weak password hashing
  const newUser = vulnerableDb.createUser(username, password);
  
  // Create session
  const sessionId = vulnerableDb.createSession(newUser.id, newUser.username, newUser.role);
  
  res.json({ 
    success: true, 
    sessionId,
    username: newUser.username,
    role: newUser.role
  });
});

// Vulnerable comment system - XSS vulnerability
router.post('/comments', (req, res) => {
  const { sessionId, content } = req.body;
  
  // Check session
  const session = vulnerableDb.getSession(sessionId);
  if (!session) {
    return res.json({ success: false, message: 'Not authenticated' });
  }
  
  // No XSS protection - content is stored as-is
  const newComment = vulnerableDb.addComment(session.username, content); // No sanitization
  
  res.json({ success: true, comment: newComment });
});

router.get('/comments', (req, res) => {
  const comments = vulnerableDb.getComments();
  res.json({ success: true, comments });
});

// Vulnerable admin check - poor access control
router.get('/admin-check', (req, res) => {
  const { sessionId } = req.query;
  
  // Check session
  const session = vulnerableDb.getSession(sessionId);
  if (!session) {
    return res.json({ success: false, message: 'Not authenticated' });
  }
  
  // No proper role check - just returns true if authenticated
  res.json({ success: true, isAdmin: true });
});

export default router;