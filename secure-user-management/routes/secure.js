import express from 'express';
import { secureDb } from '../config/db.js';

const router = express.Router();

// Secure login - protected against SQL injection
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.json({ success: false, message: 'Username and password are required' });
  }
  
  // Using parameterized query pattern to prevent SQL injection
  console.log('Secure query would use parameterized query with username and password as parameters');
  
  // Find user (safely)
  const user = secureDb.findUser(username);
  if (!user) {
    // Use generic error message to prevent username enumeration
    return res.json({ success: false, message: 'Invalid username or password' });
  }
  
  // Verify password securely
  const passwordValid = secureDb.verifyPassword(password, user.passwordHash);
  if (!passwordValid) {
    // Use generic error message to prevent username enumeration
    return res.json({ success: false, message: 'Invalid username or password' });
  }
  
  // Create secure session with expiration
  const sessionId = secureDb.createSession(user.id, user.username, user.role);
  
  res.json({ 
    success: true, 
    sessionId,
    username: user.username,
    role: user.role
  });
});

// Secure register - strong password hashing
router.post('/register', (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.json({ success: false, message: 'Username and password are required' });
  }
  
  // Username validation
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.json({ 
      success: false, 
      message: 'Username must be 3-20 characters and can only contain letters, numbers, and underscores' 
    });
  }
  
  // Password strength validation
  if (password.length < 8) {
    return res.json({ success: false, message: 'Password must be at least 8 characters' });
  }
  
  if (!/[A-Z]/.test(password)) {
    return res.json({ success: false, message: 'Password must contain at least one uppercase letter' });
  }
  
  if (!/[a-z]/.test(password)) {
    return res.json({ success: false, message: 'Password must contain at least one lowercase letter' });
  }
  
  if (!/[0-9]/.test(password)) {
    return res.json({ success: false, message: 'Password must contain at least one number' });
  }
  
  if (!/[^A-Za-z0-9]/.test(password)) {
    return res.json({ success: false, message: 'Password must contain at least one special character' });
  }
  
  // Check if username exists
  const existingUser = secureDb.findUser(username);
  if (existingUser) {
    return res.json({ success: false, message: 'Username already exists' });
  }
  
  // Create user with secure password hashing
  const newUser = secureDb.createUser(username, password);
  
  // Create secure session with expiration
  const sessionId = secureDb.createSession(newUser.id, newUser.username, newUser.role);
  
  res.json({ 
    success: true, 
    sessionId,
    username: newUser.username,
    role: newUser.role
  });
});

// Secure comment system - XSS protection
router.post('/comments', (req, res) => {
  const { sessionId, content } = req.body;
  
  // Check session
  const session = secureDb.getSession(sessionId);
  if (!session) {
    return res.json({ success: false, message: 'Not authenticated' });
  }
  
  // Input validation
  if (!content || content.trim() === '') {
    return res.json({ success: false, message: 'Comment content is required' });
  }
  
  // Add comment with XSS protection
  const newComment = secureDb.addComment(session.username, content);
  
  res.json({ success: true, comment: newComment });
});

router.get('/comments', (req, res) => {
  const comments = secureDb.getComments();
  res.json({ success: true, comments });
});

// Secure admin check - proper role-based access control
router.get('/admin-check', (req, res) => {
  const { sessionId } = req.query;
  
  // Check session
  const session = secureDb.getSession(sessionId);
  if (!session) {
    return res.json({ success: false, message: 'Not authenticated' });
  }
  
  // Proper role check
  const isAdmin = session.role === 'admin';
  
  res.json({ success: true, isAdmin });
});

export default router;