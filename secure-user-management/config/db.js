import crypto from 'crypto';

// Simulated database
const db = {
  users: [
    {
      id: 1,
      username: 'admin',
      // MD5 hash of 'password123'
      passwordHash: '482c811da5d5b4bc6d497ffa98491e38',
      role: 'admin'
    }
  ],
  comments: [
    {
      id: 1,
      username: 'admin',
      content: 'Welcome to our community!'
    }
  ],
  sessions: {}
};

// Helper functions for vulnerable implementation
export const vulnerableDb = {
  findUser: (username) => {
    return db.users.find(u => u.username === username);
  },
  
  createUser: (username, password) => {
    // Weak password hashing using MD5
    const passwordHash = crypto.createHash('md5').update(password).digest('hex');
    
    const newUser = {
      id: db.users.length + 1,
      username,
      passwordHash,
      role: 'user'
    };
    
    db.users.push(newUser);
    return newUser;
  },
  
  createSession: (userId, username, role) => {
    const sessionId = Math.random().toString(36).substring(2);
    db.sessions[sessionId] = { userId, username, role };
    return sessionId;
  },
  
  getSession: (sessionId) => {
    return db.sessions[sessionId];
  },
  
  removeSession: (sessionId) => {
    delete db.sessions[sessionId];
  },
  
  getComments: () => {
    return [...db.comments];
  },
  
  addComment: (username, content) => {
    const newComment = {
      id: db.comments.length + 1,
      username,
      content
    };
    
    db.comments.push(newComment);
    return newComment;
  }
};

// Helper functions for secure implementation
export const secureDb = {
  findUser: (username) => {
    return db.users.find(u => u.username === username);
  },
  
  createUser: (username, password) => {
    // Secure password hashing with salt
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto
      .pbkdf2Sync(password, salt, 1000, 64, 'sha512')
      .toString('hex');
    
    const newUser = {
      id: db.users.length + 1,
      username,
      passwordHash: `${salt}:${passwordHash}`,
      role: 'user'
    };
    
    db.users.push(newUser);
    return newUser;
  },
  
  verifyPassword: (password, storedHash) => {
    // For admin with MD5 hash (for demo purposes)
    if (!storedHash.includes(':')) {
      const passwordHash = crypto.createHash('md5').update(password).digest('hex');
      return passwordHash === storedHash;
    }
    
    // For secure hashed passwords
    const [salt, hash] = storedHash.split(':');
    const passwordHash = crypto
      .pbkdf2Sync(password, salt, 1000, 64, 'sha512')
      .toString('hex');
    
    return passwordHash === hash;
  },
  
  createSession: (userId, username, role) => {
    const sessionId = crypto.randomBytes(32).toString('hex');
    db.sessions[sessionId] = { 
      userId, 
      username, 
      role,
      expires: Date.now() + 3600000 // 1 hour expiration
    };
    return sessionId;
  },
  
  getSession: (sessionId) => {
    const session = db.sessions[sessionId];
    
    if (!session) {
      return null;
    }
    
    // Check expiration
    if (session.expires && session.expires < Date.now()) {
      delete db.sessions[sessionId];
      return null;
    }
    
    return session;
  },
  
  removeSession: (sessionId) => {
    delete db.sessions[sessionId];
  },
  
  getComments: () => {
    return [...db.comments];
  },
  
  addComment: (username, content) => {
    // Sanitize content to prevent XSS
    const sanitizedContent = content
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
      .replace(/script/gi, 'blocked')
      .replace(/onerror/gi, 'blocked')
      .replace(/onclick/gi, 'blocked')
      .replace(/onload/gi, 'blocked');
    
    const newComment = {
      id: db.comments.length + 1,
      username,
      content: sanitizedContent
    };
    
    db.comments.push(newComment);
    return newComment;
  }
};