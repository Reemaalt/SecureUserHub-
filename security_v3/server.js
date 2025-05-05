// Simple Express server for security demonstration
const express = require("express")
const bodyParser = require("body-parser")
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express()
const PORT = 3000

// Middleware
app.use(bodyParser.json())
app.use(express.static(".")) // Serve static files from current directory

// Set up SQLite database
const db = new sqlite3.Database("./security_demo.db", (err) => {
  if (err) {
    console.error("Error opening database", err.message);
  } else {
    console.log("Connected to the SQLite database.");
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  // Create users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  // Create comments table
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  // Create sessions table
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires BIGINT,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);
  // Insert admin user if not exists
  const adminPasswordHash = crypto.createHash("md5").update("password123").digest("hex");
  
  db.get("SELECT * FROM users WHERE username = ?", ["admin"], (err, row) => {
    if (err) {
      console.error("Error checking admin user:", err.message);
    } else if (!row) {
      db.run(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ["admin", adminPasswordHash, "admin"],
        function(err) {
          if (err) {
            console.error("Error creating admin user:", err.message);
          } else {
            console.log("Admin user created with ID:", this.lastID);
         
          }
        }
      );
    }
  });
}
// ==========================================
// VULNERABLE API ENDPOINTS
// ==========================================

// Vulnerable Register (SQL Injection vulnerability in direct string interpolation)
app.post("/api/vulnerable/register", (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username is provided
    if (!username || username.trim() === "") {
      return res.status(400).json({ success: false, message: "Username is required" });
    }

    // Check if password is provided
    if (!password || password.trim() === "") {
      return res.status(400).json({ success: false, message: "Password is required" });
    }

    // Weak password hashing using MD5 (VULNERABLE)
    const passwordHash = crypto.createHash("md5").update(password).digest("hex");

    // VULNERABLE: SQL Injection possible due to direct string interpolation
    const query = `INSERT INTO users (username, password_hash, role) 
                   VALUES ('${username}', '${passwordHash}', 'user')`;
    
    db.run(query, function(err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(400).json({ success: false, message: "Username already exists" });
        }
        console.error("Registration error:", err.message);
        return res.status(500).json({ success: false, message: "Registration failed" });
      }
      
      const userId = this.lastID;
           // Create session (no expiration)
           const sessionId = Math.random().toString(36).substring(2);
      
           db.run(
             "INSERT INTO sessions (session_id, user_id, username, role) VALUES (?, ?, ?, ?)",
             [sessionId, userId, username, "user"],
             (err) => {
               if (err) {
                 console.error("Session creation error:", err.message);
                 return res.status(500).json({ success: false, message: "Session creation failed" });
               }
               
               res.json({
                 success: true,
                 message: "Registration successful",
                 username: username,
                 role: "user",
                 sessionId: sessionId,
               });
             }
           );
         });
       } catch (error) {
         console.error("Registration error:", error);
         res.status(500).json({ success: false, message: "Registration failed" });
       }
     });

// Vulnerable Login (SQL Injection vulnerability)
app.post("/api/vulnerable/login", (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username and password are provided
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required" });
    }

    // VULNERABLE: SQL Injection possible due to direct string interpolation
    const query = `SELECT * FROM users WHERE username = '${username}'`;
  
    db.get(query, (err, user) => {
      if (err) {
        console.error("Login error:", err.message);
        return res.status(500).json({ success: false, message: "Login failed" });
      }

      if (!user) {
        return res.status(401).json({ success: false, message: "Invalid username or password" });
      }

      // Weak password verification (MD5)
      const passwordHash = crypto.createHash("md5").update(password).digest("hex");

      if (passwordHash !== user.password_hash) {
        return res.status(401).json({ success: false, message: "Invalid username or password" });
      }

      // Create session (no expiration)
      const sessionId = Math.random().toString(36).substring(2);
      
      db.run(
        "INSERT INTO sessions (session_id, user_id, username, role) VALUES (?, ?, ?, ?)",
        [sessionId, user.id, user.username, user.role],
        (err) => {
          if (err) {
            console.error("Session creation error:", err.message);
            return res.status(500).json({ success: false, message: "Session creation failed" });
          }
          
          res.json({
            success: true,
            message: "Login successful",
            username: user.username,
            role: user.role,
            sessionId: sessionId,
          });
        }
      );
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

// Vulnerable Comments - Get
app.get("/api/vulnerable/comments", (req, res) => {
  try {
    db.all("SELECT * FROM comments ORDER BY id DESC", (err, comments) => {
      if (err) {
        console.error("Error getting comments:", err.message);
        return res.status(500).json({ success: false, message: "Failed to get comments" });
      }
      
      res.json({
        success: true,
        comments: comments,
      });
    });
  } catch (error) {
    console.error("Error getting comments:", error);
    res.status(500).json({ success: false, message: "Failed to get comments" });
  }
});

// Vulnerable Comments - Post (vulnerable to XSS)
app.post("/api/vulnerable/comments", (req, res) => {
  try {
    const { sessionId, content } = req.body;

    // Check if content is provided
    if (!content || content.trim() === "") {
      return res.status(400).json({ success: false, message: "Comment content is required" });
    }

    // Check if session exists
    db.get("SELECT * FROM sessions WHERE session_id = ?", [sessionId], (err, session) => {
      if (err) {
        console.error("Session check error:", err.message);
        return res.status(500).json({ success: false, message: "Failed to verify session" });
      }

      if (!session) {
        return res.status(401).json({ success: false, message: "Invalid session" });
      }

      // Add comment (vulnerable to XSS - no content sanitization)
      db.run(
        "INSERT INTO comments (username, content) VALUES (?, ?)",
        [session.username, content], // No sanitization!
        function(err) {
          if (err) {
            console.error("Error adding comment:", err.message);
            return res.status(500).json({ success: false, message: "Failed to add comment" });
          }
          
          const newComment = {
            id: this.lastID,
            username: session.username,
            content: content,
          };
          
          res.json({
            success: true,
            comment: newComment,
          });
        }
      );
    });
  } catch (error) {
    console.error("Error adding comment:", error);
    res.status(500).json({ success: false, message: "Failed to add comment" });
  }
});

// Vulnerable Admin Check (broken access control)
app.get("/api/vulnerable/admin-check", (req, res) => {
  try {
    const { sessionId } = req.query;

    if (!sessionId) {
      return res.status(400).json({ success: false, message: "Session ID is required" });
    }

    // Check if session exists
    db.get("SELECT * FROM sessions WHERE session_id = ?", [sessionId], (err, session) => {
      if (err) {
        console.error("Session check error:", err.message);
        return res.status(500).json({ success: false, message: "Failed to verify session" });
      }

      // VULNERABLE: Always returns isAdmin: true if session exists
      // This is a deliberate access control vulnerability
      if (session) {
        return res.json({
          success: true,
          isAdmin: true, // Always returns true regardless of actual role
        });
      }

      res.status(401).json({ success: false, message: "Invalid session" });
    });
  } catch (error) {
    console.error("Admin check error:", error);
    res.status(500).json({ success: false, message: "Admin check failed" });
  }
});


// ==========================================
// SECURE API ENDPOINTS
// ==========================================

// Secure Register
app.post("/api/secure/register", (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username is provided
    if (!username || username.trim() === "") {
      return res.status(400).json({ success: false, message: "Username is required" });
    }

    // Check if password is provided
    if (!password || password.trim() === "") {
      return res.status(400).json({ success: false, message: "Password is required" });
    }

    // Password strength validation
    const hasMinLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[^A-Za-z0-9]/.test(password);

    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasNumber || !hasSpecialChar) {
      return res.status(400).json({
        success: false,
        message: "Password does not meet security requirements",
      });
    }

    // Check if username already exists - SECURE: Using parameterized query
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, existingUser) => {
      if (err) {
        console.error("Username check error:", err.message);
        return res.status(500).json({ success: false, message: "Registration failed" });
      }

      if (existingUser) {
        return res.status(400).json({ success: false, message: "Username already exists" });
      }

      // Secure password hashing with salt
      const salt = crypto.randomBytes(16).toString("hex");
      const passwordHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
      const combinedHash = `${salt}:${passwordHash}`;

      // SECURE: Using parameterized query
      db.run(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        [username, combinedHash, "user"],
        function(err) {
          if (err) {
            console.error("User creation error:", err.message);
            return res.status(500).json({ success: false, message: "Registration failed" });
          }
          
          const userId = this.lastID;
          
          // Create session with expiration
          const sessionId = crypto.randomBytes(32).toString("hex");
          const expires = Date.now() + 3600000; // 1 hour expiration
          
          // SECURE: Using parameterized query
          db.run(
            "INSERT INTO sessions (session_id, user_id, username, role, expires) VALUES (?, ?, ?, ?, ?)",
            [sessionId, userId, username, "user", expires],
            (err) => {
              if (err) {
                console.error("Session creation error:", err.message);
                return res.status(500).json({ success: false, message: "Session creation failed" });
              }
              
              res.json({
                success: true,
                message: "Registration successful",
                username: username,
                role: "user",
                sessionId: sessionId,
              });
            }
          );
        }
      );
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ success: false, message: "Registration failed" });
  }
});

// Secure Login with rate limiting
const loginAttempts = {}; // Store login attempts by IP

app.post("/api/secure/login", (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = req.ip; // Get client IP for rate limiting

    // Check if username and password are provided
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required" });
    }

    // Rate limiting check
    if (!loginAttempts[ip]) {
      loginAttempts[ip] = {
        count: 0,
        lockUntil: 0,
      };
    }

    // Check if IP is locked
    if (loginAttempts[ip].lockUntil > Date.now()) {
      const remainingSeconds = Math.ceil((loginAttempts[ip].lockUntil - Date.now()) / 1000);
      return res.status(429).json({
        success: false,
        message: `Too many login attempts. Try again in ${remainingSeconds} seconds.`,
        locked: true,
        lockTimer: remainingSeconds,
      });
    }

    // SECURE: Using parameterized query
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
      if (err) {
        console.error("Login error:", err.message);
        return res.status(500).json({ success: false, message: "Login failed" });
      }

      // Check if user exists
      if (!user) {
        // Increment failed attempts
        loginAttempts[ip].count++;

        // Lock account after 5 failed attempts
        if (loginAttempts[ip].count >= 5) {
          loginAttempts[ip].lockUntil = Date.now() + 60000; // 1 minute lockout
          return res.status(429).json({
            success: false,
            message: "Too many failed login attempts. Account locked for 60 seconds.",
            locked: true,
            lockTimer: 60,
          });
        }

        return res.status(401).json({
          success: false,
          message: "Invalid username or password",
          attempts: loginAttempts[ip].count,
        });
      }

      // Secure password verification
      let isPasswordValid = false;

      // For admin with MD5 hash (for demo purposes)
      if (!user.password_hash.includes(":")) {
        const passwordHash = crypto.createHash("md5").update(password).digest("hex");
        isPasswordValid = passwordHash === user.password_hash;
      } else {
        // For secure hashed passwords
        const [salt, hash] = user.password_hash.split(":");
        const passwordHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
        isPasswordValid = passwordHash === hash;
      }

      if (!isPasswordValid) {
        // Increment failed attempts
        loginAttempts[ip].count++;

        // Lock account after 5 failed attempts
        if (loginAttempts[ip].count >= 5) {
          loginAttempts[ip].lockUntil = Date.now() + 60000; // 1 minute lockout
          return res.status(429).json({
            success: false,
            message: "Too many failed login attempts. Account locked for 60 seconds.",
            locked: true,
            lockTimer: 60,
          });
        }

        return res.status(401).json({
          success: false,
          message: "Invalid username or password",
          attempts: loginAttempts[ip].count,
        });
      }

      // Reset login attempts on successful login
      loginAttempts[ip].count = 0;

      // Create session with expiration
      const sessionId = crypto.randomBytes(32).toString("hex");
      const expires = Date.now() + 3600000; // 1 hour expiration
      
      // SECURE: Using parameterized query
      db.run(
        "INSERT INTO sessions (session_id, user_id, username, role, expires) VALUES (?, ?, ?, ?, ?)",
        [sessionId, user.id, user.username, user.role, expires],
        (err) => {
          if (err) {
            console.error("Session creation error:", err.message);
            return res.status(500).json({ success: false, message: "Session creation failed" });
          }
          
          res.json({
            success: true,
            message: "Login successful",
            username: user.username,
            role: user.role,
            sessionId: sessionId,
          });
        }
      );
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

// Secure Comments - Get
app.get("/api/secure/comments", (req, res) => {
  try {
    // SECURE: Using parameterized query (though not needed here as no user input)
    db.all("SELECT * FROM comments ORDER BY id DESC", (err, comments) => {
      if (err) {
        console.error("Error getting comments:", err.message);
        return res.status(500).json({ success: false, message: "Failed to get comments" });
      }
      
      res.json({
        success: true,
        comments: comments,
      });
    });
  } catch (error) {
    console.error("Error getting comments:", error);
    res.status(500).json({ success: false, message: "Failed to get comments" });
  }
});

// Secure Comments - Post (with XSS prevention)
app.post("/api/secure/comments", (req, res) => {
  try {
    const { sessionId, content } = req.body;

    // Check if content is provided
    if (!content || content.trim() === "") {
      return res.status(400).json({ success: false, message: "Comment content is required" });
    }

    // Check if session exists and is valid
    db.get("SELECT * FROM sessions WHERE session_id = ?", [sessionId], (err, session) => {
      if (err) {
        console.error("Session check error:", err.message);
        return res.status(500).json({ success: false, message: "Failed to verify session" });
      }

      if (!session) {
        return res.status(401).json({ success: false, message: "Invalid session" });
      }

      // Check session expiration
      if (session.expires && session.expires < Date.now()) {
        db.run("DELETE FROM sessions WHERE session_id = ?", [sessionId]);
        return res.status(401).json({ success: false, message: "Session expired" });
      }

      // Sanitize content to prevent XSS
      const sanitizedContent = content
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .replace(/script/gi, "blocked")
        .replace(/onerror/gi, "blocked")
        .replace(/onclick/gi, "blocked")
        .replace(/onload/gi, "blocked");

      // SECURE: Using parameterized query with sanitized content
      db.run(
        "INSERT INTO comments (username, content) VALUES (?, ?)",
        [session.username, sanitizedContent],
        function(err) {
          if (err) {
            console.error("Error adding comment:", err.message);
            return res.status(500).json({ success: false, message: "Failed to add comment" });
          }
          
          const newComment = {
            id: this.lastID,
            username: session.username,
            content: sanitizedContent,
          };
          
          res.json({
            success: true,
            comment: newComment,
          });
        }
      );
    });
  } catch (error) {
    console.error("Error adding comment:", error);
    res.status(500).json({ success: false, message: "Failed to add comment" });
  }
});

// Secure Admin Check
app.get("/api/secure/admin-check", (req, res) => {
  try {
    const { sessionId } = req.query;

    if (!sessionId) {
      return res.status(400).json({ success: false, message: "Session ID is required" });
    }

    // SECURE: Using parameterized query
    db.get("SELECT * FROM sessions WHERE session_id = ?", [sessionId], (err, session) => {
      if (err) {
        console.error("Session check error:", err.message);
        return res.status(500).json({ success: false, message: "Failed to verify session" });
      }

      // Check if session exists
      if (!session) {
        return res.status(401).json({ success: false, message: "Invalid session" });
      }

      // Check session expiration
      if (session.expires && session.expires < Date.now()) {
        db.run("DELETE FROM sessions WHERE session_id = ?", [sessionId]);
        return res.status(401).json({ success: false, message: "Session expired" });
      }

      // Secure admin check - verifies user has admin role
      return res.json({
        success: true,
        isAdmin: session.role === "admin",
      });
    });
  } catch (error) {
    console.error("Admin check error:", error);
    res.status(500).json({ success: false, message: "Admin check failed" });
  }
});

// Secure Admin Users
app.get("/api/secure/admin/users", (req, res) => {
  try {
    const { sessionId } = req.query;

    if (!sessionId) {
      return res.status(400).json({ success: false, message: "Session ID is required" });
    }

    // SECURE: Using parameterized query
    db.get("SELECT * FROM sessions WHERE session_id = ?", [sessionId], (err, session) => {
      if (err) {
        console.error("Session check error:", err.message);
        return res.status(500).json({ success: false, message: "Failed to verify session" });
      }

      // Check if session exists
      if (!session) {
        return res.status(401).json({ success: false, message: "Invalid session" });
      }

      // Check session expiration
      if (session.expires && session.expires < Date.now()) {
        db.run("DELETE FROM sessions WHERE session_id = ?", [sessionId]);
        return res.status(401).json({ success: false, message: "Session expired" });
      }

      // Check if user is admin
      if (session.role !== "admin") {
        return res.status(403).json({ success: false, message: "Unauthorized access" });
      }

      // SECURE: Using parameterized query
      db.all("SELECT id, username, role FROM users", (err, users) => {
        if (err) {
          console.error("Error getting users:", err.message);
          return res.status(500).json({ success: false, message: "Failed to get users" });
        }
        
        res.json({
          success: true,
          users: users,
        });
      });
    });
  } catch (error) {
    console.error("Error getting users:", error);
    res.status(500).json({ success: false, message: "Failed to get users" });
  }
});

// Clean up expired sessions periodically
setInterval(() => {
  const now = Date.now();
  db.run("DELETE FROM sessions WHERE expires < ?", [now], (err) => {
    if (err) {
      console.error("Error cleaning up expired sessions:", err.message);
    }
  });
}, 60000); // Clean up every minute

// Close database connection on process exit
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed');
    }
    process.exit(0);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Open http://localhost:${PORT}/index.html to view the application`);
});