const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const https = require("https");
const cookieParser = require("cookie-parser"); 

// Import the encryption utility
const encryptionmy = require("./encryptingmy");

const app = express();
const PORT = 3000;
const HTTPS_PORT = 8443; // Standard port for HTTPS testing

app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static("."));

const httpsOptions = {
pfx: fs.readFileSync(path.join(__dirname, 'certs', 'cert.pfx')),
  passphrase: 'password'
};

/*
this is commnted out to show the  vulnerable endpoint  corctly
// Middleware to set secure headers
app.use((req, res, next) => {
  // HTTP Strict Transport Security
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  // X-XSS-Protection
  res.setHeader("X-XSS-Protection", "1; mode=block");
  
  // Referrer-Policy
  res.setHeader("Referrer-Policy", "no-referrer");
  
  next();
});
*/

// Create HTTPS server
const httpsServer = https.createServer(httpsOptions, app);

// Keep the HTTP server to show vulnerable mode use for development only
app.listen(PORT, () => {
  console.log(`HTTP Server running on http://localhost:${PORT} (vulnerable more )`);
});

httpsServer.listen(HTTPS_PORT, () => {
  console.log(`HTTPS Server running on https://localhost:${HTTPS_PORT} (secure)`);
});


// SQLite setup
const db = new sqlite3.Database("./security_demo.db", (err) => {
  if (err) {
    console.error("Database error:", err.message);
  } else {
    console.log("Connected to SQLite DB");
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

 db.run(`CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    role TEXT,
    encrypted_data TEXT,
    expires BIGINT
  )`);
  
// For secure mode, use PBKDF2 with salt for admin password
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync("password123@", salt, 1000, 64, "sha512").toString("hex");
  const adminPasswordHash = `${salt}:${hash}`;
    
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
      db.run(
        `INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
        ["admin", adminPasswordHash, "admin"],
        function (err) {
          if (!err) {
            console.log("Admin user created with ID:", this.lastID);
          }
        }
      );
    }
  });
}
/*if vulnerable
const adminPasswordHash = crypto.createHash("md5").update("password123").digest("hex");

  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
      db.run(
        `INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
        ["admin", adminPasswordHash, "admin"],
        function (err) {
          if (!err) {
            console.log("Admin user created with ID:", this.lastID);
          }
        }
      );
    }
  });
}  */

function verifySession(sessionId, callback) {
  db.get("SELECT * FROM sessions WHERE session_id = ?", [sessionId], (err, session) => {
    if (err || !session || (session.expires && session.expires < Date.now())) {
      return callback(null);
    }
    
    // If this is a secure session with encrypted data
    if (session.encrypted_data) {
      try {
        const decryptedData = encryptionmy.decrypt(session.encrypted_data);
        if (!decryptedData) {
          return callback(null);
        }
        
        const sessionData = JSON.parse(decryptedData);
        return callback(sessionData);
      } catch (error) {
        console.error("Session decryption error:", error);
        return callback(null);
      }
    } 
    // For vulnerable sessions with direct fields
    else {
      return callback({
        user_id: session.user_id,
        username: session.username,
        role: session.role,
        created: Date.now()
      });
    }
  });
}
// endpoint to get all users (for admin panel) secure mode
app.get("/api/secure/admin/users", (req, res) => {
  const { sessionId } = req.query;
  
  if (!sessionId) {
    return res.status(400).json({ success: false, message: "Missing session ID" });
  }

  verifySession(sessionId, (sessionData) => {
    if (!sessionData) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }
    
    if (sessionData.role !== "admin") {
      return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    db.all("SELECT id, username, role FROM users", (err, users) => {
      if (err) {
        return res.status(500).json({ success: false, message: "Failed to load users" });
      }
      res.json({ success: true, users });
    });
  });
});

// ========== VULNERABLE ENDPOINTS ==========

app.get("/api/vulnerable/admin-check", (req, res) => {
  const { sessionId } = req.query;
 
  db.get(`SELECT * FROM sessions WHERE session_id = '${sessionId}'`, (err, session) => {
    if (!session) return res.status(401).json({ success: false, message: "Invalid session" });
    res.json({ success: true, isAdmin: session.role === "admin" });
  });
});
app.post("/api/vulnerable/register", (req, res) => {
  const { username, password } = req.body;
  
  // Use MD5 hash for vulnerable mode (insecure)
  const passwordHash = crypto.createHash("md5").update(password).digest("hex");
  
  // SQL injection vulnerability by using direct string interpolation
  const query = `INSERT INTO users (username, password_hash, role) VALUES ('${username}', '${passwordHash}', 'user')`;

  db.run(query, function (err) {
    if (err) return res.status(500).json({ success: false, message: "Register failed" });

    const sessionId = Math.random().toString(36).substring(2);
    
    // SQL injection vulnerability in the sessions table
    db.run(
      `INSERT INTO sessions (session_id, user_id, username, role) VALUES ('${sessionId}', ${this.lastID}, '${username}', 'user')`,
      (err) => {
        if (err) return res.status(500).json({ success: false, message: "Session failed" });

        res.json({ success: true, sessionId, username, role: "user" });
      }
    );
  });
});

app.post("/api/vulnerable/login", (req, res) => {
  const { username, password } = req.body;
  
  // Use MD5 hash for vulnerable mode (insecure)
  const passwordHash = crypto.createHash("md5").update(password).digest("hex");
  
  // SQL injection vulnerability by using direct string interpolation
  const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${passwordHash}'`;

  db.get(query, (err, user) => {
    if (err || !user) return res.status(401).json({ success: false, message: "Invalid login" });

    const sessionId = Math.random().toString(36).substring(2);
    
    // Insert vulnerable session (SQL injection vulnerability)
    db.run(
      `INSERT INTO sessions (session_id, user_id, username, role) VALUES ('${sessionId}', ${user.id}, '${user.username}', '${user.role}')`,
      (err) => {
        if (err) return res.status(500).json({ success: false, message: "Session failed" });

        res.json({ success: true, sessionId, username: user.username, role: user.role });
      }
    );
  });
});

app.post("/api/vulnerable/comments", (req, res) => {
  const { sessionId, content } = req.body;
  // SQL injection vulnerability
  db.get(`SELECT * FROM sessions WHERE session_id = '${sessionId}'`, (err, session) => {
    if (!session) return res.status(401).json({ success: false, message: "Invalid session" });
    
    // No content sanitization - XSS vulnerability
    const query = `INSERT INTO comments (username, content) VALUES ('${session.username}', '${content}')`;
    db.run(query, function (err) {
      if (err) return res.status(500).json({ success: false, message: "Failed to comment" });
      res.json({ success: true, comment: { id: this.lastID, username: session.username, content } });
    });
  });
});

app.get("/api/vulnerable/comments", (req, res) => {
  db.all("SELECT * FROM comments ORDER BY id DESC", (err, comments) => {
    if (err) return res.status(500).json({ success: false, message: "Failed to load" });
    res.json({ success: true, comments });
  });
});

// endpoint for the vulnerable version (view-only)
// Vulnerable endpoint to get all users with SQL injection vulnerability
app.get("/api/vulnerable/admin/users", (req, res) => {
  const { sessionId } = req.query;
  
  if (!sessionId) {
    return res.status(400).json({ success: false, message: "Missing session ID" });
  }

  // This creates an SQL injection vulnerability
  db.get(`SELECT * FROM sessions WHERE session_id = '${sessionId}'`, (err, session) => {
    if (!session) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }

    // We don't verify if session.role === "admin" in vulnerable mode - any authenticated user can see all users
    db.all("SELECT id, username, role FROM users", (err, users) => {
      if (err) {
        return res.status(500).json({ success: false, message: "Failed to load users" });
      }
      res.json({ success: true, users });
    });
  });
});


// Vulnerable endpoint to delete a user with no proper role check
app.post("/api/vulnerable/admin/delete-user", (req, res) => {
  const { sessionId, userId } = req.body;

  if (!sessionId || !userId) {
    return res.status(400).json({ success: false, message: "Missing data" });
  }

  // This allows any authenticated user to delete users if they have the endpoint URL
  db.get(`SELECT * FROM sessions WHERE session_id = '${sessionId}'`, (err, session) => {
    if (!session) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }
    
    // We're not checking if the user is actually an admin
    db.run(`DELETE FROM users WHERE id = ${userId}`, (err) => {
      if (err) return res.status(500).json({ success: false, message: "Failed to delete user" });
      
      // Also delete related sessions
      db.run(`DELETE FROM sessions WHERE user_id = ${userId}`);
      
      res.json({ success: true, message: "User deleted" });
    });
  });
});

//  update a user's role with no proper role check
app.post("/api/vulnerable/admin/update-role", (req, res) => {
  const { sessionId, userId, newRole } = req.body;

  if (!sessionId || !userId || !newRole) {
    return res.status(400).json({ success: false, message: "Missing data" });
  }

  // Any authenticated user can change roles if they have the endpoint URL
  db.get(`SELECT * FROM sessions WHERE session_id = '${sessionId}'`, (err, session) => {
    if (!session) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }

    db.run(`UPDATE users SET role = '${newRole}' WHERE id = ${userId}`, (err) => {
      if (err) return res.status(500).json({ success: false, message: "Failed to update role" });
      res.json({ success: true, message: "User role updated" });
    });
  });
});

// vulnerable admin-check endpoint
app.get("/api/vulnerable/admin-check", (req, res) => {
  const { sessionId } = req.query;
  db.get(`SELECT * FROM sessions WHERE session_id = '${sessionId}'`, (err, session) => {
    if (!session) return res.status(401).json({ success: false, message: "Invalid session" });
    
    //  we check for admin role but the SQL query is injectable
    res.json({ success: true, isAdmin: session.role === "admin" });
  });
});

// ========== SECURE ENDPOINTS ==========

// Initialize encryption key when the server starts
encryptionmy.initializeEncryptionKey();

const loginAttempts = {};

app.post("/api/secure/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: "Missing input" });

  const strong =
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password);

  if (!strong) return res.status(400).json({ success: false, message: "Weak password" });

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (user) return res.status(400).json({ success: false, message: "Username taken" });

    const role = username.toLowerCase() === "admin" ? "admin" : "user";
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
    const combined = `${salt}:${hash}`;

    db.run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", [username, combined, role], function (err) {
      if (err) return res.status(500).json({ success: false, message: "Insert failed" });

      const sessionId = crypto.randomBytes(32).toString("hex");
      const expires = Date.now() + 3600000;
       
      const sessionData = {
          user_id: this.lastID,
          username: username,
          role: role,
          created: Date.now()
        };
        
        const encryptedData = encryptionmy.encrypt(JSON.stringify(sessionData));

        db.run(
          "INSERT INTO sessions (session_id, encrypted_data, expires) VALUES (?, ?, ?)",
          [sessionId, encryptedData, expires], 
          (err) => {
            if (err) return res.status(500).json({ success: false, message: "Session error" });
            res.json({ success: true, sessionId, username, role });
          }
        );
      }
    );
  });
});

app.post("/api/secure/login", (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (!loginAttempts[ip]) loginAttempts[ip] = { count: 0, lockUntil: 0 };
  if (loginAttempts[ip].lockUntil > Date.now())
    return res.status(429).json({ success: false, message: "Locked", lockTimer: Math.ceil((loginAttempts[ip].lockUntil - Date.now()) / 1000) });

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) {
      loginAttempts[ip].count++;
      if (loginAttempts[ip].count >= 5) loginAttempts[ip].lockUntil = Date.now() + 60000;
      return res.status(401).json({ success: false, message: "Invalid login" });
    }

    let isValid = false;
    if (user.password_hash.includes(":")) {
      const [salt, hash] = user.password_hash.split(":");
      const userHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
      isValid = userHash === hash;
    } else {
      const userHash = crypto.createHash("md5").update(password).digest("hex");
      isValid = userHash === user.password_hash;
    }

    if (!isValid) {
      loginAttempts[ip].count++;
      if (loginAttempts[ip].count >= 5) loginAttempts[ip].lockUntil = Date.now() + 60000;
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    loginAttempts[ip].count = 0;
    const sessionId = crypto.randomBytes(32).toString("hex");
    const expires = Date.now() + 3600000;
    
     // Create session data object
    const sessionData = {
      user_id: user.id,
      username: user.username,
      role: user.role,
      created: Date.now()
    };
    
    // Encrypt the session data
    const encryptedData = encryptionmy.encrypt(JSON.stringify(sessionData));

    // Store encrypted session data
    db.run("INSERT INTO sessions (session_id, encrypted_data, expires) VALUES (?, ?, ?)", 
      [sessionId, encryptedData, expires], (err) => {
        if (err) return res.status(500).json({ success: false, message: "Session error" });
        res.json({ success: true, sessionId, username: user.username, role: user.role });
      });
  });
});

 //admin-check endpoint
app.get("/api/secure/admin-check", (req, res) => {
  const { sessionId } = req.query;
  
  if (!sessionId) {
    return res.status(400).json({ success: false, message: "Missing session ID" });
  }
  
  verifySession(sessionId, (sessionData) => {
    if (!sessionData) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }
    
    res.json({ success: true, isAdmin: sessionData.role === "admin" });
  });
});

//  comments endpoint with session verification
app.post("/api/secure/comments", (req, res) => {
  const { sessionId, content } = req.body;
  
  verifySession(sessionId, (sessionData) => {
    if (!sessionData) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }

    const sanitized = content
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/script/gi, "blocked")
      .replace(/onerror/gi, "blocked");

    db.run("INSERT INTO comments (username, content) VALUES (?, ?)", 
      [sessionData.username, sanitized], function (err) {
        if (err) return res.status(500).json({ success: false, message: "Comment failed" });
        res.json({ 
          success: true, 
          comment: { 
            id: this.lastID, 
            username: sessionData.username, 
            content: sanitized 
          }
        });
      });
  });
});

app.get("/api/secure/comments", (req, res) => {
  db.all("SELECT * FROM comments ORDER BY id DESC", (err, comments) => {
    if (err) return res.status(500).json({ success: false, message: "Failed to load" });
    res.json({ success: true, comments });
  });
});

//role endpoint to properly check permissions
app.post("/api/secure/admin/update-role", (req, res) => {
  const { sessionId, userId, newRole } = req.body;

  if (!sessionId || !userId || !newRole) {
    return res.status(400).json({ success: false, message: "Missing data" });
  }

  verifySession(sessionId, (sessionData) => {
    if (!sessionData) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }
    
    if (sessionData.role !== "admin") {
      return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    db.run("UPDATE users SET role = ? WHERE id = ?", [newRole, userId], (err) => {
      if (err) return res.status(500).json({ success: false, message: "Failed to update role" });
      res.json({ success: true, message: "User role updated" });
    });
  });
});

// Delete-user endpoint to properly check permissions
app.post("/api/secure/admin/delete-user", (req, res) => {
  const { sessionId, userId } = req.body;

  if (!sessionId || !userId) {
    return res.status(400).json({ success: false, message: "Missing data" });
  }

  verifySession(sessionId, (sessionData) => {
    if (!sessionData) {
      return res.status(401).json({ success: false, message: "Invalid session" });
    }
    
    if (sessionData.role !== "admin") {
      return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
      if (err) return res.status(500).json({ success: false, message: "Failed to delete user" });
      
      // Also delete related sessions
      db.run("DELETE FROM sessions WHERE user_id = ?", [userId]);
      
      res.json({ success: true, message: "User deleted" });
    });
  });
});

app.post("/api/secure/logout", (req, res) => {
  const sessionId = req.cookies.secureSessionId;
  
  if (sessionId) {
    // Remove from database
    db.run("DELETE FROM sessions WHERE session_id = ?", [sessionId]);
    
    // Clear the cookie
    res.clearCookie('secureSessionId', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/'
    });
  }
  
  res.json({ success: true, message: "Logged out successfully" });
});

// Middleware to get session from secure cookie
function getSessionFromCookie(req, res, next) {
  const sessionId = req.cookies.secureSessionId || req.query.sessionId || req.body.sessionId;
  
  if (!sessionId) {
    req.sessionData = null;
    return next();
  }
  
  verifySession(sessionId, (sessionData) => {
    req.sessionData = sessionData;
    next();
  });
}

// Apply the middleware to all routes
app.use(getSessionFromCookie);

// Auto-clean expired sessions
setInterval(() => {
  db.run("DELETE FROM sessions WHERE expires < ?", [Date.now()]);
}, 60000);

process.on("SIGINT", () => {
  db.close();
  process.exit(0);
});