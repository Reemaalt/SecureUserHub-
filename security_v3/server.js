const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(express.static("."));

// SQLite DB setup
const db = new sqlite3.Database("./security_demo.db", (err) => {
  if (err) {
    console.error("Error opening database", err.message);
  } else {
    console.log("Connected to the SQLite database.");
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
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires BIGINT,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  const adminPasswordHash = crypto.createHash("md5").update("password123").digest("hex");

  db.get("SELECT * FROM users WHERE username = ?", ["admin"], (err, row) => {
    if (!row) {
      db.run(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
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

// ==========================================
// VULNERABLE API ENDPOINTS
// ==========================================

// Register - Vulnerable to SQL Injection
app.post("/api/vulnerable/register", (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Missing username or password" });
    }

    const passwordHash = crypto.createHash("md5").update(password).digest("hex");

    const query = `INSERT INTO users (username, password_hash, role) VALUES ('${username}', '${passwordHash}', 'user')`;

    db.run(query, function (err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(400).json({ success: false, message: "Username already exists" });
        }
        return res.status(500).json({ success: false, message: "Registration failed" });
      }

      const userId = this.lastID;
      const sessionId = Math.random().toString(36).substring(2);

      // Vulnerable session insert
      const unsafeQuery = `INSERT INTO sessions (session_id, user_id, username, role)
                           VALUES ('${sessionId}', ${userId}, '${username}', 'user')`;

      db.run(unsafeQuery, (err) => {
        if (err) {
          return res.status(500).json({ success: false, message: "Session creation failed" });
        }

        res.json({
          success: true,
          message: "Registration successful",
          username: username,
          role: "user",
          sessionId: sessionId,
        });
      });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Registration error" });
  }
});

// Login - Vulnerable to SQL Injection
app.post("/api/vulnerable/login", (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Missing credentials" });
    }

    // Hash password for query (will be ignored in SQLi bypass)
    const passwordHash = crypto.createHash("md5").update(password).digest("hex");

    // Vulnerable query with string interpolation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${passwordHash}'`;

    db.get(query, (err, user) => {
      if (err || !user) {
        return res.status(401).json({ success: false, message: "Invalid login" });
      }

      const sessionId = Math.random().toString(36).substring(2);

      db.run(
        `INSERT INTO sessions (session_id, user_id, username, role) 
         VALUES ('${sessionId}', ${user.id}, '${user.username}', '${user.role}')`,
        (err) => {
          if (err) {
            return res.status(500).json({ success: false, message: "Session failed" });
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
  } catch (err) {
    res.status(500).json({ success: false, message: "Login error" });
  }
});

// Comments POST - Vulnerable to SQL Injection + XSS
app.post("/api/vulnerable/comments", (req, res) => {
  try {
    const { sessionId, content } = req.body;

    if (!content || !sessionId) {
      return res.status(400).json({ success: false, message: "Missing content or session" });
    }

    db.get(`SELECT * FROM sessions WHERE session_id = '${sessionId}'`, (err, session) => {
      if (err || !session) {
        return res.status(401).json({ success: false, message: "Invalid session" });
      }

      const unsafeQuery = `INSERT INTO comments (username, content)
                           VALUES ('${session.username}', '${content}')`;

      db.run(unsafeQuery, function (err) {
        if (err) {
          return res.status(500).json({ success: false, message: "Failed to add comment" });
        }

        res.json({
          success: true,
          comment: {
            id: this.lastID,
            username: session.username,
            content: content,
          },
        });
      });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to add comment" });
  }
});

// Comments GET
app.get("/api/vulnerable/comments", (req, res) => {
  db.all("SELECT * FROM comments ORDER BY id DESC", (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: "Failed to get comments" });
    }
    res.json({ success: true, comments: rows });
  });
});

// Admin check (bypass logic)
app.get("/api/vulnerable/admin-check", (req, res) => {
  const { sessionId } = req.query;

  db.get("SELECT * FROM sessions WHERE session_id = ?", [sessionId], (err, session) => {
    if (session) {
      // Vulnerable: always returns true
      return res.json({ success: true, isAdmin: true });
    }
    res.status(401).json({ success: false, message: "Invalid session" });
  });
});

// Server listen
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
