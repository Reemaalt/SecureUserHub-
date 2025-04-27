// Simple Express server for security demonstration
const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const path = require("path")
const crypto = require("crypto")

const app = express()
const PORT = 3000

// Middleware
app.use(bodyParser.json())
app.use(express.static(".")) // Serve static files from current directory

// Simple file-based storage
const DATA_FILE = path.join(__dirname, "data.json")

// Initialize data if it doesn't exist
if (!fs.existsSync(DATA_FILE)) {
  const initialData = {
    users: [
      {
        id: 1,
        username: "admin",
        // MD5 hash of 'password123'
        passwordHash: "482c811da5d5b4bc6d497ffa98491e38",
        role: "admin",
      },
    ],
    comments: [
      {
        id: 1,
        username: "admin",
        content: "Welcome to our community!",
      },
    ],
    sessions: {},
  }

  fs.writeFileSync(DATA_FILE, JSON.stringify(initialData, null, 2))
}

// Helper function to read data
function readData() {
  const data = fs.readFileSync(DATA_FILE, "utf8")
  return JSON.parse(data)
}

// Helper function to write data
function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2))
}

// ==========================================
// VULNERABLE API ENDPOINTS
// ==========================================

// Vulnerable Register
app.post("/api/vulnerable/register", (req, res) => {
  try {
    const { username, password } = req.body

    // Check if username is provided
    if (!username || username.trim() === "") {
      return res.status(400).json({ success: false, message: "Username is required" })
    }

    // Check if password is provided
    if (!password || password.trim() === "") {
      return res.status(400).json({ success: false, message: "Password is required" })
    }

    const data = readData()

    // Check if username already exists
    const existingUser = data.users.find((u) => u.username === username)
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Username already exists" })
    }

    // Weak password hashing using MD5 (VULNERABLE)
    const passwordHash = crypto.createHash("md5").update(password).digest("hex")

    // Create new user
    const newUser = {
      id: data.users.length + 1,
      username,
      passwordHash,
      role: "user",
    }

    data.users.push(newUser)

    // Create session
    const sessionId = Math.random().toString(36).substring(2)
    data.sessions[sessionId] = { userId: newUser.id, username: newUser.username, role: newUser.role }

    writeData(data)

    res.json({
      success: true,
      message: "Registration successful",
      username: newUser.username,
      role: newUser.role,
      sessionId,
    })
  } catch (error) {
    console.error("Registration error:", error)
    res.status(500).json({ success: false, message: "Registration failed" })
  }
})

// Vulnerable Login
app.post("/api/vulnerable/login", (req, res) => {
  try {
    const { username, password } = req.body

    // Check if username and password are provided
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required" })
    }

    const data = readData()

    // Find user
    const user = data.users.find((u) => u.username === username)

    // Check if user exists
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid username or password" })
    }

    // Weak password verification (MD5)
    const passwordHash = crypto.createHash("md5").update(password).digest("hex")

    // Check if password is correct
    if (passwordHash !== user.passwordHash) {
      return res.status(401).json({ success: false, message: "Invalid username or password" })
    }

    // Create session (no expiration)
    const sessionId = Math.random().toString(36).substring(2)
    data.sessions[sessionId] = { userId: user.id, username: user.username, role: user.role }

    writeData(data)

    res.json({
      success: true,
      message: "Login successful",
      username: user.username,
      role: user.role,
      sessionId,
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ success: false, message: "Login failed" })
  }
})

// Vulnerable Comments - Get
app.get("/api/vulnerable/comments", (req, res) => {
  try {
    const data = readData()

    res.json({
      success: true,
      comments: data.comments,
    })
  } catch (error) {
    console.error("Error getting comments:", error)
    res.status(500).json({ success: false, message: "Failed to get comments" })
  }
})

// Vulnerable Comments - Post (vulnerable to XSS)
app.post("/api/vulnerable/comments", (req, res) => {
  try {
    const { sessionId, content } = req.body

    // Check if content is provided
    if (!content || content.trim() === "") {
      return res.status(400).json({ success: false, message: "Comment content is required" })
    }

    const data = readData()

    // Check if session exists
    const session = data.sessions[sessionId]
    if (!session) {
      return res.status(401).json({ success: false, message: "Invalid session" })
    }

    // Add comment (vulnerable to XSS - no content sanitization)
    const newComment = {
      id: data.comments.length + 1,
      username: session.username,
      content: content, // No sanitization!
    }

    data.comments.push(newComment)
    writeData(data)

    res.json({
      success: true,
      comment: newComment,
    })
  } catch (error) {
    console.error("Error adding comment:", error)
    res.status(500).json({ success: false, message: "Failed to add comment" })
  }
})

// Vulnerable Admin Check (broken access control)
app.get("/api/vulnerable/admin-check", (req, res) => {
  try {
    const { sessionId } = req.query

    if (!sessionId) {
      return res.status(400).json({ success: false, message: "Session ID is required" })
    }

    const data = readData()

    // Get session
    const session = data.sessions[sessionId]

    // Vulnerable admin check - only checks if session exists, not if user is admin
    if (session) {
      // This is vulnerable because it doesn't properly verify the role
      return res.json({
        success: true,
        isAdmin: true, // Always returns true if session exists
      })
    }

    res.status(401).json({ success: false, message: "Invalid session" })
  } catch (error) {
    console.error("Admin check error:", error)
    res.status(500).json({ success: false, message: "Admin check failed" })
  }
})

// ==========================================
// SECURE API ENDPOINTS
// ==========================================

// Secure Register
app.post("/api/secure/register", (req, res) => {
  try {
    const { username, password } = req.body

    // Check if username is provided
    if (!username || username.trim() === "") {
      return res.status(400).json({ success: false, message: "Username is required" })
    }

    // Check if password is provided
    if (!password || password.trim() === "") {
      return res.status(400).json({ success: false, message: "Password is required" })
    }

    // Password strength validation
    const hasMinLength = password.length >= 8
    const hasUppercase = /[A-Z]/.test(password)
    const hasLowercase = /[a-z]/.test(password)
    const hasNumber = /[0-9]/.test(password)
    const hasSpecialChar = /[^A-Za-z0-9]/.test(password)

    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasNumber || !hasSpecialChar) {
      return res.status(400).json({
        success: false,
        message: "Password does not meet security requirements",
      })
    }

    const data = readData()

    // Check if username already exists
    const existingUser = data.users.find((u) => u.username === username)
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Username already exists" })
    }

    // Secure password hashing with salt
    const salt = crypto.randomBytes(16).toString("hex")
    const passwordHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex")

    // Create new user
    const newUser = {
      id: data.users.length + 1,
      username,
      passwordHash: `${salt}:${passwordHash}`,
      role: "user",
    }

    data.users.push(newUser)

    // Create session with expiration
    const sessionId = crypto.randomBytes(32).toString("hex")
    data.sessions[sessionId] = {
      userId: newUser.id,
      username: newUser.username,
      role: newUser.role,
      expires: Date.now() + 3600000, // 1 hour expiration
    }

    writeData(data)

    res.json({
      success: true,
      message: "Registration successful",
      username: newUser.username,
      role: newUser.role,
      sessionId,
    })
  } catch (error) {
    console.error("Registration error:", error)
    res.status(500).json({ success: false, message: "Registration failed" })
  }
})

// Secure Login with rate limiting
const loginAttempts = {} // Store login attempts by IP

app.post("/api/secure/login", (req, res) => {
  try {
    const { username, password } = req.body
    const ip = req.ip // Get client IP for rate limiting

    // Check if username and password are provided
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required" })
    }

    // Rate limiting check
    if (!loginAttempts[ip]) {
      loginAttempts[ip] = {
        count: 0,
        lockUntil: 0,
      }
    }

    // Check if IP is locked
    if (loginAttempts[ip].lockUntil > Date.now()) {
      const remainingSeconds = Math.ceil((loginAttempts[ip].lockUntil - Date.now()) / 1000)
      return res.status(429).json({
        success: false,
        message: `Too many login attempts. Try again in ${remainingSeconds} seconds.`,
        locked: true,
        lockTimer: remainingSeconds,
      })
    }

    const data = readData()

    // Find user
    const user = data.users.find((u) => u.username === username)

    // Check if user exists
    if (!user) {
      // Increment failed attempts
      loginAttempts[ip].count++

      // Lock account after 5 failed attempts
      if (loginAttempts[ip].count >= 5) {
        loginAttempts[ip].lockUntil = Date.now() + 60000 // 1 minute lockout
        return res.status(429).json({
          success: false,
          message: "Too many failed login attempts. Account locked for 60 seconds.",
          locked: true,
          lockTimer: 60,
        })
      }

      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
        attempts: loginAttempts[ip].count,
      })
    }

    // Secure password verification
    let isPasswordValid = false

    // For admin with MD5 hash (for demo purposes)
    if (!user.passwordHash.includes(":")) {
      const passwordHash = crypto.createHash("md5").update(password).digest("hex")
      isPasswordValid = passwordHash === user.passwordHash
    } else {
      // For secure hashed passwords
      const [salt, hash] = user.passwordHash.split(":")
      const passwordHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex")
      isPasswordValid = passwordHash === hash
    }

    if (!isPasswordValid) {
      // Increment failed attempts
      loginAttempts[ip].count++

      // Lock account after 5 failed attempts
      if (loginAttempts[ip].count >= 5) {
        loginAttempts[ip].lockUntil = Date.now() + 60000 // 1 minute lockout
        return res.status(429).json({
          success: false,
          message: "Too many failed login attempts. Account locked for 60 seconds.",
          locked: true,
          lockTimer: 60,
        })
      }

      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
        attempts: loginAttempts[ip].count,
      })
    }

    // Reset login attempts on successful login
    loginAttempts[ip].count = 0

    // Create session with expiration
    const sessionId = crypto.randomBytes(32).toString("hex")
    data.sessions[sessionId] = {
      userId: user.id,
      username: user.username,
      role: user.role,
      expires: Date.now() + 3600000, // 1 hour expiration
    }

    writeData(data)

    res.json({
      success: true,
      message: "Login successful",
      username: user.username,
      role: user.role,
      sessionId,
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ success: false, message: "Login failed" })
  }
})

// Secure Comments - Get
app.get("/api/secure/comments", (req, res) => {
  try {
    const data = readData()

    res.json({
      success: true,
      comments: data.comments,
    })
  } catch (error) {
    console.error("Error getting comments:", error)
    res.status(500).json({ success: false, message: "Failed to get comments" })
  }
})

// Secure Comments - Post (with XSS prevention)
app.post("/api/secure/comments", (req, res) => {
  try {
    const { sessionId, content } = req.body

    // Check if content is provided
    if (!content || content.trim() === "") {
      return res.status(400).json({ success: false, message: "Comment content is required" })
    }

    const data = readData()

    // Check if session exists and is valid
    const session = data.sessions[sessionId]
    if (!session) {
      return res.status(401).json({ success: false, message: "Invalid session" })
    }

    // Check session expiration
    if (session.expires && session.expires < Date.now()) {
      delete data.sessions[sessionId]
      writeData(data)
      return res.status(401).json({ success: false, message: "Session expired" })
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
      .replace(/onload/gi, "blocked")

    // Add comment with sanitized content
    const newComment = {
      id: data.comments.length + 1,
      username: session.username,
      content: sanitizedContent,
    }

    data.comments.push(newComment)
    writeData(data)

    res.json({
      success: true,
      comment: newComment,
    })
  } catch (error) {
    console.error("Error adding comment:", error)
    res.status(500).json({ success: false, message: "Failed to add comment" })
  }
})

// Secure Admin Check
app.get("/api/secure/admin-check", (req, res) => {
  try {
    const { sessionId } = req.query

    if (!sessionId) {
      return res.status(400).json({ success: false, message: "Session ID is required" })
    }

    const data = readData()

    // Get session
    const session = data.sessions[sessionId]

    // Check if session exists
    if (!session) {
      return res.status(401).json({ success: false, message: "Invalid session" })
    }

    // Check session expiration
    if (session.expires && session.expires < Date.now()) {
      delete data.sessions[sessionId]
      writeData(data)
      return res.status(401).json({ success: false, message: "Session expired" })
    }

    // Secure admin check - verifies user has admin role
    return res.json({
      success: true,
      isAdmin: session.role === "admin",
    })
  } catch (error) {
    console.error("Admin check error:", error)
    res.status(500).json({ success: false, message: "Admin check failed" })
  }
})

// Secure Admin Users
app.get("/api/secure/admin/users", (req, res) => {
  try {
    const { sessionId } = req.query

    if (!sessionId) {
      return res.status(400).json({ success: false, message: "Session ID is required" })
    }

    const data = readData()

    // Get session
    const session = data.sessions[sessionId]

    // Check if session exists
    if (!session) {
      return res.status(401).json({ success: false, message: "Invalid session" })
    }

    // Check session expiration
    if (session.expires && session.expires < Date.now()) {
      delete data.sessions[sessionId]
      writeData(data)
      return res.status(401).json({ success: false, message: "Session expired" })
    }

    // Check if user is admin
    if (session.role !== "admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" })
    }

    // Return users without password hashes
    const users = data.users.map((user) => ({
      id: user.id,
      username: user.username,
      role: user.role,
    }))

    res.json({
      success: true,
      users,
    })
  } catch (error) {
    console.error("Error getting users:", error)
    res.status(500).json({ success: false, message: "Failed to get users" })
  }
})

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
  console.log(`Open http://localhost:${PORT}/index.html to view the application`)
})
