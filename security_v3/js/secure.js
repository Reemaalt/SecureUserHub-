// Secure implementation JavaScript

// Check if we're on the register page
if (document.getElementById("register-form") && document.getElementById("password-requirements")) {
  const passwordInput = document.getElementById("password")
  const submitButton = document.getElementById("submit-button")

  // Password strength validation
  passwordInput.addEventListener("input", () => {
    const password = passwordInput.value

    const hasMinLength = password.length >= 8
    const hasUppercase = /[A-Z]/.test(password)
    const hasLowercase = /[a-z]/.test(password)
    const hasNumber = /[0-9]/.test(password)
    const hasSpecialChar = /[^A-Za-z0-9]/.test(password)

    document.getElementById("length-check").className = hasMinLength
      ? "requirement requirement-pass"
      : "requirement requirement-fail"
    document.getElementById("length-check").innerHTML = hasMinLength
      ? "<span>✓</span> At least 8 characters"
      : "<span>✖</span> At least 8 characters"

    document.getElementById("uppercase-check").className = hasUppercase
      ? "requirement requirement-pass"
      : "requirement requirement-fail"
    document.getElementById("uppercase-check").innerHTML = hasUppercase
      ? "<span>✓</span> At least one uppercase letter"
      : "<span>✖</span> At least one uppercase letter"

    document.getElementById("lowercase-check").className = hasLowercase
      ? "requirement requirement-pass"
      : "requirement requirement-fail"
    document.getElementById("lowercase-check").innerHTML = hasLowercase
      ? "<span>✓</span> At least one lowercase letter"
      : "<span>✖</span> At least one lowercase letter"

    document.getElementById("number-check").className = hasNumber
      ? "requirement requirement-pass"
      : "requirement requirement-fail"
    document.getElementById("number-check").innerHTML = hasNumber
      ? "<span>✓</span> At least one number"
      : "<span>✖</span> At least one number"

    document.getElementById("special-check").className = hasSpecialChar
      ? "requirement requirement-pass"
      : "requirement requirement-fail"
    document.getElementById("special-check").innerHTML = hasSpecialChar
      ? "<span>✓</span> At least one special character"
      : "<span>✖</span> At least one special character"

    const isPasswordStrong = hasMinLength && hasUppercase && hasLowercase && hasNumber && hasSpecialChar
    submitButton.disabled = !isPasswordStrong
  })

  document.getElementById("register-form").addEventListener("submit", async (e) => {
    e.preventDefault()

    const username = document.getElementById("username").value
    const password = document.getElementById("password").value
    const submitButton = document.getElementById("submit-button")
    const errorMessage = document.getElementById("error-message")

    submitButton.textContent = "Registering..."
    submitButton.disabled = true
    errorMessage.style.display = "none"

    try {
      // Call the secure register API
      const response = await fetch("/api/secure/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        // Store session ID in localStorage (in a real app, use HttpOnly cookies)
        localStorage.setItem("secureSessionId", data.sessionId)
        localStorage.setItem("secureUsername", data.username)
        localStorage.setItem("secureRole", data.role)

        // Redirect to dashboard
        window.location.href = "dashboard.html"
      } else {
        errorMessage.textContent = data.message
        errorMessage.style.display = "block"
        submitButton.textContent = "Register"
        submitButton.disabled = false
      }
    } catch (error) {
      console.error("Registration error:", error)
      errorMessage.textContent = "Registration failed. Please try again."
      errorMessage.style.display = "block"
      submitButton.textContent = "Register"
      submitButton.disabled = false
    }
  })
}

// Check if we're on the login page
if (document.getElementById("login-form") && document.getElementById("attempts-message")) {
  let attempts = 0
  let locked = false
  let lockTimer = 0
  let lockInterval

  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault()

    if (locked) {
      document.getElementById("error-message").textContent =
        `Account temporarily locked. Try again in ${lockTimer} seconds.`
      document.getElementById("error-message").style.display = "block"
      return
    }

    const username = document.getElementById("username").value
    const password = document.getElementById("password").value
    const submitButton = document.getElementById("submit-button")
    const errorMessage = document.getElementById("error-message")
    const attemptsMessage = document.getElementById("attempts-message")

    submitButton.textContent = "Logging in..."
    submitButton.disabled = true
    errorMessage.style.display = "none"

    try {
      // Call the secure login API
      const response = await fetch("/api/secure/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        // Store session ID in localStorage (in a real app, use HttpOnly cookies)
        localStorage.setItem("secureSessionId", data.sessionId)
        localStorage.setItem("secureUsername", data.username)
        localStorage.setItem("secureRole", data.role)

        // Reset attempts
        attempts = 0
        attemptsMessage.style.display = "none"

        // Redirect to dashboard
        window.location.href = "dashboard.html"
      } else {
        // Handle locked account
        if (data.locked) {
          locked = true
          lockTimer = data.lockTimer
          errorMessage.textContent = data.message
          errorMessage.style.display = "block"
          submitButton.textContent = `Locked (${lockTimer}s)`
          submitButton.disabled = true

          // Start countdown
          lockInterval = setInterval(() => {
            lockTimer--
            submitButton.textContent = `Locked (${lockTimer}s)`

            if (lockTimer <= 0) {
              clearInterval(lockInterval)
              locked = false
              attempts = 0
              submitButton.textContent = "Login"
              submitButton.disabled = false
              attemptsMessage.style.display = "none"
            }
          }, 1000)
        } else {
          // Handle failed login
          attempts = data.attempts || attempts + 1
          errorMessage.textContent = data.message
          errorMessage.style.display = "block"
          attemptsMessage.textContent = `Failed login attempts: ${attempts}/5`
          attemptsMessage.style.display = "block"
          submitButton.textContent = "Login"
          submitButton.disabled = false
        }
      }
    } catch (error) {
      console.error("Login error:", error)
      errorMessage.textContent = "Login failed. Please try again."
      errorMessage.style.display = "block"
      submitButton.textContent = "Login"
      submitButton.disabled = false
    }
  })
}

// Check if we're on the secure dashboard page
if (document.getElementById("logout-button") && !document.getElementById("admin-view-button")) {
  // Check authentication
  const sessionId = localStorage.getItem("secureSessionId")
  const username = localStorage.getItem("secureUsername")
  const role = localStorage.getItem("secureRole")

  if (!sessionId || !username) {
    window.location.href = "login.html"
  }

  // Display user info
  document.getElementById("username-display").textContent = username
  document.getElementById("role-display").textContent = `Role: ${role || "user"}`
  document.getElementById("name").value = username
  document.getElementById("role").value = role || "user"

  // Show admin link if user is admin
  if (document.getElementById("admin-link") && role === "admin") {
    document.getElementById("admin-link").style.display = "inline-block"
  }

  // Tab switching
  const tabButtons = document.querySelectorAll(".tab-button")
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      // Hide all tab content
      document.querySelectorAll(".tab-content").forEach((tab) => {
        tab.classList.remove("active")
      })

      // Remove active class from all buttons
      tabButtons.forEach((btn) => {
        btn.classList.remove("active")
      })

      // Show selected tab content
      const tabId = button.getAttribute("data-tab")
      document.getElementById(`${tabId}-tab`).classList.add("active")
      button.classList.add("active")
    })
  })

  // Load comments
  async function loadComments() {
    try {
      const response = await fetch("/api/secure/comments")
      const data = await response.json()

      const commentsContainer = document.getElementById("comments-container")

      if (!data.success || data.comments.length === 0) {
        commentsContainer.innerHTML = '<p class="no-comments">No comments yet.</p>'
      } else {
        commentsContainer.innerHTML = ""

        data.comments.forEach((comment) => {
          const commentElement = document.createElement("div")
          commentElement.className = "comment"

          // Safe from XSS - using textContent instead of innerHTML
          const usernameElement = document.createElement("div")
          usernameElement.className = "comment-username"
          usernameElement.textContent = comment.username

          const contentElement = document.createElement("div")
          contentElement.className = "comment-content"
          contentElement.textContent = comment.content

          commentElement.appendChild(usernameElement)
          commentElement.appendChild(contentElement)

          commentsContainer.appendChild(commentElement)
        })
      }
    } catch (error) {
      console.error("Error loading comments:", error)
    }
  }

  loadComments()

  // Add comment
  document.getElementById("comment-form").addEventListener("submit", async (e) => {
    e.preventDefault()

    const content = document.getElementById("comment").value

    if (!content.trim()) return

    try {
      const response = await fetch("/api/secure/comments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          sessionId: localStorage.getItem("secureSessionId"),
          content,
        }),
      })

      const data = await response.json()

      if (data.success) {
        document.getElementById("comment").value = ""

        // Switch to comments tab
        document.querySelector('[data-tab="comments"]').click()

        // Reload comments
        loadComments()
      }
    } catch (error) {
      console.error("Error adding comment:", error)
    }
  })

  // Logout
  document.getElementById("logout-button").addEventListener("click", () => {
    localStorage.removeItem("secureSessionId")
    localStorage.removeItem("secureUsername")
    localStorage.removeItem("secureRole")
    window.location.href = "../index.html"
  })
}

// Check if we're on the admin page
if (document.title.includes("Admin Panel")) {
  // Check authentication and admin role
  const sessionId = localStorage.getItem("secureSessionId")
  const role = localStorage.getItem("secureRole")

  if (!sessionId) {
    window.location.href = "login.html"
  }

  // Verify admin role on the server
  async function checkAdminAccess() {
    try {
      const response = await fetch(`/api/secure/admin-check?sessionId=${sessionId}`)
      const data = await response.json()

      if (!data.success || !data.isAdmin) {
        // Redirect non-admin users
        window.location.href = "dashboard.html"
      } else {
        // Load admin data if user is admin
        loadAdminData()
      }
    } catch (error) {
      console.error("Error checking admin status:", error)
      window.location.href = "dashboard.html"
    }
  }

  // Load admin data
  async function loadAdminData() {
    try {
      const loadingIndicator = document.getElementById("loading-indicator")
      const adminContent = document.getElementById("admin-content")

      // Get users
      const usersResponse = await fetch(`/api/secure/admin/users?sessionId=${sessionId}`)
      const usersData = await usersResponse.json()

      // Get comments
      const commentsResponse = await fetch("/api/secure/comments")
      const commentsData = await commentsResponse.json()

      if (usersData.success && commentsData.success) {
        // Populate users table
        const usersTableBody = document.getElementById("users-table-body")
        usersTableBody.innerHTML = ""

        usersData.users.forEach((user) => {
          const row = document.createElement("tr")

          const idCell = document.createElement("td")
          idCell.textContent = user.id

          const usernameCell = document.createElement("td")
          usernameCell.textContent = user.username

          const roleCell = document.createElement("td")
          roleCell.textContent = user.role

          const actionsCell = document.createElement("td")
          const editButton = document.createElement("button")
          editButton.textContent = "Edit"
          editButton.className = "button outline"
          editButton.style.marginRight = "0.5rem"

          const deleteButton = document.createElement("button")
          deleteButton.textContent = "Delete"
          deleteButton.className = "button outline"
          deleteButton.style.color = "var(--red-500)"

          actionsCell.appendChild(editButton)
          actionsCell.appendChild(deleteButton)

          row.appendChild(idCell)
          row.appendChild(usernameCell)
          row.appendChild(roleCell)
          row.appendChild(actionsCell)

          usersTableBody.appendChild(row)
        })

        // Populate comments table
        const commentsTableBody = document.getElementById("comments-table-body")
        commentsTableBody.innerHTML = ""

        commentsData.comments.forEach((comment) => {
          const row = document.createElement("tr")

          const idCell = document.createElement("td")
          idCell.textContent = comment.id

          const usernameCell = document.createElement("td")
          usernameCell.textContent = comment.username

          const contentCell = document.createElement("td")
          contentCell.textContent = comment.content

          const actionsCell = document.createElement("td")
          const deleteButton = document.createElement("button")
          deleteButton.textContent = "Delete"
          deleteButton.className = "button outline"
          deleteButton.style.color = "var(--red-500)"

          actionsCell.appendChild(deleteButton)

          row.appendChild(idCell)
          row.appendChild(usernameCell)
          row.appendChild(contentCell)
          row.appendChild(actionsCell)

          commentsTableBody.appendChild(row)
        })

        // Show admin content
        loadingIndicator.style.display = "none"
        adminContent.style.display = "block"
      }
    } catch (error) {
      console.error("Error loading admin data:", error)
    }
  }

  // Check admin access when page loads
  checkAdminAccess()
}
