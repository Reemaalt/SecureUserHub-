// Vulnerable implementation JavaScript

// Check if we're on the register page
if (document.getElementById("register-form") && !document.getElementById("password-requirements")) {
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
      // Call the vulnerable register API
      const response = await fetch("/api/vulnerable/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        // Store session ID in localStorage (insecure)
        localStorage.setItem("vulnerableSessionId", data.sessionId)
        localStorage.setItem("vulnerableUsername", data.username)
        localStorage.setItem("vulnerableRole", data.role)

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
if (document.getElementById("login-form") && !document.getElementById("attempts-message")) {
  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault()

    const username = document.getElementById("username").value
    const password = document.getElementById("password").value
    const submitButton = document.getElementById("submit-button")
    const errorMessage = document.getElementById("error-message")

    submitButton.textContent = "Logging in..."
    submitButton.disabled = true
    errorMessage.style.display = "none"

    try {
      // Call the vulnerable login API
      const response = await fetch("/api/vulnerable/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        // Store session ID in localStorage (insecure)
        localStorage.setItem("vulnerableSessionId", data.sessionId)
        localStorage.setItem("vulnerableUsername", data.username)
        localStorage.setItem("vulnerableRole", data.role)

        // Redirect to dashboard
        window.location.href = "dashboard.html"
      } else {
        errorMessage.textContent = data.message
        errorMessage.style.display = "block"
        submitButton.textContent = "Login"
        submitButton.disabled = false
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

// Check if we're on the dashboard page
if (document.getElementById("logout-button") && document.getElementById("admin-view-button")) {
  // Check authentication
  const sessionId = localStorage.getItem("vulnerableSessionId")
  const username = localStorage.getItem("vulnerableUsername")
  const role = localStorage.getItem("vulnerableRole")

  if (!sessionId || !username) {
    window.location.href = "login.html"
  }

  // Display user info
  document.getElementById("username-display").textContent = username
  document.getElementById("role-display").textContent = `Role: ${role || "user"}`
  document.getElementById("name").value = username
  document.getElementById("role").value = role || "user"
  document.getElementById("current-user").textContent = `User 2: ${username} (${role || "user"})`

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
      const response = await fetch("/api/vulnerable/comments")
      const data = await response.json()

      const commentsContainer = document.getElementById("comments-container")

      if (!data.success || data.comments.length === 0) {
        commentsContainer.innerHTML = '<p class="no-comments">No comments yet.</p>'
      } else {
        commentsContainer.innerHTML = ""

        data.comments.forEach((comment) => {
          const commentElement = document.createElement("div")
          commentElement.className = "comment"

          // Vulnerable to XSS - using innerHTML with unsanitized content
          commentElement.innerHTML = `
            <div class="comment-username">${comment.username}</div>
            <div class="comment-content">${comment.content}</div>
          `

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
      const response = await fetch("/api/vulnerable/comments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          sessionId: localStorage.getItem("vulnerableSessionId"),
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

  // Admin view toggle
  document.getElementById("admin-view-button").addEventListener("click", async () => {
    const adminPanel = document.getElementById("admin-panel")
    const adminViewButton = document.getElementById("admin-view-button")

    if (adminPanel.style.display === "none" || !adminPanel.style.display) {
      try {
        // Vulnerable admin check - no proper role verification
        const response = await fetch(`/api/vulnerable/admin-check?sessionId=${sessionId}`)
        const data = await response.json()

        if (data.success && data.isAdmin) {
          adminPanel.style.display = "block"
          adminViewButton.textContent = "Exit Admin View"
        }
      } catch (error) {
        console.error("Error checking admin status:", error)
      }
    } else {
      adminPanel.style.display = "none"
      adminViewButton.textContent = "Admin View"
    }
  })

  // Logout
  document.getElementById("logout-button").addEventListener("click", () => {
    localStorage.removeItem("vulnerableSessionId")
    localStorage.removeItem("vulnerableUsername")
    localStorage.removeItem("vulnerableRole")
    window.location.href = "../index.html"
  })
}
