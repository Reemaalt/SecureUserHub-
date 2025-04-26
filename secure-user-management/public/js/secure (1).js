// Check if we're on the register page
if (document.getElementById('register-form') && document.getElementById('password')) {
  const passwordInput = document.getElementById('password');
  const submitButton = document.getElementById('submit-button');
  
  // Password strength validation
  passwordInput.addEventListener('input', () => {
    const password = passwordInput.value;
    
    const hasMinLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[^A-Za-z0-9]/.test(password);
    
    document.getElementById('length-check').className = hasMinLength ? 'requirement-pass' : 'requirement-fail';
    document.getElementById('uppercase-check').className = hasUppercase ? 'requirement-pass' : 'requirement-fail';
    document.getElementById('lowercase-check').className = hasLowercase ? 'requirement-pass' : 'requirement-fail';
    document.getElementById('number-check').className = hasNumber ? 'requirement-pass' : 'requirement-fail';
    document.getElementById('special-check').className = hasSpecialChar ? 'requirement-pass' : 'requirement-fail';
    
    const isPasswordStrong = hasMinLength && hasUppercase && hasLowercase && hasNumber && hasSpecialChar;
    submitButton.disabled = !isPasswordStrong;
  });
  
  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorMessage = document.getElementById('error-message');
    
    submitButton.textContent = 'Registering...';
    submitButton.disabled = true;
    errorMessage.style.display = 'none';
    
    try {
      const response = await fetch('/api/secure/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      
      if (data.success) {
        // Store session ID in localStorage (in a real app, use HttpOnly cookies)
        localStorage.setItem('secureSessionId', data.sessionId);
        localStorage.setItem('secureUsername', data.username);
        localStorage.setItem('secureRole', data.role);
        
        // Redirect to dashboard
        window.location.href = '/secure/dashboard';
      } else {
        errorMessage.textContent = data.message;
        errorMessage.style.display = 'block';
        submitButton.textContent = 'Register';
        submitButton.disabled = false;
      }
    } catch (error) {
      errorMessage.textContent = 'Registration failed. Please try again.';
      errorMessage.style.display = 'block';
      submitButton.textContent = 'Register';
      submitButton.disabled = false;
    }
  });
}

// Check if we're on the login page
if (document.getElementById('login-form') && !document.getElementById('password-requirements')) {
  let attempts = 0;
  let locked = false;
  
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    if (locked) {
      document.getElementById('error-message').textContent = 'Account temporarily locked due to too many failed attempts. Please try again later.';
      document.getElementById('error-message').style.display = 'block';
      return;
    }
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const submitButton = document.getElementById('submit-button');
    const errorMessage = document.getElementById('error-message');
    const attemptsMessage = document.getElementById('attempts-message');
    
    submitButton.textContent = 'Logging in...';
    submitButton.disabled = true;
    errorMessage.style.display = 'none';
    
    try {
      const response = await fetch('/api/secure/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      
      if (data.success) {
        // Store session ID in localStorage (in a real app, use HttpOnly cookies)
        localStorage.setItem('secureSessionId', data.sessionId);
        localStorage.setItem('secureUsername', data.username);
        localStorage.setItem('secureRole', data.role);
        
        // Reset attempts
        attempts = 0;
        if (attemptsMessage) attemptsMessage.style.display = 'none';
        
        // Redirect to dashboard
        window.location.href = '/secure/dashboard';
      } else {
        attempts++;
        
        if (attempts >= 5) {
          locked = true;
          errorMessage.textContent = 'Account temporarily locked due to too many failed attempts. Please try again later.';
          errorMessage.style.display = 'block';
          submitButton.textContent = 'Account Locked';
          submitButton.disabled = true;
          
          // Unlock after 1 minute (in a real app, this would be longer and server-side)
          setTimeout(() => {
            locked = false;
            attempts = 0;
            submitButton.textContent = 'Login';
            submitButton.disabled = false;
            if (attemptsMessage) attemptsMessage.style.display = 'none';
          }, 60000);
        } else {
          errorMessage.textContent = data.message;
          errorMessage.style.display = 'block';
          if (attemptsMessage) {
            attemptsMessage.textContent = `Failed login attempts: ${attempts}/5`;
            attemptsMessage.style.display = 'block';
          }
          submitButton.textContent = 'Login';
          submitButton.disabled = false;
        }
      }
    } catch (error) {
      errorMessage.textContent = 'Login failed. Please try again.';
      errorMessage.style.display = 'block';
      submitButton.textContent = 'Login';
      submitButton.disabled = false;
    }
  });
}

// Check if we're on the dashboard page
if (document.getElementById('logout-button') && !document.getElementById('admin-view-button')) {
  // Check authentication
  const sessionId = localStorage.getItem('secureSessionId');
  const username = localStorage.getItem('secureUsername');
  const role = localStorage.getItem('secureRole');
  
  if (!sessionId || !username) {
    window.location.href = '/secure/login';
  }
  
  // Display user info
  if (document.getElementById('username-display')) {
    document.getElementById('username-display').textContent = username;
    document.getElementById('role-display').textContent = role || 'user';
  }
  
  // Show admin link if user is admin
  if (document.getElementById('admin-link') && role === 'admin') {
    document.getElementById('admin-link').style.display = 'inline-block';
  }
  
  // Tab switching
  const tabButtons = document.querySelectorAll('.tab-button');
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      // Hide all tab content
      document.querySelectorAll('.tab-content').forEach(tab => {
        tab.style.display = 'none';
      });
      
      // Remove active class from all buttons
      tabButtons.forEach(btn => {
        btn.classList.remove('active');
      });
      
      // Show selected tab content
      const tabId = button.getAttribute('data-tab');
      document.getElementById(`${tabId}-tab`).style.display = 'block';
      button.classList.add('active');
    });
  });
  
  // Load comments
  async function loadComments() {
    try {
      const response = await fetch('/api/secure/comments');
      const data = await response.json();
      
      if (data.success) {
        const commentsContainer = document.getElementById('comments-container');
        
        if (data.comments.length === 0) {
          commentsContainer.innerHTML = '<p class="no-comments">No comments yet.</p>';
        } else {
          commentsContainer.innerHTML = '';
          
          data.comments.forEach(comment => {
            const commentElement = document.createElement('div');
            commentElement.className = 'comment';
            
            // Safe from XSS - using textContent instead of innerHTML
            const usernameElement = document.createElement('div');
            usernameElement.className = 'comment-username';
            usernameElement.textContent = comment.username;
            
            const contentElement = document.createElement('div');
            contentElement.className = 'comment-content';
            contentElement.textContent = comment.content;
            
            commentElement.appendChild(usernameElement);
            commentElement.appendChild(contentElement);
            
            commentsContainer.appendChild(commentElement);
          });
        }
      }
    } catch (error) {
      console.error('Error loading comments:', error);
    }
  }
  
  if (document.getElementById('comments-container')) {
    loadComments();
  }
  
  // Add comment
  if (document.getElementById('comment-form')) {
    document.getElementById('comment-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const content = document.getElementById('comment').value;
      
      if (!content.trim()) return;
      
      try {
        const response = await fetch('/api/secure/comments', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ sessionId, content })
        });
        
        const data = await response.json();
        
        if (data.success) {
          document.getElementById('comment').value = '';
          
          // Switch to comments tab
          document.querySelector('[data-tab="comments"]').click();
          
          // Reload comments
          loadComments();
        }
      } catch (error) {
        console.error('Error adding comment:', error);
      }
    });
  }
  
  // Logout
  document.getElementById('logout-button').addEventListener('click', () => {
    localStorage.removeItem('secureSessionId');
    localStorage.removeItem('secureUsername');
    localStorage.removeItem('secureRole');
    window.location.href = '/';
  });
}

// Check if we're on the admin page
if (document.title.includes('Admin Panel')) {
  // Check authentication and admin role
  const sessionId = localStorage.getItem('secureSessionId');
  
  async function checkAdmin() {
    try {
      const response = await fetch(`/api/secure/admin-check?sessionId=${sessionId}`);
      const data = await response.json();
      
      if (!data.success || !data.isAdmin) {
        window.location.href = '/secure/login';
      }
    } catch (error) {
      console.error('Error checking admin status:', error);
      window.location.href = '/secure/login';
    }
  }
  
  if (!sessionId) {
    window.location.href = '/secure/login';
  } else {
    checkAdmin();
  }
}