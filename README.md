# Overview
This project is focused on implementing secure and vulnerable endpoints using Node.js, Express, and SQLite. The main goal is to demonstrate common web vulnerabilities and how to mitigate them, such as SQL injection and Cross-Site Scripting (XSS).

## Key Security Features Demonstrated

- **Password Storage:** Weak MD5 hashing vs. secure PBKDF2 with salt
- **XSS Prevention:** Unsanitized content vs. proper content sanitization
- **Session Management:** Insecure localStorage vs. secure session handling
- **Access Control:** Weak role verification vs. proper role-based access control
- **Rate Limiting:** No protection vs. protection against brute force attacks

## Getting Started

### Prerequisites
-Node.js (v18+)


### Installation
1. download the files (index.html /server.js /encryptingmy.js)
2. Install dependencies:
   \`\`\`
npm install express body-parser sqlite3 cookie-parser
   \`\`\`
3. Start the server:
   \`\`\`
   node server.js
   \`\`\`
4. Open your browser and navigate to:
   \`\`\`
   http://localhost:3000
   \`\`\`

## Default Login is our admin 

- Username: `admin`
- Password: `password123@`

## Security Vulnerabilities Demonstrated
1. SQL Injection Test
try login with
  \`\`\`
user: admin'--
password:  anything 
   \`\`\`
   
3. XSS Test
post a comnt with 
   \`\`\`
<img src=x onerror=alert(1)>
   \`\`\`
   
## Project Structure

- `index.html` - Main landing page with  Vulnerable version of the application and  Secure version of the application both with  JavaScript functions for client-side functionality
- `server.js` - Simple Express server with API endpoints

