# Web Security Demonstration

This project demonstrates common web security vulnerabilities and their mitigations. It includes two versions of the same application:

## Vulnerable Version
The vulnerable version contains intentional security flaws to demonstrate what can go wrong when security best practices are not followed.

## Secure Version
The secure version implements proper security measures to mitigate the vulnerabilities present in the vulnerable version.

## Key Security Features Demonstrated

- **Password Storage:** Weak MD5 hashing vs. secure PBKDF2 with salt
- **XSS Prevention:** Unsanitized content vs. proper content sanitization
- **Session Management:** Insecure localStorage vs. secure session handling
- **Access Control:** Weak role verification vs. proper role-based access control
- **Rate Limiting:** No protection vs. protection against brute force attacks

## Getting Started

### Prerequisites
- Node.js (v14 or higher)

### Installation

1. download the files
2. Install dependencies:
   \`\`\`
  -------------
   \`\`\`
3. Start the server:
   \`\`\`
  -----------
   \`\`\`
4. Open your browser and navigate to:
   \`\`\`
   http://localhost:3000
   \`\`\`

## Default Login

- Username: `admin`
- Password: `password123`

- Username: `user1`
- Password: `password123456`

## Security Vulnerabilities Demonstrated

### Vulnerable Version

1. **Weak Password Storage**
   - Uses MD5 hashing which is vulnerable to rainbow table attacks
   - No salt is used, making identical passwords have identical hashes

2. **Cross-Site Scripting (XSS)**
   - Comments are not sanitized before being displayed
   - Try posting: `----------` in the comments

3. **Insecure Session Management**
   - Session IDs stored in localStorage (accessible to JavaScript)
   - No session expiration

4. **Broken Access Controls**
   - Any authenticated user can access admin functionality
   - No proper role verification

5. **No Rate Limiting**
   - No protection against brute force attacks
   - Unlimited login attempts allowed

### Secure Version

1. **Secure Password Storage**
   - Uses PBKDF2 with salt for password hashing
   - Enforces password strength requirements

2. **XSS Prevention**
   - All user input is sanitized before being displayed
   - Uses textContent instead of innerHTML

3. **Secure Session Management**
   - Sessions have expiration times
   - Better session ID generation

4. **Proper Access Controls**
   - Server-side verification of user roles
   - Proper authorization checks

5. **Rate Limiting**
   - Limits failed login attempts
   - Implements account lockout after too many failed attempts

## Project Structure

- `index.html` - Main landing page with  Vulnerable version of the application and  Secure version of the application both with  JavaScript functions for client-side functionality
- `server.js` - Simple Express server with API endpoints

