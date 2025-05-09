# Web Security Project 

## Overview

This project is focused on implementing secure and vulnerable endpoints using Node.js, Express, and SQLite. The main goal is to demonstrate common web vulnerabilities and how to mitigate them, such as SQL injection and Cross-Site Scripting (XSS).

## Key Security Features Demonstrated

* **Password Storage:** Weak MD5 hashing vs. secure PBKDF2 with salt
* **XSS Prevention:** Unsanitized content vs. proper content sanitization
* **Session Management:** Insecure localStorage vs. secure session handling
* **Access Control:** Weak role verification vs. proper role-based access control
* **Rate Limiting:** No protection vs. protection against brute force attacks

## Getting Started

### Prerequisites

* Node.js (v18+)

### Installation

1. Download the files (index.html, server.js, encryptingmy.js)
2. Install dependencies:

   ```bash
   npm install express body-parser sqlite3 cookie-parser
   ```
3. Start the server:

   ```bash
   node server.js
   ```
4. Open your browser and navigate to:

   ```
   http://localhost:3000
   ```

## Default Login (Admin)

* Username: `admin`
* Password: `password123@`

## Security Vulnerabilities Demonstrated

1. **SQL Injection Test**

   * Try logging in with:

     ```
     Username: admin'--
     Password: anything
     ```

2. **XSS Test**

   * Post a comment with:

     ```html
     <img src=x onerror=alert(1)>
     ```

## Project Structure

* `index.html` - Main landing page containing both the vulnerable and secure versions of the application, with JavaScript functions for client-side functionality.
* `server.js` - Simple Express server with API endpoints.
* `encryptingmy.js ` - hold the encryption and decryption functions with the key initialization 
