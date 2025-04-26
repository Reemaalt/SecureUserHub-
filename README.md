secure-user-management/
├── config/
│   └── db.js
├── routes/
│   ├── vulnerable.js
│   └── secure.js
├── public/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   ├── vulnerable.js
│   │   └── secure.js
│   ├── index.html
│   ├── vulnerable/
│   │   ├── register.html
│   │   ├── login.html
│   │   └── dashboard.html
│   └── secure/
│       ├── register.html
│       ├── login.html
│       └── dashboard.html
├── app.js
└── package.json

###  Install Dependencies

Navigate to the project directory and install the dependencies:

```shellscript
cd secure-user-management
npm install
```

### 4. Start the Server

Start the application:

```shellscript
npm start
```

The server will start running on [http://localhost:3000](http://localhost:3000).

### 5. Access the Application

Open your web browser and navigate to:

- [http://localhost:3000](http://localhost:3000)


From there, you can choose between the vulnerable and secure implementations.

## Testing the Vulnerabilities

### 1. SQL Injection

- Try logging in with username: `admin' --` and any password
- This bypasses the password check in the vulnerable version


### 2. XSS (Cross-Site Scripting)

- In the vulnerable version, post a comment with: `<script>alert('XSS')</script>`
- The script will execute when viewing comments


### 3. Access Control

- In the vulnerable version, any user can access the admin panel by clicking "Admin View"
- In the secure version, only users with the admin role can access the admin panel


### 4. Default Admin Account

- Username: `admin`
- Password: `password123`


## Security Features Implemented

1. **SQL Injection Protection**: Parameterized queries
2. **Password Security**: Strong hashing with salt
3. **XSS Protection**: Input sanitization
4. **Access Control**: Role-based access control
5. **Session Management**: Secure sessions with expiration
6. **Brute Force Protection**: Account lockout after multiple failed attempts
7. **Input Validation**: Strict validation for usernames and passwords


This application demonstrates both vulnerable and secure implementations side by side, making it easy to understand common web security vulnerabilities and how to mitigate them.
