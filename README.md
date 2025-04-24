# SecureUserApp

A simple Flask web application demonstrating common security vulnerabilities and their mitigations.

## Setup Instructions

1. Clone this repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Mac/Linux: `source venv/bin/activate`
4. Install dependencies: `pip install flask werkzeug`
5. Run the application: `python app.py`
6. Visit `http://127.0.0.1:5000` in your browser

## Security Features

This application demonstrates:
1. SQL Injection prevention
2. Secure password storage
3. Protection against XSS attacks
4. Role-based access control
5. Secure session management

## Testing

### Vulnerable Version
- SQL Injection: Login with username `admin' --` to bypass password check
- XSS: Enter HTML/JavaScript in the comment field
- Access Control: Access the /admin page directly as a regular user

### Secure Version
All these vulnerabilities have been fixed in the current version.

## User Accounts
- Admin: username=admin, password=admin123
- Create your own user accounts as needed
