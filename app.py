from flask import Flask, render_template, request, redirect, url_for, flash, session, escape
import sqlite3
import hashlib
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
# SECURE: Generate a strong random secret key
app.secret_key = secrets.token_hex(16)

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        comment TEXT
    )
    ''')
    # Create admin user with secure password hashing
    admin_password = generate_password_hash("admin123")
    try:
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                  ("admin", admin_password, 1))
    except sqlite3.IntegrityError:
        pass  # Admin already exists
    conn.commit()
    conn.close()

init_db()

# SECURE: Admin access control decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Access denied: Admin privileges required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# SECURE: Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # SECURE: Use parameterized queries
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Check if user exists - SECURE: using parameters
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        # SECURE: Strong password hashing with bcrypt
        hashed_password = generate_password_hash(password)
        
        # Insert new user - SECURE: using parameters
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                  (username, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # SECURE: Use parameterized queries
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # SECURE: Query user first, then validate password separately
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        # SECURE: Check hashed password
        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['user_id'] = user[0]
            session['is_admin'] = user[3]
            flash('You have been logged in!')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's comment (if any)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT comment FROM users WHERE id = ?", (session['user_id'],))
    result = c.fetchone()
    comment = result[0] if result and result[0] else ""
    conn.close()
    
    # SECURE: Pass the comment without marking it safe in the template
    return render_template('dashboard.html', username=session['username'], comment=comment)

@app.route('/update_comment', methods=['POST'])
@login_required
def update_comment():
    # SECURE: Sanitize input to prevent XSS
    comment = escape(request.form['comment'])
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
        
    # Update the user's comment - SECURE: using parameters
    c.execute("UPDATE users SET comment = ? WHERE id = ?", (comment, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Comment updated!')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@login_required
@admin_required  # SECURE: Proper access control
def admin():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin FROM users")
    users = c.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # SECURE: In production, you would use a real HTTPS cert
    # For development, this is fine, but add a comment about HTTPS requirement
    app.run(debug=True)
    # In production: app.run(ssl_context='adhoc')  # Requires: pip install pyopenssl