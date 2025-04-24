from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Insecure for demonstration

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    # Create admin user for testing
    admin_password = hashlib.md5("admin123".encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                  ("admin", admin_password, 1))
    except sqlite3.IntegrityError:
        pass  # Admin already exists
    conn.commit()
    conn.close()

init_db()

# Insecure password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: SQL Injection in registration
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Check if user exists - VULNERABLE to SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}'"
        c.execute(query)
        if c.fetchone():
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        # VULNERABLE: Weak password hashing (MD5)
        hashed_password = hash_password(password)
        
        # Insert new user - VULNERABLE to SQL injection
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed_password}')"
        c.execute(query)
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
        
        # VULNERABLE: SQL Injection in login
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # VULNERABLE: Direct string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            session['user_id'] = user[0]
            session['is_admin'] = user[3]
            flash('You have been logged in!')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.')
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please login first')
        return redirect(url_for('login'))
    
    # Get user's comment (if any)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT comment FROM users WHERE id = ?", (session['user_id'],))
    result = c.fetchone()
    comment = result[0] if result and result[0] else ""
    conn.close()
    
    return render_template('dashboard.html', username=session['username'], comment=comment)

@app.route('/update_comment', methods=['POST'])
def update_comment():
    if 'username' not in session:
        flash('Please login first')
        return redirect(url_for('login'))
    
    # VULNERABLE: XSS vulnerability (no input sanitization)
    comment = request.form['comment']
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # First, add the comment column if it doesn't exist
    try:
        c.execute("ALTER TABLE users ADD COLUMN comment TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
        
    # Update the user's comment
    c.execute("UPDATE users SET comment = ? WHERE id = ?", (comment, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Comment updated!')
    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    # VULNERABLE: Improper access control
    # Anyone can access this page by directly entering the URL
    
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
    app.run(debug=True)