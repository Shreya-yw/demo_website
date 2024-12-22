from flask import Flask, render_template, request, redirect, url_for, session, flash
from passlib.hash import sha256_crypt
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Securely generated secret key

# Mock database
users = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    if 'signup' in request.form:
        email = request.form['email']
        password = sha256_crypt.hash(request.form['password'])
        
        if email in users:
            flash('Email already exists!', 'danger')
            return redirect(url_for('index'))
        
        users[email] = password
        flash('Signup successful!', 'success')
        return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    
    if email in users and sha256_crypt.verify(password, users[email]):
        session['email'] = email
        return redirect(url_for('home'))
    else:
        flash('Invalid credentials!', 'danger')
        return redirect(url_for('index'))

@app.route('/home')
def home():
    if 'email' in session:
        return render_template('home.html')
    else:
        flash('Please login first!', 'warning')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
