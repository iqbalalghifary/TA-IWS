from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from passlib.hash import bcrypt
from models.user import db, User

user_routes = Blueprint('user_routes', __name__)

@approute('/')
def home():
    return render_template('index.html')

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response

@user_routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.verify(password, user.password):
            login_user(user)
            flash('Login successful!', 'success')
            session['logged_in'] = True
            return redirect(url_for('user.dashboard'))

        flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html')

@user_routes.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    session['logged_in'] = False
    return redirect(url_for('user.login'))

@user_routes.route('/signup', methods=['GET', 'POST'])
def signup():
    db = getattr(current_app, 'db', None)
    if db is None:
        raise RuntimeError('No database found for user_bp. Make sure to pass db when registering the Blueprint.')
    if request.method == 'POST':
        full_name = request.form['full_name']
        student_id = request.form['student_id']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('user.login'))

        hashed_password = bcrypt.hash(password)

        new_user = User(full_name=full_name, student_id=student_id, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in.', 'success')
        return redirect(url_for('user.login'))

    return render_template('signup.html')

@user_routes.route('/dashboard')
@login_required
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('user.login'))
    return render_template('dashboard.html')
