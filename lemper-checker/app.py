from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from passlib.hash import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Ganti dengan kunci rahasia yang kuat
app.config['SESSION_TYPE'] = 'filesystem'

# Konfigurasi database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost/lemper'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Inisialisasi Flask-Login
# LoginManager menyediakan alat yang sangat membantu dalam manajemen autentikasi pengguna
login_manager = LoginManager()
login_manager.init_app(app)

# Model user
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255))
    student_id = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.verify(password, user.password):
            login_user(user)
            flash('Login successful!', 'success')
            session['logged_in'] = True  # Menyimpan status login dalam sesi
            return redirect(url_for('dashboard'))

        flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html')

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    session['logged_in'] = False  # Mengubah status login dalam sesi
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        student_id = request.form['student_id']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)

        new_user = User(full_name=full_name, student_id=student_id, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
