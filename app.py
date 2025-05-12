from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'nagyontitkoskodj'

# PostgreSQL beállítás
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Modellek ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='felhasználó')  # 'adminisztrátor', 'kezelő', 'felhasználó'
    active = db.Column(db.Boolean, default=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default='Új')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Jogosultsági ellenőrző segédfüggvények ---
def is_admin():
    return 'user_id' in session and get_current_user().role == 'adminisztrátor'

def is_manager():
    return 'user_id' in session and get_current_user().role == 'kezelő'

def get_current_user():
    return User.query.get(session['user_id']) if 'user_id' in session else None

# --- Kezdőlap ---
@app.route('/')
def index():
    user = get_current_user()
    if not user or not user.active:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    if user.role == 'adminisztrátor' or user.role == 'kezelő':
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(user_id=user.id).all()

    return render_template('index.html', user=user, tasks=tasks)

# --- Regisztráció ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return 'Ez a felhasználónév már foglalt.'
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        role = 'adminisztrátor' if username == 'admin' else 'felhasználó'
        user = User(username=username, password=hashed_pw, role=role)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# --- Bejelentkezés ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.active and bcrypt.check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        return 'Hibás belépési adatok vagy tiltott fiók.'
    return render_template('login.html')

# --- Kijelentkezés ---
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# --- Új feladat ---
@app.route('/add', methods=['POST'])
def add():
    user = get_current_user()
    if user and user.active:
        title = request.form['title']
        task = Task(title=title, user_id=user.id)
        db.session.add(task)
        db.session.commit()
    return redirect(url_for('index'))

# --- Feladat státusz frissítése ---
@app.route('/update/<int:task_id>', methods=['POST'])
def update(task_id):
    user = get_current_user()
    task = Task.query.get(task_id)
    if user and user.active and task:
        if user.role == 'adminisztrátor' or task.user_id == user.id:
            task.status = request.form['status']
            db.session.commit()
    return redirect(url_for('index'))

# --- Felhasználók kezelése (admin nézet) ---
@app.route('/admin/users')
def manage_users():
    user = get_current_user()
    if not user or user.role != 'adminisztrátor':
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin_users.html', users=users, current_user=user)

@app.route('/admin/toggle/<int:user_id>')
def toggle_user(user_id):
    admin = get_current_user()
    if not admin or admin.role != 'adminisztrátor':
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user and user.username != 'admin':
        user.active = not user.active
        db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    admin = get_current_user()
    if not admin or admin.role != 'adminisztrátor':
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user:
        new_pw = bcrypt.generate_password_hash(request.form['new_password']).decode('utf-8')
        user.password = new_pw
        db.session.commit()
    return redirect(url_for('manage_users'))

# --- Indítás ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=10000, debug=True)
