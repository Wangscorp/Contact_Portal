from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

mail = Mail(app)

# MongoDB setup
client = MongoClient(app.config['MONGO_URI'])
db = client.contact_portal
users_collection = db.users
contacts_collection = db.contacts

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = str(user_id)
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_id, user_data['username'])
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        if users_collection.find_one({'username': username}):
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        if users_collection.find_one({'email': email}):
            flash('Email already exists', 'error')
            return redirect(url_for('register'))

        user_data = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow()
        }
        result = users_collection.insert_one(user_data)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_data = users_collection.find_one({'username': username})
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data['_id'], user_data['username'])
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user_data = users_collection.find_one({'email': email})
        if user_data:
            token = generate_password_hash(str(datetime.utcnow()), method='pbkdf2:sha256')
            users_collection.update_one({'_id': user_data['_id']}, {'$set': {'reset_token': token, 'token_expiry': datetime.utcnow() + timedelta(hours=1)}})
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click the following link to reset your password: {url_for("reset_password", token=token, _external=True)}'
            mail.send(msg)
            flash('Password reset email sent', 'success')
        else:
            flash('Email not found', 'error')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['password']
        user_data = users_collection.find_one({'reset_token': token, 'token_expiry': {'$gt': datetime.utcnow()}})
        if user_data:
            hashed_password = generate_password_hash(password)
            users_collection.update_one({'_id': user_data['_id']}, {'$set': {'password': hashed_password, 'reset_token': None, 'token_expiry': None}})
            flash('Password reset successful. Please log in.', 'success')
            return redirect(url_for('login'))
        flash('Invalid or expired token', 'error')
        return redirect(url_for('reset_password', token=token))
    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    contacts = list(contacts_collection.find({'user_id': ObjectId(current_user.id)}))
    return render_template('dashboard.html', contacts=contacts)

@app.route('/add-contact', methods=['POST'])
@login_required
def add_contact():
    mobile = request.form['mobile']
    email = request.form['email']
    address = request.form['address']
    registration_number = request.form['registration_number']
    
    contact_data = {
        'user_id': ObjectId(current_user.id),
        'mobile': mobile,
        'email': email,
        'address': address,
        'registration_number': registration_number,
        'created_at': datetime.utcnow()
    }
    contacts_collection.insert_one(contact_data)
    flash('Contact added successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/search-contact', methods=['POST'])
@login_required
def search_contact():
    registration_number = request.form['registration_number']
    contact = contacts_collection.find_one({'user_id': ObjectId(current_user.id), 'registration_number': registration_number})
    if contact:
        return render_template('dashboard.html', contacts=[contact], searched_contact=contact)
    else:
        flash('Contact not found', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete-contact/<contact_id>', methods=['POST'])
@login_required
def delete_contact(contact_id):
    contacts_collection.delete_one({'_id': ObjectId(contact_id), 'user_id': ObjectId(current_user.id)})
    flash('Contact deleted successfully', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
