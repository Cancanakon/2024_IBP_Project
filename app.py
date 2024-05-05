from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired, Length
import os
from wtforms import TextAreaField
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')
    announcements = db.relationship('Announcement', backref='author', lazy=True)
    messages = db.relationship('Message', backref='sender', lazy=True)
# Admin paneline kullanıcıları gösterme
@app.route('/users_list')
def users_list():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    admin_user = User.query.get(session['user_id'])
    users = User.query.all()
    return render_template('users_list.html', admin_user=admin_user, users=users)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    read = db.Column(db.Boolean, default=False)

# Form Classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class AnnouncementForm(FlaskForm):
    content = TextAreaField('Announcement', validators=[InputRequired(), Length(min=1, max=200)])

class UserAddForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('user', 'User')], validators=[InputRequired()])
    profile_pic = FileField('Profile Picture', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Images only!')])

# Create the database
with app.app_context():
    db.create_all()

# Home Page
@app.route('/')
def index():
    return render_template('index.html')

# Admin login page and panel
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, role='admin').first()
        if user and user.password == form.password.data:
            session['user_id'] = user.id  # Store admin user id in session
            return redirect(url_for('admin_panel'))
        else:
            flash('Incorrect username or password!', 'error')
    return render_template('admin_login.html', form=form)

@app.route('/admin/panel')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    admin_user = User.query.get(session['user_id'])
    announcements = Announcement.query.all()
    users = User.query.filter_by(role='user').all()
    messages = Message.query.all()
    return render_template('admin_panel.html', admin_user=admin_user, announcements=announcements, users=users,
                           messages=messages,current_user=admin_user)

@app.route('/admin/add_user', methods=['GET', 'POST'])
def add_user():
    form = UserAddForm()
    if form.validate_on_submit():
        if form.profile_pic.data:
            picture_file = save_picture(form.profile_pic.data)
        else:
            picture_file = 'default.jpg'
        new_user = User(username=form.username.data, password=form.password.data, role=form.role.data, profile_pic=picture_file)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('add_user.html', form=form)

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_fn)
    form_picture.save(picture_path)
    return picture_fn

# User login page and panel
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, role='user').first()
        if user and user.password == form.password.data:
            session['user_id'] = user.id  # Store user id in session
            return redirect(url_for('user_panel'))
        else:
            flash('Incorrect username or password!', 'error')
    return render_template('user_login.html', form=form)

@app.route('/user/panel')
def user_panel():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    current_user = User.query.get(session['user_id'])
    announcements = Announcement.query.all()
    messages = Message.query.filter_by(user_id=current_user.id).all()
    return render_template('user_panel.html', current_user=current_user, announcements=announcements, messages=messages)

if __name__ == '__main__':
    app.run(debug=True)
