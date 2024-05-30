from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Length
import os
import secrets
from datetime import datetime, timedelta

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
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Yeni sütun eklendi
    announcements = db.relationship('Announcement', backref='author', lazy=True)
    messages_sent = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    messages_received = db.relationship('Message', backref='receiver', lazy=True, foreign_keys='Message.receiver_id')

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Yeni sütun

# Form Classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class AnnouncementForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=1, max=100)])
    content = TextAreaField('Announcement', validators=[InputRequired(), Length(min=1, max=200)])

class UserAddForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('user', 'User')], validators=[InputRequired()])
    profile_pic = FileField('Profile Picture', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Images only!')])

class SendMessageForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(max=100)])
    content = TextAreaField('Message', validators=[InputRequired(), Length(min=1, max=200)])

# Create the database
with app.app_context():
    db.create_all()

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
    return render_template('admin_panel.html', admin_user=admin_user, announcements=announcements, users=users, messages=messages, current_user=admin_user)

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

@app.route('/admin/users')
def users_list():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    admin_user = User.query.get(session['user_id'])
    users = User.query.all()
    return render_template('users_list.html', admin_user=admin_user, users=users)

@app.route('/user/update/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('users_list'))
    return render_template('update_user.html', user=user)

@app.route('/user/delete/<int:user_id>')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users_list'))

@app.route('/api/user_registration_data')
def user_registration_data():
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(hours=1)  # Son 1 saatlik zaman dilimini baz al

    data = []
    current_date = start_date
    while current_date <= end_date:
        next_date = current_date + timedelta(minutes=1)
        count = User.query.filter(User.created_at.between(current_date, next_date)).count()
        current_date_str = current_date.strftime('%Y-%m-%d %H:%M:%S')
        data.append((current_date_str, count))
        current_date = next_date

    dates = [date for date, count in data]
    counts = [count for date, count in data]

    return jsonify({"dates": dates, "counts": counts})

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
    messages = Message.query.filter_by(receiver_id=current_user.id).all()
    return render_template('user_panel.html', current_user=current_user, announcements=announcements, messages=messages)

@app.route('/api/user_role_stats')
def user_role_stats():
    roles = db.session.query(User.role, db.func.count(User.role)).group_by(User.role).all()
    role_data = {
        "roles": [role for role, count in roles],
        "counts": [count for role, count in roles]
    }
    return jsonify(role_data)

@app.route('/user/send_message', methods=['GET', 'POST'])
def send_message():
    form = SendMessageForm()
    if form.validate_on_submit():
        receiver_id = request.args.get('receiver_id')  # Get receiver id from URL parameter
        message_title = form.title.data
        message_content = form.content.data
        new_message = Message(title=message_title, content=message_content, sender_id=session['user_id'], receiver_id=receiver_id, timestamp=datetime.utcnow())
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent successfully!', 'success')
        return redirect(url_for('user_panel'))
    return render_template('send_message.html', form=form)

@app.route('/admin/messages')
def admin_messages():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    admin_user = User.query.get(session['user_id'])
    all_messages = Message.query.all()  # Tüm mesajları al
    return render_template('admin_messages.html', admin_user=admin_user, all_messages=all_messages)

@app.route('/admin/messages/<int:message_id>/read', methods=['GET'])
def read_message(message_id):
    message = Message.query.get_or_404(message_id)
    message.read = True
    db.session.commit()
    flash('Message marked as read!', 'success')
    return redirect(url_for('message_detail', message_id=message_id))

@app.route('/admin/messages/<int:message_id>')
def message_detail(message_id):
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    admin_user = User.query.get(session['user_id'])
    message = Message.query.get_or_404(message_id)
    return render_template('message_detail.html', admin_user=admin_user, message=message)

@app.route('/admin/messages/<int:message_id>/reply', methods=['GET', 'POST'])
def reply_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    admin_user = User.query.get(session['user_id'])
    original_message = Message.query.get_or_404(message_id)

    form = SendMessageForm()
    if form.validate_on_submit():
        message_title = form.title.data
        message_content = form.content.data
        new_message = Message(title=message_title, content=message_content, sender_id=admin_user.id, receiver_id=original_message.sender_id)
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent successfully!', 'success')
        return redirect(url_for('admin_messages'))

    return render_template('reply_message.html', admin_user=admin_user, original_message=original_message, form=form)

@app.route('/announcement_list')
def announcement_list():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    current_user = User.query.get(session['user_id'])
    announcements = Announcement.query.all()
    return render_template('announcement_list.html', current_user=current_user, announcements=announcements)

@app.route('/admin/add_announcement', methods=['GET', 'POST'])
def add_announcement():
    form = AnnouncementForm()
    if form.validate_on_submit():
        announcement = Announcement(title=form.title.data, content=form.content.data, user_id=session['user_id'])
        db.session.add(announcement)
        db.session.commit()
        flash('Duyuru başarıyla eklendi!', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('add_announcement.html', form=form)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
