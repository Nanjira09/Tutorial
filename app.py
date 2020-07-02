from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_wtf.file import FileField, FileAllowed
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, UserMixin, current_user, logout_user, login_required
from datetime import datetime
import secrets
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///post.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = '55b31186c97bbd468b3417c248ab6417'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'abdul.nanjira@gmail.com'
app.config['MAIL_PASSWORD'] = 'jhvbqzenaauzhfqa'
mail = Mail(app)


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(40), nullable=False)
    author = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return 'Blog ' + str(self.id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return 'User ' + str(self.id)


class RegistrationForm(Form):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password', message='Password do not match!')])

    def validate_username(self, username):
        username = User.query.filter_by(username=username.data).first()
        if username:
            raise ValidationError('That Username Already Taken! Please Choose Another One.')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('That Email Already Taken! please Choose Another One.')


class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')


class UpdateAccountForm(Form):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Pic', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])

    def validate_username(self, username):
        if username.data != current_user.username:
            username = User.query.filter_by(username=username.data).first()
            if username:
                raise ValidationError('That Username Already Taken! Please Choose Another One.')

    def validate_email(self, email):
        if email.data != current_user.email:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError('That Email Already Taken! please Choose Another One.')


class RequestResetForm(Form):
    email = StringField('Email', validators=[DataRequired(), Email()])

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email is None:
            raise ValidationError('There is no Account with that Email.Please Register.')


class ResetPasswordForm(Form):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password', message='Password do not match!')])


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('post'))
    if request.method == 'POST' and form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        username = form.username.data
        email = form.email.data
        password = hashed_password
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your Account has been Registered Successfully', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('post'))
    if request.method == 'POST' and form.validate():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('post'))
        else:
            flash('login Unsuccessful,Check Your Email and Password and Try Again.')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/account')
def account():
    image_file = url_for('static', filename='profile_pics/ ' + current_user.image_file)
    return render_template('account.html', image_file=image_file)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('post'))
    form = RequestResetForm(request.form)
    if form.validate():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An Email has been send with Instructions to Reset your Password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('post'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an Invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your Password has been Updated.You can now Login!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)


@app.route('/update', methods=['GET', 'POST'])
def update():
    form = UpdateAccountForm(request.form)
    if request.method == 'POST' and form.validate():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your Account was Updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('update.html', form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='securesally@gmail.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be done.
'''
    mail.send(msg)


@app.route('/post')
@login_required
def post():
    page = request.args.get('page', 1, type=int)
    posts = Blog.query.order_by(Blog.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('post.html', posts=posts)


@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        blog_title = request.form['title']
        blog_author = request.form['author']
        blog_content = request.form['content']
        new_post = Blog(title=blog_title, author=blog_author, content=blog_content)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('post'))
    return render_template('add.html')


@app.route('/post/delete/<int:id>')
def delete(id):
    post = Blog.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('post'))


@app.route('/post/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    post = Blog.query.get_or_404(id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.author = request.form['author']
        post.content = request.form['content']
        db.session.commit()
        return redirect(url_for('post'))
    return render_template('edit.html', post=post)


if __name__ == '__main__':
    app.run(debug=True)