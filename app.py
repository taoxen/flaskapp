from flask import Flask, render_template, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from forms import LoginForm, RegisterForm

app = Flask(__name__)
app.config['SECRET_KEY'] = "Thisisasecretkey!!"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://sql12209738:HnugljBG7p@sql12.freemysqlhosting.net/sql12209738'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define a base model for other database tables to inherit
class Base(db.Model):

    __abstract__  = True

    id            = db.Column(db.Integer, primary_key=True)
    date_created  = db.Column(db.DateTime,  default=db.func.current_timestamp())
    date_modified = db.Column(db.DateTime,  default=db.func.current_timestamp(),
                                           onupdate=db.func.current_timestamp())

# Define a User model
class User(Base, UserMixin):

    __tablename__ = 'auth_user'

    # User Name
    name    = db.Column(db.String(128),  nullable=False)

    # Identification Data: email & password
    email    = db.Column(db.String(128),  nullable=False,
                                            unique=True)
    password = db.Column(db.String(192),  nullable=False)

    # Authorisation Data: role & status
    role     = db.Column(db.SmallInteger, nullable=False)
    status   = db.Column(db.SmallInteger, nullable=False)

    # New instance instantiation procedure
    def __init__(self, name, email, password):

        self.name     = name
        self.email    = email
        self.password = password

    def __repr__(self):
        return '<User %r>' % (self.name)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
	user = User.query.filter_by(name=form.username.data).first()
	if user:
	    if check_password_hash(user.password, form.password.data):
		login_user(user, remember=form.remember.data)

		return redirect(url_for('dashboard'))
	return '<h3>Invalid username or password<h3>'

	return '<h3>' + form.username.data + ' ' + form.password.data + '</h3>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
	flash('all is well')
	hashed_password = generate_password_hash(form.password.data, method='sha256')
	new_user = User(name=form.username.data, password=hashed_password, email=form.email.data)
	new_user.role = 1
	new_user.status = 1
	db.session.add(new_user)
	db.session.commit()

	return '<h3>New user has been created</h3>'
	#return '<h3>' + form.username.data + ' ' + form.password.data + ' ' + form.email.data + '</h3>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.name)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='192.168.0.201', debug=True)
