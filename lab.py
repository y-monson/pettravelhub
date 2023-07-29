'''This is a blog app'''
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from passlib.hash import sha256_crypt

app = Flask(__name__)

app.config['SECRET_KEY'] = '1e7408b39468bebb40f5e80355f76b4'

@app.route("/")
@app.route("/index")
@app.route("/index.html")
def home():
    '''Function to render home page'''
    return render_template('index.html')

@app.route("/about")
@app.route("/about.html")
def about():
    '''Function to render about page'''
    return render_template('about.html')

class RegistrationForm(FlaskForm):
    '''Registration form'''
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12, max=32)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    '''Login Form'''
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign in')

class UpdatePasswordForm(FlaskForm):
    '''Update password'''
    #flask_change_password = ChangePassword(min_password_length=12)
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Current Password', validators=[DataRequired()])
    password_new = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route("/register", methods=['GET', 'POST'])
@app.route("/register.html", methods=['GET', 'POST'])
def register():
    '''Function to render login page'''
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        hash_pass = sha256_crypt.hash(form.password.data)

        with open('users.txt', 'a', encoding="utf-8") as f:
            f.write(f"{username},{hash_pass}\n")
        flash('Thank you for registering! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
@app.route("/login.html", methods=['GET', 'POST'])
def login():
    '''Function to render login page'''
    form = LoginForm()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open('users.txt') as f:
            for line in f:
                user_on_file, pd_on_file = line.strip().split(',')
                if username == user_on_file and sha256_crypt.verify(password, pd_on_file):
                    session['username'] = username
                    flash('Login successful!')
                    return redirect(url_for('home'))
    return render_template('login.html', title='Log in', form=form)

@app.route("/update_password", methods=['GET', 'POST'])
@app.route("/update_password.html", methods=['GET', 'POST'])
def update_password():
    '''Function to update password'''
    form = UpdatePasswordForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        password_new = form.password_new.data

        with open('CommonPassword.txt', encoding="utf-8") as f:
            common_passwords = [line.strip() for line in f]
            for i in common_passwords:
                if i == password_new:
                    flash('Password is on the common passwords list - easy to guess!', 'error')
                    return redirect(url_for('update_password'))

        with open('users.txt', 'r+', encoding="utf-8") as f:
            for line in f:
                user, user_pass = line.strip().split(',')
                if ((username == user) and (sha256_crypt.verify(password, user_pass))):
                    hash_password_new = sha256_crypt.hash(password_new)
                    new_line = f"{username},{hash_password_new}\n"
                    updated_file = []
                    with open('users.txt', 'r', encoding="utf-8") as f2:
                        for line2 in f2:
                            if line2.strip().split(',')[0] == username:
                                updated_file.append(new_line)
                        with open('users.txt', 'w', encoding="utf-8") as f2:
                            f2.write(''.join(updated_file))
                    flash('Password update successful!')
                    return redirect(url_for('home'))

    return render_template('update_password.html', title='Update password', form=form)

if __name__ == '__main__':
    app.run(debug=True)
