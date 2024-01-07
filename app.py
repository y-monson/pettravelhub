'''This is a blogging app, it allows users to register, login, and
change password. Once logged in, the user can access the rest of the site'''
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length
from passlib.hash import sha256_crypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

app.config['SECRET_KEY'] = '1e7408b39468bebb40f5e80355f76b4'

#Initialize Flask-login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route("/")
@app.route("/index")
@app.route("/index.html")
def home():
    '''Function to render home page'''
    return render_template('index.html')

@app.route("/about")
@app.route("/about.html")
@login_required
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
                    # Create a User object with a unique identifier (e.g., username)
                    user = User(username)
                    # Log in the user
                    login_user(user)
                    flash('Login successful!')
                    return redirect(url_for('blog_post'))

    return render_template('login.html', title='Log in', form=form)

@app.route("/update_password", methods=['GET', 'POST'])
@app.route("/update_password.html", methods=['GET', 'POST'])
@login_required
def update_password():
    form = UpdatePasswordForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        password_new = form.password_new.data

        # Check if the new password is in the list of common passwords
        with open('CommonPassword.txt', encoding="utf-8") as f:
            common_passwords = [line.strip() for line in f]
            if password_new in common_passwords:
                flash('Password is on the common passwords list - consider choosing a stronger password!', 'warning')

        # Update password in the users.txt file
        updated_file = []
        with open('users.txt', 'r+', encoding="utf-8") as f:
            for line in f:
                user, user_pass = line.strip().split(',')
                if username == user and sha256_crypt.verify(password, user_pass):
                    hash_password_new = sha256_crypt.hash(password_new)
                    updated_file.append(f"{username},{hash_password_new}\n")
                else:
                    updated_file.append(line)

            # Write the updated content back to the file
            f.seek(0)
            f.truncate()
            f.write(''.join(updated_file))

            flash('Password update successful!', 'success')
            return redirect(url_for('home'))

    return render_template('update_password.html', title='Update password', form=form)

class BlogPostForm(FlaskForm):
    '''Blog Post Entry Form'''
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')

def save_blog_post(title, content):
    with open('blog.txt', 'a', encoding='utf-8') as f:
        f.write(f"Title: {title}\n")
        f.write(f"Content: {content}\n\n")

def read_blog_posts():
    with open('blog.txt', 'r', encoding='utf-8') as f:
        posts = f.readlines()

        # Create a list of dictionaries, each containing title and content
        formatted_posts = []
        current_post = {}
        for line in posts:
            if line.startswith('Title: '):
                current_post['title'] = line[len('Title: '):].strip()
            elif line.startswith('Content: '):
                current_post['content'] = line[len('Content: '):].strip()
                formatted_posts.append({'title': current_post['title'], 'content': current_post['content']})

        # Reverse the order of the list to display the most recent post first
        reversed_posts = reversed(formatted_posts)
        return list(reversed_posts)

@app.route("/blog_post", methods=['GET', 'POST'])
@app.route("/blog_post.html", methods=['GET', 'POST'])
@login_required
def blog_post():
    form = BlogPostForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        save_blog_post(title, content)

        # Clear the form data for a new entry
        form.title.data = ''
        form.content.data = ''

    # Read all blog posts for display
    blog_posts = read_blog_posts()

    return render_template('blog_post.html', title='Blog Post Entry', form=form, blog_posts=blog_posts)

if __name__ == '__main__':
    login_manager.init_app(app)
    app.run()

