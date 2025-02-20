from flask import Flask, render_template, Response, redirect, url_for, session, request, flash, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps


#########################################################################################################################
app = Flask(__name__) # initializing
app.secret_key = 'your_secret_key'  # Secure random key should be used in production

# Configuring SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#########################################################################################################################
#Database Model
# User model
class User(db.Model):
    """User Model"""
    userid = db.Column(db.String(10), primary_key=True, unique=True, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
#########################################################################################################################
# Role-based access control decorator
def role_required(role):
    """Decorator to require a specific role for accessing a route."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            user = User.query.filter_by(username=session['username']).first()
            if user.role != role:
                return redirect(url_for('index'))  # Redirect to the home page if unauthorized
            return func(*args, **kwargs)
        return wrapper
    return decorator

#########################################################################################################################
#routes
@app.route("/")
def index():
    """Displays a Page based on the session of the current user"""
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        print(f"User in session: {user.username}, Role: {user.role}")  # Log the session user and role
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        elif user.role == 'student':
            return redirect(url_for('student_dashboard'))
    return render_template('index.html')

#not using now
@app.route("/vidnoeo")
def vidnoeo():
    return Response(
        generate_frame(), mimetype="multipart/x-mixed-replace; boundary=frame"
    )

#########################################################################################################################
#route for register
@app.route("/register", methods=["GET", "POST"])
def register():
    """Handle user registration."""
    if request.method == "POST":
        username = request.form['username']
        userid = request.form['userid']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        role = request.form.get('role', 'student')  # Default to 'student' if not provided

        # Check if passwords match
        if password != confirm_password:
            return render_template('auth/register.html', error="Passwords do not match.")
        
        # Check if the userid already exists in the database
        existing_user = User.query.filter_by(userid=userid).first()
        if existing_user:
            return render_template('auth/register.html', error="User ID already exists.")
        
        # Create a new user with the selected role
        new_user = User(username=username, userid=userid, role=role)  # Use the role passed by the form
        new_user.set_password(password)  # Hash the password
        db.session.add(new_user)
        db.session.commit()
        
        # Set session and redirect to the correct dashboard based on role
        session['username'] = username
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))  # Default to student dashboard
    
    return render_template('auth/register.html')


#########################################################################################################################
#route for login
@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        userid = request.form['userid']
        password = request.form['password']
        user = User.query.filter_by(userid=userid).first()
        if user and user.check_password(password):
            session.clear()  # Ensure the session is reset before adding new user info
            session['username'] = user.username
            session['role'] = user.role  # Store the role in the session

            # Log session info to make sure it's set correctly
            print(f"Session after login: {session}")

            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            return render_template('auth/login.html', error='Invalid username or password.')
    return render_template('auth/login.html')

#########################################################################################################################
#route for logout
@app.route('/logout')
def logout():
    session.clear()  # Clears the entire session
    session.pop('role', None)  # Explicitly remove 'role' from session
    print(f"Session after logout: {session}")  # Log to make sure the session is cleared
    return redirect(url_for('index'))  # Redirect to home page to ensure role is checked

#########################################################################################################################
#route for admin dashboard
# Admin dashboard route
@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    """Admin dashboard for managing users."""
    users = User.query.all()  # Get all users from the database
    return render_template('auth/dashboards/admin_dashboard.html', username=session['username'], users=users)

# Route to manage users for admin
@app.route('/admin/manage_users', methods=['GET', 'POST'])
@role_required('admin')
def manage_users():
    """Admin can manage user roles."""
    if request.method == "POST":
        userid = request.form['userid']
        new_role = request.form['role']
        user_to_update = User.query.filter_by(userid=userid).first()
        if user_to_update:
            # Handle admin trying to change their own role (don't allow it)
            if user_to_update.username == session.get('username') and new_role != 'admin':
                flash('You cannot change your own role.', 'danger')
            else:
                user_to_update.role = new_role
                db.session.commit()
                flash(f'User {user_to_update.username} role updated to {new_role}.', 'success')

            return redirect(url_for('manage_users'))  # Refresh the list

    users = User.query.all()  # Get all users from the database
    return render_template('auth/dashboards/manage_users.html', users=users)

#########################################################################################################################
#route for teacher dashboard
@app.route('/teacher_dashboard')
@role_required('teacher')
def teacher_dashboard():
    """Teacher dashboard."""
    return render_template('auth/dashboards/teacher_dashboard.html', username=session['username'])

#########################################################################################################################
#route for student dashboard
@app.route('/student_dashboard')
@role_required('student')
def student_dashboard():
    """Student dashboard."""
    return render_template('auth/dashboards/student_dashboard.html', username=session['username'])

#########################################################################################################################
#route for todayclasses
@app.route("/classes")
def classes():
    return render_template("classes.html")

#########################################################################################################################
#route for maintenance page
@app.route("/maintenance")
def maintenance():
    return render_template("maintenance.html")

#########################################################################################################################
if __name__ == '__main__':
    # Create a db and table
    with app.app_context():
        db.create_all()
    app.run(debug=True)
