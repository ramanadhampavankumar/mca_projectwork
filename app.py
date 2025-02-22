from flask import Flask, render_template, Response, redirect, url_for, session, request, flash, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime

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
    

# Classes Model
class SubjectsClasses(db.Model):  # Renamed to SubjectsClasses
    id = db.Column(db.Integer, primary_key=True)
    Branch = db.Column(db.String(200), nullable=False)
    Subject = db.Column(db.String(200), nullable=False)
    Start_Time = db.Column(db.DateTime, nullable=False)
    End_Time = db.Column(db.DateTime, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    completed = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<SubjectsClasses {self.id}>'


#########################################################################################################################
# Role-based access control decorator
def role_required(roles):
    """Decorator to require specific roles for accessing a route."""
    if not isinstance(roles, list):
        roles = [roles]  # Ensure roles is a list

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            user = User.query.filter_by(username=session['username']).first()
            if user.role not in roles:  # Check if the user's role is in the allowed roles list
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
    return render_template('auth/dashboards/admin/admin_dashboard.html', username=session['username'], users=users)
####################################################################################
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
    return render_template('auth/dashboards/admin/manage_users.html', users=users)

#########################################################################################################################
#route for teacher dashboard
@app.route('/teacher_dashboard')
@role_required('teacher')
def teacher_dashboard():
    """Teacher dashboard."""
    return render_template('auth/dashboards/teacher/teacher_dashboard.html', username=session['username'])
#########################################################################
# Route to view users for teacher
@app.route('/teacher/view_users', methods=['GET', 'POST'])
@role_required('teacher')
def view_users():

    users = User.query.all()  # Get all users from the database
    return render_template('auth/dashboards/teacher/view_users.html', users=users)

####################################################################################
# Route to add classes for admin and teacher
@app.route('/teacher/manage_classes', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])  # Allow both admin and teacher roles
def manage_classes():
    """Admin and Teacher can add and view classes."""
    if request.method == "POST":
        branch = request.form['branch']
        subject = request.form['subject']
        start_time_str = request.form['start_time']
        end_time_str = request.form['end_time']

        # Check if the start_time and end_time are not empty
        if not start_time_str or not end_time_str:
            return "Error: Start Time and End Time are required fields", 400

        try:
            # Convert string to datetime objects
            start_time = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M")
            end_time = datetime.strptime(end_time_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            return "Error: Invalid date format. Please use YYYY-MM-DDTHH:MM format", 400
        
        new_task = SubjectsClasses(Branch=branch, Subject=subject, Start_Time=start_time, End_Time=end_time)
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect("/teacher/manage_classes")
        except Exception as e:
            print(f"Error: {e}")
            return f'Error: {e}'
    else:
        subjects = SubjectsClasses.query.filter(SubjectsClasses.Start_Time != None, SubjectsClasses.End_Time != None).order_by(SubjectsClasses.date_created).all()
        return render_template('auth/dashboards/teacher/manage_classes.html', subjects=subjects)
#########################################################################
#delete classes
@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])  # Allow both admin and teacher to delete
def delete_class(id):
    task = SubjectsClasses.query.get(id)
    if task:
        try:
            db.session.delete(task)
            db.session.commit()
            flash('Class deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error: {e}', 'danger')
    else:
        flash('Class not found.', 'danger')
    return redirect(url_for('manage_classes'))

#########################################################################
#update classes
@app.route('/teacher/manage_classes/update/<int:id>', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])  # Allow both admin and teacher to update
def update_class(id):
    task = SubjectsClasses.query.get(id)
    if request.method == 'POST':
        task.Branch = request.form['branch']
        task.Subject = request.form['subject']
        task.Start_Time = datetime.strptime(request.form['start_time'], "%Y-%m-%dT%H:%M")
        task.End_Time = datetime.strptime(request.form['end_time'], "%Y-%m-%dT%H:%M")
        
        try:
            db.session.commit()
            flash('Class updated successfully!', 'success')
            return redirect(url_for('manage_classes'))
        except Exception as e:
            flash(f'Error: {e}', 'danger')

    return render_template('auth/dashboards/teacher/update_class.html', task=task)
####################################################################################



#########################################################################################################################
#route for student dashboard
@app.route('/student_dashboard')
@role_required('student')
def student_dashboard():
    """Student dashboard."""
    return render_template('auth/dashboards/student/student_dashboard.html', username=session['username'])


@app.route('/status_classes')
@role_required('student')
def status_classes():
    # Get today's date (start and end of day)
    start_of_day = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = datetime.today().replace(hour=23, minute=59, second=59, microsecond=999999)

    # Query the classes for today
    users = db.session.query(SubjectsClasses).filter(
        SubjectsClasses.Start_Time >= start_of_day,
        SubjectsClasses.End_Time <= end_of_day
    ).all()

    return render_template('auth/dashboards/student/stutus_classes.html', users=users)

@app.route('/attendance/<int:class_id>')
def attendance_status(class_id):
    # Not implemented yet
    pass

@app.route('/admin/profile', methods=['GET', 'POST'])
@role_required('admin')
def admin_profile():
    return profile('admin')

@app.route('/teacher/profile', methods=['GET', 'POST'])
@role_required('teacher')
def teacher_profile():
    return profile('teacher')

@app.route('/student/profile', methods=['GET', 'POST'])
@role_required('student')
def student_profile():
    return profile('student')


#########################################################################################################################
#route for todayclasses
@app.route('/today_classes')
def today_classes():
    # Get today's date (start and end of day)
    start_of_day = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = datetime.today().replace(hour=23, minute=59, second=59, microsecond=999999)

    # Query the classes for today
    users = db.session.query(SubjectsClasses).filter(
        SubjectsClasses.Start_Time >= start_of_day,
        SubjectsClasses.End_Time <= end_of_day
    ).all()

    return render_template('today_classes.html', users=users)

# Route to profile page for admin, teacher, and student
@app.route('/<role>/profile/', methods=['GET', 'POST'])
@role_required(['admin', 'teacher', 'student'])
def profile(role):
    """View and update user profile."""
    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Check if the current password is correct
        if not user.check_password(current_password):
            flash('Incorrect current password.', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        elif len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')  # Password length check
        else:
            # Update password
            user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully.', 'success')
            return redirect(url_for(f'{role}_profile'))  # Use the appropriate role-based profile URL

    return render_template(f'auth/dashboards/{role}/profile.html', user=user)

#########################################################################################################################
#route for contact page
@app.route("/contact")
def contact():
    return render_template("contact.html")
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
