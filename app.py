from flask import Flask, render_template, Response, redirect, url_for, session, request, flash, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime, date, time
import pytz
from sqlalchemy.orm import joinedload

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

# Attendance model
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer)
    user_id = db.Column(db.String(10))
    date_time = db.Column(db.DateTime, default=datetime.utcnow)


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

today_date = date.today().strftime('%Y-%m-%d')
today_start = datetime.combine(date.today(), time.min)
today_end = datetime.combine(date.today(), time.max)

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
@app.route('/admin/manage_roles', methods=['GET', 'POST'])
@role_required('admin')
def manage_roles():
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

            return redirect(url_for('manage_roles'))  # Refresh the list

    users = User.query.all()  # Get all users from the database
    return render_template('auth/dashboards/admin/manage_roles.html', users=users)


####################################################################################
#Route for manage classes for admin and teacher
@app.route('/<role>/manage_classes', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])  # Allow both admin and teacher roles
def manage_classes(role):
    """Admin and Teacher can add and view classes."""
    if request.method == "POST":
        branch = request.form['branch']
        subject = request.form['subject']
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        completed = 0 # Default to present classes (0)

        # Validate required fields
        if not branch or not subject or not start_time_str or not end_time_str:
            flash("Error: All fields are required", "danger")
            return redirect(url_for('manage_classes', role=role))

        try:
            # Convert string to datetime objects
            start_time = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M")
            end_time = datetime.strptime(end_time_str, "%Y-%m-%dT%H:%M")

            if start_time >= end_time:
                flash("Error: Start time must be before end time", "danger")
                return redirect(url_for('manage_classes', role=role))

            new_class = SubjectsClasses(
                Branch=branch, 
                Subject=subject, 
                Start_Time=start_time, 
                End_Time=end_time,
                completed=completed
            )

            db.session.add(new_class)
            db.session.commit()
            flash("Class added successfully!", "success")
            return redirect(url_for('manage_classes', role=role))

        except ValueError:
            flash("Error: Invalid date format. Use YYYY-MM-DDTHH:MM", "danger")
        except Exception as e:
            flash(f"Database Error: {e}", "danger")
            db.session.rollback()

        return redirect(url_for('manage_classes', role=role))

    # Fetch classes for display
    subjects = SubjectsClasses.query.filter(
        SubjectsClasses.Start_Time.isnot(None), 
        SubjectsClasses.End_Time.isnot(None)
    ).order_by(SubjectsClasses.date_created).all()

    return render_template(f'auth/dashboards/{role}/manage_classes.html', subjects=subjects, role=role)
#########################################################################
#Route for make_uncomplete classes for admin and teacher
@app.route('/<role>/complete_class/<int:id>', methods=['POST'])
@role_required(['admin', 'teacher'])
def complete_class(role, id):
    task = SubjectsClasses.query.get(id)
    if not task:
        flash('Error: Class not found.', 'danger')
        return redirect(url_for('manage_classes', role=role))

    task.completed = 1  # Mark as completed
    db.session.commit()
    flash('Class marked as completed!', 'success')
    
    return redirect(url_for('manage_classes', role=role))

#########################################################################
#Route to mark class as incomplete for admin and teacher
@app.route('/<role>/uncomplete_class/<int:id>', methods=['POST'])
@role_required(['admin', 'teacher'])
def uncomplete_class(role, id):
    task = SubjectsClasses.query.get(id)
    if not task:
        flash('Error: Class not found.', 'danger')
        return redirect(url_for('manage_classes', role=role))

    task.completed = 0  # Mark as uncompleted
    db.session.commit()
    flash('Class marked as uncompleted!', 'success')
    
    return redirect(url_for('manage_classes', role=role))

#########################################################################
#Route for delete classes for admin and teacher
@app.route('/<role>/delete/<int:id>', methods=['POST'])
@role_required(['admin', 'teacher'])
def delete_class(role, id):
    subject = SubjectsClasses.query.get_or_404(id)
    try:
        db.session.delete(subject)
        db.session.commit()
        flash('Class deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('manage_classes', role=role))


#########################################################################
#Route for update classes for admin and teacher
@app.route('/<role>/update/<int:id>', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])  # Allow both admin and teacher to update
def update_class(role, id):
    subject = SubjectsClasses.query.get_or_404(id)  # Use get_or_404 for better error handling
    
    if request.method == 'POST':
        try:
            subject.Branch = request.form['branch']
            subject.Subject = request.form['subject']
            subject.Start_Time = datetime.strptime(request.form['start_time'], "%Y-%m-%dT%H:%M")
            subject.End_Time = datetime.strptime(request.form['end_time'], "%Y-%m-%dT%H:%M")
            
            if subject.Start_Time >= subject.End_Time:
                flash("Error: Start time must be before end time", "danger")
                return redirect(url_for('update_class', role=role, id=id))
            
            db.session.commit()
            flash('Class updated successfully!', 'success')
            return redirect(url_for('manage_classes', role=role))
        except ValueError:
            flash("Error: Invalid date format. Use YYYY-MM-DDTHH:MM", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}', 'danger')

    return render_template(f'auth/dashboards/{role}/update_class.html', subject=subject, role=role)


#########################################################################
@app.route('/admin/edit_profiles', methods=['GET'])
@role_required('admin')
def edit_profiles():
    users = User.query.all()
    return render_template('auth/dashboards/admin/edit_profiles.html', users=users)

#Route for delete user for admin
@app.route('/admin/delete_user/<string:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    user = User.query.filter_by(userid=user_id).first()

    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('edit_profiles'))

#########################################################################
# Route for update profiles for admin
@app.route('/admin/update_profile/<string:user_id>', methods=['GET', 'POST'])
@role_required('admin')
def update_profile(user_id):
    user = User.query.filter_by(userid=user_id).first_or_404()

    if request.method == 'POST':
        user.userid = request.form['userid']
        user.username = request.form['username']
        new_password = request.form.get('new_password')

        if new_password:
            user.set_password(new_password)  # Hash and update password

        try:
            db.session.commit()
            flash("User updated successfully!", "success")
        except Exception as e:
            flash(f"Error updating user: {e}", "danger")

        return redirect(url_for('edit_profiles'))  # Redirect back to edit profiles

    return render_template('auth/dashboards/admin/update_profile.html', user=user)

#########################################################################
# Route to take attendance for admin and teacher
@app.route('/<role>/take_attendance')
@role_required(['admin', 'teacher'])
def take_attendance(role):
    return render_template(f'auth/dashboards/{role}/attendance/take_attendance.html')

#Route to take live attendance for admin and teacher
@app.route('/<role>/take_attendance/take_live_stream')
@role_required(['admin', 'teacher'])
def take_live_stream(role):
    return render_template(f'auth/dashboards/{role}/attendance/take_live_stream.html')
    

#Route to take manually attendance for admin and teacher
@app.route('/<role>/take_attendance/take_manually', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])
def take_manually(role):
    classes = SubjectsClasses.query.filter(SubjectsClasses.completed == 0).order_by(SubjectsClasses.Start_Time).all()
    students = User.query.filter_by(role='student').order_by(User.username).all()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        subject_id = request.form.get('class_id')

        if not user_id or not subject_id:
            flash('Please select a user and a class.', 'danger')
            return redirect(url_for('take_manually', role=role))

        try:
            subject = SubjectsClasses.query.get(subject_id)
            user = User.query.filter_by(userid=user_id).first()

            if not subject:
                flash('Invalid class selected.', 'danger')
                return redirect(url_for('take_manually', role=role))
            if not user:
                flash('Invalid User selected.', 'danger')
                return redirect(url_for('take_manually', role=role))

            # Record attendance for the current date and time
            attendance_datetime = datetime.now(pytz.timezone('Asia/Kolkata'))

            # Check if attendance already exists for this student and class on the current date
            start_of_day = attendance_datetime.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = attendance_datetime.replace(hour=23, minute=59, second=59, microsecond=999999)

            existing_attendance = Attendance.query.filter(
                Attendance.subject_id == subject.id,
                Attendance.user_id == user.userid,
                Attendance.date_time >= start_of_day,
                Attendance.date_time <= end_of_day
            ).first()

            if not existing_attendance:
                new_attendance = Attendance(subject_id=subject.id, user_id=user.userid, date_time=attendance_datetime)
                db.session.add(new_attendance)
                db.session.commit()
                flash(f'Attendance recorded for {user.username} on {attendance_datetime.strftime("%d/%m/%Y %I:%M %p")} in {subject.Subject}!', 'success')
            else:
                flash(f'Attendance already recorded for {user.username} today in {subject.Subject}.', 'warning')

            return redirect(url_for('take_manually', role=role))

        except Exception as e:
            db.session.rollback()
            flash(f'Error recording attendance: {e}', 'danger')

    return render_template(f'auth/dashboards/{role}/attendance/take_manually.html', classes=classes, students=students, role=role)

#Route to Add user images for admin and teacher
@app.route('/<role>/take_attendance/add_user_images')
@role_required(['admin', 'teacher'])
def add_user_images(role):
    return render_template(f'auth/dashboards/{role}/attendance/add_user_images.html')

#########################################################################
#Route for view attendance for admin and teacher
@app.route('/<role>/view_attendance')
@role_required(['admin', 'teacher'])
def view_attendance(role):
    return render_template(f'auth/dashboards/{role}/attendance/view_attendance.html')

#Route to today attendance report for admin and teacher
@app.route('/<role>/view_attendance/today_attendance_all', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])
def today_attendance_all(role):
    """Fetches and displays today's attendance details for all students (database times) with filtering."""
    today = date.today()
    start_of_day = datetime.combine(today, time.min)
    end_of_day = datetime.combine(today, time.max)

    students_query = User.query.filter_by(role='student').order_by(User.userid)
    subjects_today_query = SubjectsClasses.query.filter(
        db.func.date(SubjectsClasses.Start_Time) == today
    ).order_by(SubjectsClasses.Start_Time)

    # Get filter parameters from the form
    filter_userid = request.form.get('userid')
    filter_branch = request.form.get('branch')
    filter_subject = request.form.get('subject')

    # Apply filters to the queries
    if filter_userid:
        students_query = students_query.filter(User.userid == filter_userid)
    if filter_branch:
        subjects_today_query = subjects_today_query.filter(SubjectsClasses.Branch == filter_branch)
    if filter_subject:
        subjects_today_query = subjects_today_query.filter(SubjectsClasses.Subject == filter_subject)

    students = students_query.all()
    subjects_today = subjects_today_query.all()

    student_attendance_data = []
    for student in students:
        for subject_class in subjects_today:
            # Check if there's an attendance record for this student and subject today
            attendance_record = Attendance.query.filter(
                Attendance.user_id == student.userid,
                Attendance.subject_id == subject_class.id,
                Attendance.date_time >= start_of_day,
                Attendance.date_time <= end_of_day
            ).first()

            is_present = bool(attendance_record)
            attendance_time = attendance_record.date_time if attendance_record else None

            student_attendance_data.append({
                'user_id': student.userid,
                'username': student.username,
                'branch': subject_class.Branch,
                'subject': subject_class.Subject,
                'start_time': subject_class.Start_Time,
                'end_time': subject_class.End_Time,
                'attendance_taken': attendance_time,
                'attendance_status': 'Present' if is_present else 'Absent'
            })

    return render_template(
        f'auth/dashboards/{role}/attendance/today_attendance_all.html',
        student_attendance_data=student_attendance_data,
        today=today,
        students=User.query.filter_by(role='student').order_by(User.userid).all(),
        branches=SubjectsClasses.query.with_entities(SubjectsClasses.Branch).distinct().order_by(SubjectsClasses.Branch).all(),
        subjects=SubjectsClasses.query.with_entities(SubjectsClasses.Subject).distinct().order_by(SubjectsClasses.Subject).all(),
        filter_userid=filter_userid,
        filter_branch=filter_branch,
        filter_subject=filter_subject,
        role=role  # Pass the 'role' variable to the template context
    )

# Route to view attendance (Admin and Teacher) - Database Time (No Timezone Conversion)
@app.route('/<role>/view_attendance/old_attendance_all', methods=['GET', 'POST'])
@role_required(['admin', 'teacher'])
def old_attendance_all(role):
    """Displays and filters old attendance records, showing Present/Absent status based on recorded entries (no timezone conversion)."""
    students = User.query.filter_by(role='student').order_by(User.userid).all()
    subjects_classes = SubjectsClasses.query.order_by(SubjectsClasses.Branch, SubjectsClasses.Subject).all()
    attendance_records = Attendance.query.order_by(Attendance.date_time.desc()).all()

    search_userid = request.form.get('userid')
    search_branch = request.form.get('branch')
    search_subject = request.form.get('subject')
    search_date = request.form.get('attendance_date')

    filtered_attendance_data = []
    now_utc = datetime.utcnow()  # Get the current UTC time on the server

    for student in students:
        for subject_class in subjects_classes:
            # Determine search filters
            user_match = not search_userid or search_userid.lower() in student.userid.lower()
            branch_match = not search_branch or search_branch.lower() in subject_class.Branch.lower()
            subject_match = not search_subject or search_subject.lower() in subject_class.Subject.lower()
            date_match = True
            if search_date:
                try:
                    search_dt = datetime.strptime(search_date, '%Y-%m-%d').date()
                except ValueError:
                    flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
                    return render_template(f'auth/dashboards/{role}/attendance/old_attendance_all.html',
                                           students=students, subjects_classes=subjects_classes,
                                           attendance_data=filtered_attendance_data, role=role)

                # Check if there's any attendance for this student and subject on the searched date
                attendance_on_date = Attendance.query.filter(
                    Attendance.user_id == student.userid,
                    Attendance.subject_id == subject_class.id,
                    db.func.date(Attendance.date_time) == search_dt
                ).first()
                date_match = bool(attendance_on_date)  # Present if a record exists

            if user_match and branch_match and subject_match:
                # Fetch the latest attendance record for this student and subject
                latest_attendance = Attendance.query.filter(
                    Attendance.user_id == student.userid,
                    Attendance.subject_id == subject_class.id
                ).order_by(Attendance.date_time.desc()).first()

                attendance_taken = latest_attendance.date_time if latest_attendance else None
                attendance_status = 'Present' if latest_attendance else 'Absent'
                attendance_id = latest_attendance.id if latest_attendance else None
                is_future = attendance_taken > now_utc if attendance_taken else False

                if search_date:
                    # If searching by date, only show entries where attendance matches the date
                    if date_match:
                        filtered_attendance_data.append({
                            'userid': student.userid,
                            'username': student.username,
                            'branch': subject_class.Branch,
                            'subject': subject_class.Subject,
                            'start_time': subject_class.Start_Time,  # As stored in DB
                            'end_time': subject_class.End_Time,    # As stored in DB
                            'attendance_taken': attendance_taken,  # As stored in DB
                            'attendance_status': attendance_status,
                            'attendance_id': attendance_id,
                            'is_future': is_future
                        })
                else:
                    # If not searching by date, show all student-subject combinations and their latest status
                    filtered_attendance_data.append({
                        'userid': student.userid,
                        'username': student.username,
                        'branch': subject_class.Branch,
                        'subject': subject_class.Subject,
                        'start_time': subject_class.Start_Time,  # As stored in DB
                        'end_time': subject_class.End_Time,    # As stored in DB
                        'attendance_taken': attendance_taken,  # As stored in DB
                        'attendance_status': attendance_status,
                        'attendance_id': attendance_id,
                        'is_future': is_future
                    })

    return render_template(f'auth/dashboards/{role}/attendance/old_attendance_all.html',
                           students=students, subjects_classes=subjects_classes,
                           attendance_data=filtered_attendance_data, role=role)

@app.route('/<role>/delete_attendance/<int:attendance_id>', methods=['POST'])
@role_required(['admin', 'teacher'])
def delete_attendance(role, attendance_id):
    """Deletes a specific attendance record."""
    attendance = Attendance.query.get_or_404(attendance_id)
    now_utc = datetime.utcnow() # Compare with database time (assuming UTC)

    if attendance.date_time > now_utc:
        try:
            db.session.delete(attendance)
            db.session.commit()
            flash('Future attendance record deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting attendance: {e}', 'danger')
    else:
        flash('Cannot delete past attendance records through this action.', 'warning')

    return redirect(url_for('old_attendance_all', role=role))

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

#########################################################################
# Route to profile page for admin, teacher, and student
@app.route('/<role>/profile/', methods=['GET', 'POST'])
@role_required(['teacher', 'student'])
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
            return redirect(url_for('profile', role=role))  # Corrected redirection

    return render_template(f'auth/dashboards/{role}/profile.html', user=user)

#########################################################################
# Route to Edit profile for teacher
@app.route('/teacher/profile', methods=['GET', 'POST'])
@role_required('teacher')
def teacher_profile():
    return profile('teacher')

#########################################################################################################################
#route for student dashboard
@app.route('/student_dashboard')
@role_required('student')
def student_dashboard():
    """Student dashboard."""
    return render_template('auth/dashboards/student/student_dashboard.html', username=session['username'])

#########################################################################
# Route to view classes for student
@app.route('/status_classes')
@role_required('student')
def status_classes():
    # Get today's date (start and end of day)
    start_of_day = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = datetime.today().replace(hour=23, minute=59, second=59, microsecond=999999)

    # Query the classes that either start or end today and are not completed
    users = db.session.query(SubjectsClasses).filter(
        (SubjectsClasses.Start_Time >= start_of_day) & (SubjectsClasses.Start_Time <= end_of_day) |
        (SubjectsClasses.End_Time >= start_of_day) & (SubjectsClasses.End_Time <= end_of_day)
    ).filter(SubjectsClasses.completed == 0).all()

    return render_template('auth/dashboards/student/stutus_classes.html', users=users)

#########################################################################
# Route to view attendance for student
@app.route('/student/attendance/view_attendance_report')
@role_required('student')
def view_attendance_report():
    return render_template('auth/dashboards/student/attendance/view_attendance_report.html')

@app.route('/student/attendance/today_attendance', methods=['GET', 'POST'])
@role_required('student')
def today_attendance():
    """Displays today's attendance for the logged-in student with subject search and status radio buttons."""
    today = date.today()
    start_of_day = datetime.combine(today, time.min)
    end_of_day = datetime.combine(today, time.max)

    student = User.query.filter_by(username=session['username'], role='student').first()

    if not student:
        flash("Error: Student user not found.", "danger")
        return redirect(url_for('student_dashboard'))

    # Get filter parameters from the form
    filter_subject = request.form.get('subject')
    filter_status = request.form.get('status')

    attendance_data = []
    subjects_today_query = SubjectsClasses.query.filter(
        db.func.date(SubjectsClasses.Start_Time) == today
    ).order_by(SubjectsClasses.Start_Time)

    subjects_today = subjects_today_query.all()

    for subject_class in subjects_today:
        attendance_record = Attendance.query.filter(
            Attendance.user_id == student.userid,
            Attendance.subject_id == subject_class.id,
            Attendance.date_time >= start_of_day,
            Attendance.date_time <= end_of_day
        ).first()

        is_present = bool(attendance_record)
        attendance_time = attendance_record.date_time if attendance_record else None
        status = 'Present' if is_present else 'Absent'

        # Apply filters
        if filter_subject and subject_class.Subject != filter_subject:
            continue
        if filter_status and status != filter_status:
            continue

        attendance_data.append({
            'subject': subject_class.Subject,
            'start_time': subject_class.Start_Time,
            'end_time': subject_class.End_Time,
            'attendance_taken': attendance_time,
            'attendance_status': status
        })

    # Get unique subjects for the search dropdown
    unique_subjects = [sub.Subject for sub in subjects_today]
    unique_subjects = sorted(list(set(unique_subjects)))

    return render_template(
        'auth/dashboards/student/attendance/today_attendance.html',
        attendance_data=attendance_data,
        today=today,
        subjects=unique_subjects,
        filter_subject=filter_subject,
        filter_status=filter_status
    )

#Route to view old attendance for student
@app.route('/student/attendance/old_attendance', methods=['GET', 'POST'])
@role_required('student')
def old_attendance():
    """Displays old attendance for the logged-in student with filtering."""
    student = User.query.filter_by(username=session['username'], role='student').first()

    if not student:
        flash("Error: Student user not found.", "danger")
        return redirect(url_for('student_dashboard'))

    filter_subject = request.form.get('subject')
    filter_date_str = request.form.get('attendance_date')
    filter_status = request.form.get('status')

    attendance_data = []
    all_student_classes = SubjectsClasses.query.order_by(SubjectsClasses.Start_Time).all()

    for sc in all_student_classes:
        # Apply Subject Filter
        if filter_subject and sc.Subject != filter_subject:
            continue

        # Apply Date Filter (based on Start Time)
        if filter_date_str:
            try:
                filter_date = datetime.strptime(filter_date_str, '%Y-%m-%d').date()
                if sc.Start_Time.date() != filter_date:
                    continue
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
                return render_template('auth/dashboards/student/attendance/old_attendance.html',
                                       attendance_data=attendance_data,
                                       subjects=get_unique_subjects(),
                                       filter_subject=filter_subject,
                                       filter_date=filter_date_str,
                                       filter_status=filter_status)

        # Check for attendance record
        attendance_record = Attendance.query.filter_by(user_id=student.userid, subject_id=sc.id).first()

        status = 'Present' if attendance_record else 'Absent'
        attendance_taken = attendance_record.date_time if attendance_record else None

        # Apply Status Filter
        if filter_status and status != filter_status:
            continue

        attendance_data.append({
            'subject': sc.Subject,
            'start_time': sc.Start_Time,
            'end_time': sc.End_Time,
            'attendance_taken': attendance_taken,
            'attendance_status': status
        })

    attendance_data.sort(key=lambda x: x['start_time'], reverse=True)

    return render_template('auth/dashboards/student/attendance/old_attendance.html',
                           attendance_data=attendance_data,
                           subjects=get_unique_subjects(),
                           filter_subject=filter_subject,
                           filter_date=filter_date_str,
                           filter_status=filter_status)

def get_unique_subjects():
    return sorted(list(set([sc.Subject for sc in SubjectsClasses.query.all()])))

#########################################################################
#Route to Edit profile for student
@app.route('/student/profile', methods=['GET', 'POST'])
@role_required('student')
def student_profile():
    return profile('student')


#########################################################################################################################
#Route to view today classes
@app.route('/today_classes')
def today_classes():
    # Get today's date (start and end of day)
    start_of_day = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = datetime.today().replace(hour=23, minute=59, second=59, microsecond=999999)

    # Query classes that start or end today and are not completed
    users = db.session.query(SubjectsClasses).filter(
        ((SubjectsClasses.Start_Time >= start_of_day) & (SubjectsClasses.Start_Time <= end_of_day)) |
        ((SubjectsClasses.End_Time >= start_of_day) & (SubjectsClasses.End_Time <= end_of_day))
    ).filter(SubjectsClasses.completed == 0).all()

    return render_template('today_classes.html', users=users)

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
