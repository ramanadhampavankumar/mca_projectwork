from flask import Flask, render_template, Response, redirect, url_for, session, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


#########################################################################################################################
app = Flask(__name__) # initializing
app.secret_key = 'your_secret_key'  # Change this to a random secret key

# Configuring SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#########################################################################################################################
#Database Model
class User(db.Model):
    """User Model

    Args:
        db (_type_): Model from SQL Alchemy

    Returns:
        string: Only check_password returns, else used to store user info
    """
    userid = db.Column(db.String(10), primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

#########################################################################################################################


#########################################################################################################################
#routes
@app.route("/")
def index():
    """Displays a Page based on the session of the current user

    Returns:
        html template: Returns the Dashboard or Index
    """
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

#not using now
@app.route("/vidnoeo")
def vidnoeo():
    return Response(
        generate_frame(), mimetype="multipart/x-mixed-replace; boundary=frame"
    )


#########################################################################################################################
#route for login
@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        userid = request.form['userid']
        password = request.form['password']
        user = User.query.filter_by(userid=userid).first()
        if user and user.check_password(password):
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            return render_template('auth/login.html', error='Invalid username or password.')
    return render_template('auth/login.html')

#########################################################################################################################
#route for register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        userid = request.form['userid']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # Check if passwords match
        if password != confirm_password:
            return render_template('auth/register.html', error="Passwords do not match.")
        
        # Check if the userid already exists in the database
        existing_user = User.query.filter_by(userid=userid).first()
        if existing_user:
            return render_template('auth/register.html', error="User ID already exists.")
        
        # If the user doesn't exist, create a new user
        new_user = User(username=username, userid=userid)
        new_user.set_password(password)  # Hash the password
        db.session.add(new_user)
        db.session.commit()
        
        # Set session and redirect to the dashboard
        session['username'] = username
        return redirect(url_for('dashboard'))
    
    return render_template('auth/register.html')

#########################################################################################################################
#route for dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('auth/dashboards/dashboard.html', username=session['username'])
    return redirect(url_for('index'))
#########################################################################################################################
#route for logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))
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
if __name__ in '__main__':
    # Create a db and table
    with app.app_context():
        db.create_all()
    app.run(debug=True)