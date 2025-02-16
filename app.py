from flask import Flask, render_template, Response, redirect, url_for


#########################################################################################################################
app = Flask(__name__) # initializing
# Configuring SQLAlchemy


#########################################################################################################################
#Database Model


#########################################################################################################################


#########################################################################################################################
#routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vidnoeo")
def vidnoeo():
    return Response(
        generate_frame(), mimetype="multipart/x-mixed-replace; boundary=frame"
    )


#########################################################################################################################
@app.route("/login")
def login():
    return render_template("auth/login.html")

#########################################################################################################################
@app.route("/register")
def register():
    return render_template("auth/register.html")



#########################################################################################################################
@app.route("/classes")
def classes():
    return render_template("classes.html")

#########################################################################################################################
#Maintenances Page
@app.route("/maintenance")
def maintenance():
    return render_template("maintenance.html")

#########################################################################################################################
if __name__ == "__main__":
     # Create a db and table
    app.run(debug=True)