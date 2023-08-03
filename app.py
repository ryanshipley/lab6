# Flask + Security
# SDEV 300 Section 6380
# Ryan Shipley
# July 11, 2023
"""Practicing displaying HTML"""

#Imports
from datetime import date, datetime
import re
import urllib.parse
import logging
from flask import Flask, render_template, redirect, request, session, url_for

# pylint: disable=too-many-return-statements

app = Flask(__name__)

#For registered users
users = []
logging.basicConfig(filename="login.log", level=logging.INFO, format="%(asctime)s - %(message)s")

@app.route("/")

@app.route("/index.html")
def home():
    """This function renders the homepage"""
    return render_template("index.html")

@app.route("/second.html")
def second():
    """This function renders page 2"""
    return render_template("second.html",date=date.today(),time=datetime.now().strftime("%H:%M:%S"))

@app.route("/third.html")
def third():
    """This function renders the third page"""
    return render_template("third.html",date=date.today(),time=datetime.now().strftime("%H:%M:%S"))

@app.route("/register", methods=["GET", "POST"])
def register():
    """This function renders the registration form"""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        #Password Verification
        #urllib.parse.quote allows us to retrieve the error message
        if len(password) < 12:
            error_message = 'Password must be at least 12 characters long'
            encoded_error = urllib.parse.quote(error_message)
            return redirect(url_for('register',error=encoded_error))
        if not re.search(r'[a-z]', password):
            error_message = 'Password must contain at least one lowercase letter'
            encoded_error = urllib.parse.quote(error_message)
            return redirect(url_for('register',error=encoded_error))
        if not re.search(r'[A-Z]', password):
            error_message = 'Password must contain at least one uppercase letter'
            encoded_error = urllib.parse.quote(error_message)
            return redirect(url_for('register',error=encoded_error))
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            error_message = 'Password must contain at least one special character'
            encoded_error = urllib.parse.quote(error_message)
            return redirect(url_for('register',error=encoded_error))


        users.append({"username": username, "password": password})
        return redirect(url_for("login"))
    error_message = urllib.parse.unquote(request.args.get("error", ""))
    return render_template("register.html", error = error_message or "")

@app.route('/login', methods=['GET', 'POST'])
def login():
    """This function renders the login form"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user in users:
            if user['username'] == username and user['password'] == password:
                # Set a session variable to track successful login
                session['logged_in'] = True
                session["username"] = username
                return redirect(url_for('dash'))

        client_ip = request.remote_addr
        logging.info("Failed login attempt: %s, IP: %s", username, client_ip)

        return 'Invalid username or password'
    return render_template('login.html')

@app.route("/dash", methods=["GET", "POST"])
def dash():
    """This function renders the dashboard page"""
    if request.method =="POST":
        return update_password()
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("dash.html",date=date.today(),time=datetime.now().strftime("%H:%M:%S"))

@app.route("/logout")
def logout():
    """This function enables logout functionality"""
    session["logged_in"] = False
    return redirect(url_for("login"))

@app.route("/update_password", methods=["POST"])
def update_password():
    """This function enables capability to update passwords"""
    current_password = request.form["current_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    username = session.get("username")
    user = next((user for user in users if user["username"] == username), None)
    if not user:
        return "User not found"

    stored_password = user["password"]

    if current_password != stored_password:
        return "Invalid Current Password"
    if len(new_password) < 12:
        return "New password must be at least 12 characters long"
    if new_password != confirm_password:
        return "New password does not match confirmation"
    if not re.search(r"[a-z]", new_password):
        return "New password must contain at least one lowercase letter"
    if not re.search(r"[A-Z]", new_password):
        return "New password must contain at least one uppercase letter"
    if not re.search(r"[!@#$%^&*(),.?:{}|<>]", new_password):
        return "New password must contain at least one special character"

    user["password"] = new_password
    message = "Password Update Successfully"
    return render_template("dash.html", date=date.today(), time=datetime.now().strftime("%H:%M:%S"),
                            message=message)


if __name__ == "__main__":
    app.secret_key = "ILovePython"
    app.run(debug = True)
