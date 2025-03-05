from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = "static/uploads/"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Function to fetch user details
def get_user(username):
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row  
    cur = con.cursor()
    
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    con.close()
    
    return dict(user) if user else None  

# Function to update session after profile changes
def update_session(username):
    user = get_user(username)
    if user:
        print("Updated session with:", user)  # Debugging
        session["user"] = {
            "id": user["id"],
            "firstname": user["firstname"],
            "lastname": user["lastname"],
            "email": user["email"],
            "course": user["course"],
            "yearlevel": user["yearlevel"],
            "profile_pic": user["profile_pic"] if user["profile_pic"] else "default.png"
        }

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        course = request.form.get("course")
        yearlevel = request.form.get("yearlevel")

        # Ensure all fields are filled
        if not (firstname and lastname and email and username and password and course and yearlevel):
            flash("All fields are required!", "error")
            return redirect(url_for("register"))
        
        # Check if username already exists
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Username already taken. Choose a different one.", "error")
            con.close()
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Insert user into the database
        cur.execute("""
            INSERT INTO users (firstname, lastname, email, username, password, course, yearlevel, profile_pic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (firstname, lastname, email, username, hashed_password, course, yearlevel, "default.png"))

        con.commit()
        con.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login_page"))

    return render_template("login.html")

# Function to check login credentials
def check_login(username, password):
    user = get_user(username)
    if user and check_password_hash(user["password"], password):  
        update_session(username)
        return True
    return False

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("un")
        password = request.form.get("pwd")

        if not username or not password:
            flash('Please fill out both fields.', 'error')
            return redirect(url_for('login_page'))
        
        if check_login(username, password):
            return redirect(url_for("home"))
        else:
            flash('Invalid Username or Password', 'error')
            return redirect(url_for('login_page'))
    
    return render_template("login.html")

@app.route("/home")
def home():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))
    
    return render_template("homepage.html", user=session["user"])

# Route for updating profile details
@app.route("/update_profile", methods=["POST"])
def update_profile():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))

    user_id = session["user"]["id"]
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    course = request.form.get("course")
    yearlevel = request.form.get("yearlevel")

    if not (firstname and lastname and email and course and yearlevel):
        flash("All fields are required!", "error")
        return redirect(url_for("home"))

    con = sqlite3.connect("users.db")
    cur = con.cursor()
    cur.execute("""
        UPDATE users 
        SET firstname = ?, lastname = ?, email = ?, course = ?, yearlevel = ? 
        WHERE id = ?
    """, (firstname, lastname, email, course, yearlevel, user_id))
    con.commit()
    con.close()

    # ✅ Refresh session data from the database
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    cur.execute("SELECT id, firstname, lastname, email, course, yearlevel FROM users WHERE id = ?", (user_id,))
    updated_user = cur.fetchone()
    con.close()

    # ✅ Store the updated user info in session
    session["user"] = {
        "id": updated_user[0],
        "firstname": updated_user[1],
        "lastname": updated_user[2],
        "email": updated_user[3],
        "course": updated_user[4],
        "yearlevel": updated_user[5],
    }

    flash("Profile updated successfully!", "success")
    return redirect(url_for("home"))

# Route for uploading profile picture
@app.route("/upload_profile_pic", methods=["POST"])
def upload_profile_pic():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))
    if "profile_pic" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("home"))

    file = request.files["profile_pic"]
    if file.filename == "":
        flash("No selected file.", "error")
        return redirect(url_for("home"))

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        user_id = session["user"]["id"]
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        cur.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (filename, user_id))
        con.commit()
        con.close()

        session["user"]["profile_pic"] = filename  # Update session data
        flash("Profile picture updated successfully!", "success")

    return redirect(url_for("home"))

@app.route("/profile")
def profile():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))

    user_id = session["user"]["id"]
    
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    cur.execute("SELECT firstname, lastname, email, course FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    con.close()

    if user:
        session["user"]["firstname"] = user[0]
        session["user"]["lastname"] = user[1]
        session["user"]["email"] = user[2]
        session["user"]["course"] = user[3]  # Ensure course is stored in session
    else:
        flash("User not found.", "error")
        return redirect(url_for("home"))

    return redirect(url_for("profile"))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    return render_template('signup.html')

@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/edit')
def edit():
    return render_template('edit.html')

@app.route('/announcements')
def announcements():
    return render_template('announcements.html')

@app.route('/remaining_sessions')
def remaining_sessions():
    return render_template('remaining_sessions.html')

@app.route('/sit_in_rors')
def sit_in_rors():
    return render_template('sit_in_rors.html')

@app.route('/sit_in_history')
def sit_in_history():
    return render_template('sit_in_history.html')

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    return render_template('signup.html')

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login_page"))

if __name__ == "__main__":
    app.run(debug=True)
