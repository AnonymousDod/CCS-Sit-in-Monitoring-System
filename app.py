from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = "static/uploads/"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Admin credentials (in a real application, these should be stored securely in a database)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # In production, use a secure password

# Ensure uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Function to initialize database with admin table
def init_db():
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    
    # Create users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            midname TEXT,
            course TEXT NOT NULL,
            yearlevel TEXT NOT NULL,
            email TEXT NOT NULL,
            profile_pic TEXT,
            is_admin BOOLEAN DEFAULT 0
        )
    """)

    # Create sessions table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            start_time DATETIME NOT NULL,
            end_time DATETIME,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Create sit_in_history table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sit_in_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date DATE NOT NULL,
            time_in DATETIME NOT NULL,
            time_out DATETIME,
            duration INTEGER,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Check if admin user exists
    cur.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    admin = cur.fetchone()
    
    if not admin:
        # Create default admin user
        hashed_password = generate_password_hash("user", method="pbkdf2:sha256")
        cur.execute("""
            INSERT INTO users (username, password, firstname, lastname, course, yearlevel, email, is_admin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ("admin", hashed_password, "Admin", "User", "Administration", "N/A", "admin@uc.edu.ph", 1))
    
    con.commit()
    con.close()

# Initialize database when app starts
init_db()

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
        session["user"] = {
            "id": user["id"],
            "firstname": user["firstname"],
            "lastname": user["lastname"],
            "email": user["email"],
            "course": user["course"],
            "yearlevel": user["yearlevel"],
            "profile_pic": user["profile_pic"] if user["profile_pic"] else "default.png",
            "is_admin": user["is_admin"]
        }
        if user["is_admin"]:
            session["admin"] = True

# Admin authentication decorator
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if "admin" not in session or not session["admin"]:
            flash("Please login as admin first.", "error")
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Admin routes
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    # Get statistics
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # Get total users
    cur.execute("SELECT COUNT(*) as count FROM users")
    total_users = cur.fetchone()["count"]

    # Get recent users (last 5)
    cur.execute("SELECT * FROM users ORDER BY id DESC LIMIT 5")
    recent_users = cur.fetchall()

    # Get today's logins (you'll need to implement login tracking)
    today_logins = 0  # Placeholder

    # Get active sessions (you'll need to implement session tracking)
    active_sessions = 0  # Placeholder

    con.close()

    return render_template("admin_dashboard.html",
                         total_users=total_users,
                         recent_users=recent_users,
                         today_logins=today_logins,
                         active_sessions=active_sessions)

@app.route("/admin/users")
@admin_required
def admin_users():
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM users ORDER BY id DESC")
    users = cur.fetchall()
    con.close()
    return render_template("admin_users.html", users=users)

@app.route("/admin/sessions")
@admin_required
def admin_sessions():
    return render_template("admin_sessions.html")

@app.route("/admin/settings")
@admin_required
def admin_settings():
    return render_template("admin_settings.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    flash("Admin logged out successfully!", "success")
    return redirect(url_for("login_page"))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        idno = request.form.get("idno")
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        midname = request.form.get("midname")
        course = request.form.get("course")
        yearlevel = request.form.get("yearlevel")
        email = request.form.get("email")
        password = request.form.get("password")

        # Ensure all fields are filled
        if not (idno and firstname and lastname and midname and course and yearlevel and email and password):
            flash("All fields are required!", "error")
            return redirect(url_for("signup"))
        
        # Check if ID number already exists
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (idno,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("ID Number already registered. Please use a different ID number.", "error")
            con.close()
            return redirect(url_for("signup"))

        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Map course values to actual course names
        course_map = {
            "1": "Information Technology",
            "2": "Computer Engineering",
            "3": "Criminology",
            "4": "Customs Administration"
        }
        course_name = course_map.get(course, "Unknown Course")

        # Map year level values to actual year levels
        year_map = {
            "1": "1st Year",
            "2": "2nd Year",
            "3": "3rd Year",
            "4": "4th Year"
        }
        year_name = year_map.get(yearlevel, "Unknown Year")

        # Insert user into the database using ID number as username
        cur.execute("""
            INSERT INTO users (firstname, lastname, email, username, password, course, yearlevel, profile_pic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (firstname, lastname, email, idno, hashed_password, course_name, year_name, "default.png"))

        con.commit()
        con.close()

        flash("Registration successful! You can now log in using your ID number.", "success")
        return redirect(url_for("login_page"))

    return render_template("signup.html")

# Function to check login credentials
def check_login(username, password, is_admin=False):
    user = get_user(username)
    if user and check_password_hash(user["password"], password):
        if is_admin:
            if user["is_admin"]:
                update_session(username)
                return True
            return False
        elif user["is_admin"]:
            # If user is admin but didn't check the box, prevent regular login
            return False
        update_session(username)
        return True
    return False

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("un")
        password = request.form.get("pwd")
        is_admin = request.form.get("is_admin") == "on"

        if not username or not password:
            flash('Please fill out both fields.', 'error')
            return redirect(url_for('login_page'))
        
        if check_login(username, password, is_admin):
            if is_admin:
                flash('Admin login successful!', 'success')
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("home"))
        else:
            if is_admin:
                flash('Invalid admin credentials. Please check your ID number and password.', 'error')
            else:
                user = get_user(username)
                if user and user["is_admin"]:
                    flash('Please check "Login as Administrator" to access the admin dashboard.', 'error')
                else:
                    flash('Invalid ID number or password.', 'error')
            return redirect(url_for('login_page'))
    
    return render_template("login.html")

@app.route("/home")
def home():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))
    
    # Check if user is an admin
    if session["user"].get("is_admin"):
        flash("Administrators should use the admin dashboard.", "error")
        return redirect(url_for("admin_dashboard"))
    
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

    # Handle profile picture upload if provided
    profile_pic = session["user"].get("profile_pic", "default.png")  # Keep existing picture by default
    
    if "profile_pic" in request.files:
        file = request.files["profile_pic"]
        if file and file.filename:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            profile_pic = filename

    # Update database with all information including profile picture
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    cur.execute("""
        UPDATE users 
        SET firstname = ?, lastname = ?, email = ?, course = ?, yearlevel = ?, profile_pic = ?
        WHERE id = ?
    """, (firstname, lastname, email, course, yearlevel, profile_pic, user_id))
    con.commit()
    con.close()

    # Update session data
    session["user"] = {
        "id": user_id,
        "firstname": firstname,
        "lastname": lastname,
        "email": email,
        "course": course,
        "yearlevel": yearlevel,
        "profile_pic": profile_pic
    }

    flash("Profile updated successfully!", "success")
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
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))
    
    user_id = session["user"]["id"]
    
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    
    # Get active sessions for the user
    cur.execute("""
        SELECT s.*, u.firstname, u.lastname, u.course, u.yearlevel
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.user_id = ? AND s.status = 'active'
        ORDER BY s.start_time DESC
    """, (user_id,))
    active_sessions = cur.fetchall()
    
    # Get completed sessions for the last 7 days
    cur.execute("""
        SELECT s.*, u.firstname, u.lastname, u.course, u.yearlevel
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.user_id = ? AND s.status = 'completed'
        AND s.start_time >= date('now', '-7 days')
        ORDER BY s.start_time DESC
    """, (user_id,))
    recent_sessions = cur.fetchall()
    
    con.close()
    
    return render_template('remaining_sessions.html', 
                         active_sessions=active_sessions,
                         recent_sessions=recent_sessions)

@app.route('/sit_in_rors')
def sit_in_rors():
    return render_template('sit_in_rors.html')

@app.route('/sit_in_history')
def sit_in_history():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))
    
    user_id = session["user"]["id"]
    
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    
    # Get all sit-in history for the user
    cur.execute("""
        SELECT h.*, u.firstname, u.lastname, u.course, u.yearlevel
        FROM sit_in_history h
        JOIN users u ON h.user_id = u.id
        WHERE h.user_id = ?
        ORDER BY h.date DESC, h.time_in DESC
    """, (user_id,))
    history = cur.fetchall()
    
    # Get statistics
    cur.execute("""
        SELECT 
            COUNT(*) as total_sessions,
            SUM(duration) as total_duration,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_sessions
        FROM sit_in_history
        WHERE user_id = ?
    """, (user_id,))
    stats = cur.fetchone()
    
    con.close()
    
    return render_template('sit_in_history.html', 
                         history=history,
                         stats=stats)

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    return render_template('signup.html')

@app.route("/logout")
def logout():
    if "admin" in session:
        session.pop("admin", None)
        flash("Admin logged out successfully!", "success")
    else:
        session.clear()
        flash("You have been logged out.", "success")
    return redirect(url_for("login_page"))

# Remove the register_admin route since we're using a fixed admin account
@app.route("/register_admin", methods=["GET", "POST"])
def register_admin():
    flash("Admin registration is not available.", "error")
    return redirect(url_for("login_page"))

# Add new route for starting a session
@app.route('/start_session', methods=['POST'])
def start_session():
    if "user" not in session:
        return jsonify({"error": "Please log in first."}), 401
    
    user_id = session["user"]["id"]
    current_time = datetime.now()
    
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    
    # Create new session
    cur.execute("""
        INSERT INTO sessions (user_id, start_time, status)
        VALUES (?, ?, 'active')
    """, (user_id, current_time))
    
    # Create sit-in history entry
    cur.execute("""
        INSERT INTO sit_in_history (user_id, date, time_in, status)
        VALUES (?, ?, ?, 'active')
    """, (user_id, current_time.date(), current_time))
    
    con.commit()
    con.close()
    
    return jsonify({"message": "Session started successfully"})

# Add new route for ending a session
@app.route('/end_session', methods=['POST'])
def end_session():
    if "user" not in session:
        return jsonify({"error": "Please log in first."}), 401
    
    user_id = session["user"]["id"]
    current_time = datetime.now()
    
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    
    # Update active session
    cur.execute("""
        UPDATE sessions 
        SET end_time = ?, status = 'completed'
        WHERE user_id = ? AND status = 'active'
    """, (current_time, user_id))
    
    # Update sit-in history entry
    cur.execute("""
        UPDATE sit_in_history 
        SET time_out = ?, duration = strftime('%s', ?) - strftime('%s', time_in), status = 'completed'
        WHERE user_id = ? AND status = 'active'
    """, (current_time, current_time, user_id))
    
    con.commit()
    con.close()
    
    return jsonify({"message": "Session ended successfully"})

if __name__ == "__main__":
    app.run(debug=True)
