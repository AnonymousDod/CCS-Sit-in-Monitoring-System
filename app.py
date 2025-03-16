from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, Response, make_response
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import io
import csv
from io import StringIO
from functools import wraps
import random
import string

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
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        firstname TEXT NOT NULL,
        midname TEXT,
        lastname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        course TEXT NOT NULL,
        yearlevel TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    
    # Create sessions table
    c.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_time TIMESTAMP,
        status TEXT DEFAULT 'active',
        purpose TEXT,
        lab_unit TEXT,
        duration INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create reservations table
    c.execute('''
    CREATE TABLE IF NOT EXISTS reservations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        purpose TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create announcements table
    c.execute('''
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        priority TEXT DEFAULT 'normal',
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create feedback table
    c.execute('''
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comments TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

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

    # Get total users (excluding admins)
    cur.execute("SELECT COUNT(*) as count FROM users WHERE is_admin = 0")
    total_users = cur.fetchone()['count']

    # Get recent users (last 5, excluding admins)
    cur.execute("""
        SELECT username, firstname, lastname, email, course, yearlevel 
        FROM users 
        WHERE is_admin = 0 
        ORDER BY id DESC 
        LIMIT 5
    """)
    recent_users = [dict(row) for row in cur.fetchall()]

    # Get active sessions count
    cur.execute("SELECT COUNT(*) as count FROM sessions WHERE status = 'active'")
    active_sessions = cur.fetchone()['count']

    # Get today's completed sessions
    cur.execute("""
        SELECT COUNT(*) as count 
        FROM sessions 
        WHERE DATE(end_time) = DATE('now') 
        AND status = 'completed'
    """)
    today_completed_sessions = cur.fetchone()['count']

    # Calculate total hours spent today
    cur.execute("""
        SELECT SUM(CAST((julianday(end_time) - julianday(start_time)) * 24 AS INTEGER)) as total_hours
        FROM sessions 
        WHERE DATE(end_time) = DATE('now') 
        AND status = 'completed'
    """)
    result = cur.fetchone()
    total_hours_today = result['total_hours'] if result['total_hours'] is not None else 0

    # Get course statistics
    cur.execute("""
        SELECT course, COUNT(*) as count 
        FROM users 
        WHERE is_admin = 0 
        GROUP BY course
    """)
    course_stats = [dict(row) for row in cur.fetchall()]

    # Get year level statistics
    cur.execute("""
        SELECT yearlevel, COUNT(*) as count 
        FROM users 
        WHERE is_admin = 0 
        GROUP BY yearlevel
    """)
    year_level_stats = [dict(row) for row in cur.fetchall()]

    con.close()

    return render_template("admin_dashboard.html",
                         total_users=total_users,
                         recent_users=recent_users,
                         active_sessions=active_sessions,
                         today_completed_sessions=today_completed_sessions,
                         total_hours_today=total_hours_today,
                         course_stats=course_stats,
                         year_level_stats=year_level_stats)

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
    # Get database connection
    db = get_db()
    cursor = db.cursor()
    
    # Get session statistics
    cursor.execute("""
        SELECT 
            COUNT(DISTINCT user_id) as active_users,
            COUNT(*) as total_sessions,
            SUM(CASE WHEN end_time IS NOT NULL THEN 1 ELSE 0 END) as completed_sessions,
            AVG(CASE WHEN end_time IS NOT NULL THEN 
                (julianday(end_time) - julianday(start_time)) * 24 * 60 
                ELSE 0 END) as avg_duration
        FROM sessions
    """)
    stats = cursor.fetchone()
    
    # Render the template with statistics
    return render_template("admin_sessions.html", stats=stats)

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
    
    # Get announcements
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("""
        SELECT a.*, u.username as created_by
        FROM announcements a
        JOIN users u ON a.created_by = u.id
        ORDER BY a.created_at DESC
        LIMIT 5
    """)
    announcements = []
    for row in cur.fetchall():
        announcement = dict(row)
        # Convert created_at string to datetime object
        announcement['created_at'] = datetime.strptime(announcement['created_at'], '%Y-%m-%d %H:%M:%S')
        announcements.append(announcement)
    con.close()
    
    return render_template("homepage.html", user=session["user"], announcements=announcements)

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

def get_db():
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    return con

@app.route('/announcements')
def announcements():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))
    
    # Get announcements
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        SELECT a.*, u.username as created_by
        FROM announcements a
        JOIN users u ON a.created_by = u.id
        ORDER BY a.created_at DESC
    """)
    announcements = [dict(row) for row in cur.fetchall()]
    con.close()
    
    return render_template("announcements.html", announcements=announcements)

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
        SELECT s.*, u.firstname, u.lastname
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.user_id = ? AND s.status = 'active'
        ORDER BY s.start_time DESC
    """, (user_id,))
    active_sessions = [dict(row) for row in cur.fetchall()]
    
    # Get completed sessions for the last 7 days
    cur.execute("""
        SELECT s.*, u.firstname, u.lastname
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.user_id = ? 
        AND s.status = 'completed'
        AND s.start_time >= datetime('now', '-7 days')
        ORDER BY s.start_time DESC
    """, (user_id,))
    recent_sessions = [dict(row) for row in cur.fetchall()]
    
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
        return redirect(url_for('login_page'))
    
    user_id = session["user"]["id"]
    
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Get user's session history
        cur.execute("""
            SELECT id, start_time, end_time, duration, status
            FROM sessions
            WHERE user_id = ?
            ORDER BY start_time DESC
        """, (user_id,))
        history = cur.fetchall()
        
        # Get statistics
        cur.execute("""
            SELECT 
                COUNT(*) as total_sessions,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_sessions,
                SUM(CASE WHEN duration IS NOT NULL THEN duration ELSE 0 END) as total_duration
            FROM sessions
            WHERE user_id = ?
        """, (user_id,))
        stats = cur.fetchone()
        
        con.close()
        
        # Format history data
        formatted_history = []
        for entry in history:
            formatted_entry = {
                'id': entry[0],
                'date': datetime.strptime(entry[1], '%Y-%m-%d %H:%M:%S.%f').strftime('%Y-%m-%d'),
                'time_in': datetime.strptime(entry[1], '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S'),
                'time_out': datetime.strptime(entry[2], '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S') if entry[2] else None,
                'duration': entry[3],
                'status': entry[4]
            }
            formatted_history.append(formatted_entry)
        
        # Format statistics
        statistics = {
            'total_sessions': stats[0],
            'completed_sessions': stats[1],
            'total_duration': stats[2]
        }
        
        return render_template('sit_in_history.html', history=formatted_history, stats=statistics)
    except Exception as e:
        if con:
            con.close()
        flash('Error loading history: ' + str(e), 'error')
        return redirect(url_for('home'))

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
    
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Check if user already has an active session
        cur.execute("""
            SELECT id FROM sessions 
            WHERE user_id = ? AND status = 'active'
        """, (user_id,))
        
        if cur.fetchone():
            con.close()
            return jsonify({"error": "You already have an active session"}), 400
        
        # Create new session
        cur.execute("""
            INSERT INTO sessions (user_id, start_time, status)
            VALUES (?, ?, 'active')
        """, (user_id, current_time))
        
        session_id = cur.lastrowid
        
        con.commit()
        con.close()
        
        return jsonify({"success": True, "message": "Session started successfully", "session_id": session_id})
    except Exception as e:
        if con:
            con.close()
        return jsonify({"error": str(e)}), 500

@app.route('/end_session', methods=['POST'])
def end_session():
    if "user" not in session:
        return jsonify({"error": "Please log in first."}), 401
    
    user_id = session["user"]["id"]
    current_time = datetime.now()
    
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Get active session for the user
        cur.execute("""
            SELECT id, start_time 
            FROM sessions 
            WHERE user_id = ? AND status = 'active'
            ORDER BY start_time DESC LIMIT 1
        """, (user_id,))
        active_session = cur.fetchone()

        if not active_session:
            return jsonify({'error': 'No active session found'}), 404

        # Calculate duration in minutes
        start_time = datetime.strptime(active_session[1], '%Y-%m-%d %H:%M:%S.%f')
        duration = int((current_time - start_time).total_seconds() / 60)

        # Update session
        cur.execute("""
            UPDATE sessions 
            SET end_time = ?, status = 'completed', duration = ?
            WHERE id = ?
        """, (current_time, duration, active_session[0]))

        con.commit()
        con.close()
        return jsonify({'success': True})
    except Exception as e:
        if con:
            con.close()
        return jsonify({"error": str(e)}), 500

@app.route("/api/search_student/<student_id>")
@admin_required
def search_student(student_id):
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    
    cur.execute("""
        SELECT id, username, firstname, lastname, course, yearlevel
        FROM users
        WHERE username = ? AND is_admin = 0
    """, (student_id,))
    
    student = cur.fetchone()
    con.close()
    
    if student:
        return jsonify({
            "found": True,
            "id": student["id"],
            "firstname": student["firstname"],
            "lastname": student["lastname"],
            "course": student["course"],
            "yearlevel": student["yearlevel"]
        })
    
    return jsonify({"found": False})

@app.route("/api/start_sitin", methods=["POST"])
@admin_required
def start_sitin():
    data = request.json
    student_id = data.get("studentId")
    purpose = data.get("purpose")
    lab_unit = data.get("labUnit")
    session_id = data.get("sessionId")  # For starting scheduled sessions
    
    if not all([student_id, purpose, lab_unit]):
        return jsonify({"success": False, "error": "Missing required fields"})
    
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Get user ID from username
        cur.execute("SELECT id FROM users WHERE username = ?", (student_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({"success": False, "error": "Student not found"})
        
        user_id = user[0]
        current_time = datetime.now()
        
        # Check if user already has an active session
        cur.execute("""
            SELECT id FROM sessions 
            WHERE user_id = ? AND status = 'active'
        """, (user_id,))
        
        if cur.fetchone():
            return jsonify({"success": False, "error": "Student already has an active session"})
        
        if session_id:
            # Update scheduled session to active
            cur.execute("""
                UPDATE sessions 
                SET status = 'active', 
                    start_time = ?
                WHERE id = ? AND status = 'scheduled'
            """, (current_time, session_id))
        else:
            # Create new session
            cur.execute("""
                INSERT INTO sessions (user_id, start_time, status, purpose, lab_unit)
                VALUES (?, ?, 'active', ?, ?)
            """, (user_id, current_time, purpose, lab_unit))
        
        # Create sit-in history entry
        cur.execute("""
            INSERT INTO sit_in_history (user_id, date, time_in, status, purpose, lab_unit)
            VALUES (?, ?, ?, 'active', ?, ?)
        """, (user_id, current_time.date(), current_time, purpose, lab_unit))
        
        con.commit()
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        con.close()

@app.route("/api/end_sitin/<int:session_id>", methods=["POST"])
@admin_required
def end_sitin(session_id):
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        current_time = datetime.now()
        
        # Update session
        cur.execute("""
            UPDATE sessions 
            SET end_time = ?, 
                status = 'completed',
                duration = CAST((julianday(?) - julianday(start_time)) * 24 * 3600 AS INTEGER)
            WHERE id = ? AND status = 'active'
        """, (current_time, current_time, session_id))
        
        # Get user_id from session
        cur.execute("SELECT user_id FROM sessions WHERE id = ?", (session_id,))
        session_data = cur.fetchone()
        
        if session_data:
            user_id = session_data[0]
            # Update sit-in history
            cur.execute("""
                UPDATE sit_in_history 
                SET time_out = ?, 
                    status = 'completed',
                    duration = CAST((julianday(?) - julianday(time_in)) * 24 * 3600 AS INTEGER)
                WHERE user_id = ? AND status = 'active'
            """, (current_time, current_time, user_id))
        
        con.commit()
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        con.close()

@app.route('/make_reservation', methods=['POST'])
def make_reservation():
    if "user" not in session:
        return jsonify({"error": "Please log in first."}), 401
    
    data = request.get_json()
    user_id = session["user"]["id"]
    
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Insert new reservation
        cur.execute("""
            INSERT INTO reservations (user_id, date, time, purpose, lab_unit, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
        """, (user_id, data['date'], data['time'], data['purpose'], data['lab_unit']))
        
        con.commit()
        con.close()
        
        return jsonify({"success": True, "message": "Reservation submitted successfully"})
    except Exception as e:
        if con:
            con.close()
        return jsonify({"error": str(e)}), 500

@app.route("/api/get_reservations")
@admin_required
def get_reservations():
    try:
        con = sqlite3.connect("users.db")
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        
        # Debug: Print all reservations regardless of status
        cur.execute("""
            SELECT r.*, u.firstname, u.lastname, u.course, u.yearlevel
            FROM reservations r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
        """)
        all_reservations = [dict(row) for row in cur.fetchall()]
        print("All reservations:", all_reservations)
        
        # Get pending reservations
        cur.execute("""
            SELECT r.*, u.firstname, u.lastname, u.course, u.yearlevel
            FROM reservations r
            JOIN users u ON r.user_id = u.id
            WHERE r.status = 'pending'
            ORDER BY r.created_at DESC
        """)
        
        pending_reservations = [dict(row) for row in cur.fetchall()]
        print("Pending reservations:", pending_reservations)
        
        con.close()
        
        return jsonify({
            "reservations": pending_reservations,
            "debug_all_reservations": all_reservations  # This will help us debug
        })
        
    except Exception as e:
        print("Error in get_reservations:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/admin/reservations")
@admin_required
def admin_reservations():
    return render_template("admin_reservations.html")

@app.route("/api/get_pending_reservations")
@admin_required
def get_pending_reservations():
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        SELECT r.*, u.firstname, u.lastname, u.course, u.yearlevel
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        WHERE r.status = 'pending'
        ORDER BY r.date, r.time
    """)
    reservations = [dict(row) for row in cur.fetchall()]
    con.close()
    return jsonify({"success": True, "reservations": reservations})

@app.route("/api/approve_reservation/<int:reservation_id>", methods=["POST"])
@admin_required
def approve_reservation(reservation_id):
    con = get_db()
    cur = con.cursor()
    try:
        cur.execute("UPDATE reservations SET status = 'approved' WHERE id = ?", (reservation_id,))
        con.commit()
        return jsonify({"success": True, "message": "Reservation approved successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        con.close()

@app.route("/api/reject_reservation/<int:reservation_id>", methods=["POST"])
@admin_required
def reject_reservation(reservation_id):
    con = get_db()
    cur = con.cursor()
    try:
        cur.execute("UPDATE reservations SET status = 'rejected' WHERE id = ?", (reservation_id,))
        con.commit()
        return jsonify({"success": True, "message": "Reservation rejected successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        con.close()

@app.route("/api/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Check if user exists and is not an admin
        cur.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({"success": False, "error": "User not found"})
        if user[0]:
            return jsonify({"success": False, "error": "Cannot delete admin users"})
        
        # Delete user's sessions
        cur.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        # Delete user's sit-in history
        cur.execute("DELETE FROM sit_in_history WHERE user_id = ?", (user_id,))
        # Delete user's reservations
        cur.execute("DELETE FROM reservations WHERE user_id = ?", (user_id,))
        # Delete the user
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        con.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        con.close()

@app.route("/api/update_user/<int:user_id>", methods=["POST"])
@admin_required
def update_user(user_id):
    try:
        data = request.json
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Check if user exists
        cur.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        if not cur.fetchone():
            return jsonify({"success": False, "error": "User not found"})
        
        # Update user details
        cur.execute("""
            UPDATE users 
            SET firstname = ?, lastname = ?, email = ?, 
                course = ?, yearlevel = ?
            WHERE id = ?
        """, (data['firstname'], data['lastname'], data['email'],
              data['course'], data['yearlevel'], user_id))
        
        con.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        con.close()

@app.route("/api/get_user_details/<int:user_id>")
@admin_required
def get_user_details(user_id):
    try:
        con = sqlite3.connect("users.db")
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        
        # Get user details
        cur.execute("""
            SELECT id, username, firstname, lastname, email, 
                   course, yearlevel, is_admin
            FROM users WHERE id = ?
        """, (user_id,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "User not found"})
        
        # Get user's session statistics
        cur.execute("""
            SELECT 
                COUNT(*) as total_sessions,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_sessions,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_sessions,
                SUM(duration) as total_duration
            FROM sessions 
            WHERE user_id = ?
        """, (user_id,))
        stats = cur.fetchone()
        
        return jsonify({
            "success": True,
            "user": dict(user),
            "stats": dict(stats)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        con.close()

@app.route("/api/get_session_stats")
@admin_required
def get_session_stats():
    db = get_db()
    cursor = db.cursor()
    
    # Get active users (users with ongoing sessions)
    cursor.execute("""
        SELECT COUNT(DISTINCT user_id) as active_users 
        FROM sessions 
        WHERE end_time IS NULL
    """)
    active_users = cursor.fetchone()['active_users']
    
    # Get total sessions
    cursor.execute("SELECT COUNT(*) as total FROM sessions")
    total_sessions = cursor.fetchone()['total']
    
    # Get completed sessions
    cursor.execute("""
        SELECT COUNT(*) as completed 
        FROM sessions 
        WHERE end_time IS NOT NULL
    """)
    completed_sessions = cursor.fetchone()['completed']
    
    # Get average duration of completed sessions
    cursor.execute("""
        SELECT AVG(CAST((julianday(end_time) - julianday(start_time)) * 24 * 60 AS INTEGER)) as avg_duration 
        FROM sessions 
        WHERE end_time IS NOT NULL
    """)
    avg_duration = cursor.fetchone()['avg_duration'] or 0
    
    return jsonify({
        'success': True,
        'active_users': active_users,
        'total_sessions': total_sessions,
        'completed_sessions': completed_sessions,
        'average_duration': avg_duration
    })

@app.route("/api/get_filtered_sessions")
@admin_required
def get_filtered_sessions():
    filter_type = request.args.get('filter', '')
    db = get_db()
    cursor = db.cursor()
    
    query = """
        SELECT s.*, u.username as student_id, u.firstname, u.lastname,
        CAST((julianday(COALESCE(s.end_time, datetime('now'))) - julianday(s.start_time)) * 24 * 60 as INTEGER) as duration
        FROM sessions s
        JOIN users u ON s.user_id = u.id
    """
    
    if filter_type == 'today':
        query += " WHERE DATE(s.start_time) = DATE('now')"
    elif filter_type == 'week':
        query += " WHERE s.start_time >= datetime('now', '-7 days')"
    elif filter_type == 'month':
        query += " WHERE s.start_time >= datetime('now', '-30 days')"
    
    query += " ORDER BY s.start_time DESC"
    
    cursor.execute(query)
    sessions = cursor.fetchall()
    
    return jsonify({
        'success': True,
        'sessions': sessions
    })

@app.route("/api/export_sessions")
@admin_required
def export_sessions():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT s.id, u.username as student_id, u.firstname, u.lastname,
        s.start_time, s.end_time,
        CAST((julianday(COALESCE(s.end_time, datetime('now'))) - julianday(s.start_time)) * 24 * 60 as INTEGER) as duration
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.start_time DESC
    """)
    
    sessions = cursor.fetchall()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Session ID', 'Student ID', 'Name', 'Start Time', 'End Time', 'Duration (minutes)'])
    
    for session in sessions:
        writer.writerow([
            session['id'],
            session['student_id'],
            f"{session['firstname']} {session['lastname']}",
            session['start_time'],
            session['end_time'] or 'Ongoing',
            session['duration']
        ])
    
    # Create the response
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=sessions_export.csv'}
    )
    
    return response

@app.route("/admin/announcements")
@admin_required
def admin_announcements():
    return render_template("admin_announcements.html")

@app.route("/api/create_announcement", methods=["POST"])
@admin_required
def create_announcement():
    try:
        data = request.get_json()
        title = data.get("title")
        content = data.get("content")
        priority = data.get("priority", "normal")
        
        if not title or not content:
            return jsonify({"success": False, "error": "Title and content are required"})
        
        if priority not in ["normal", "high", "urgent"]:
            priority = "normal"
        
        conn = sqlite3.connect("users.db")
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO announcements (title, content, priority, created_by)
            VALUES (?, ?, ?, ?)
        """, (title, content, priority, session["user"]["id"]))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/get_announcements")
@admin_required
def get_announcements():
    try:
        conn = sqlite3.connect("users.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        cur.execute("""
            SELECT a.*, u.username as created_by
            FROM announcements a
            JOIN users u ON a.created_by = u.id
            ORDER BY a.created_at DESC
        """)
        
        announcements = [dict(row) for row in cur.fetchall()]
        conn.close()
        
        return jsonify({"success": True, "announcements": announcements})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/delete_announcement/<int:announcement_id>", methods=["POST"])
@admin_required
def delete_announcement(announcement_id):
    try:
        conn = sqlite3.connect("users.db")
        cur = conn.cursor()
        
        cur.execute("DELETE FROM announcements WHERE id = ?", (announcement_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/admin/sitin")
@admin_required
def admin_sitin():
    # Get database connection
    conn = get_db()
    cur = conn.cursor()

    # Get statistics
    cur.execute("""
        SELECT 
            COUNT(*) as total_records,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_sessions,
            SUM(CASE WHEN date(time_in) = date('now') THEN 1 ELSE 0 END) as today_sessions,
            SUM(CASE WHEN date(time_in) = date('now') AND time_out IS NOT NULL 
                THEN round((julianday(time_out) - julianday(time_in)) * 24)
                ELSE 0 END) as total_hours_today
        FROM sit_in_history
    """)
    stats = dict(zip(['total_records', 'active_sessions', 'today_sessions', 'total_hours_today'], 
                    cur.fetchone()))

    # Get all sit-in records with user information
    cur.execute("""
        SELECT 
            s.id as session_id,
            u.username as student_id,
            u.firstname || ' ' || u.lastname as student_name,
            u.course,
            u.yearlevel,
            datetime(s.time_in) as time_in,
            datetime(s.time_out) as time_out,
            CASE 
                WHEN s.time_out IS NOT NULL 
                THEN round((julianday(s.time_out) - julianday(s.time_in)) * 24, 1)
                ELSE NULL 
            END as duration,
            s.status
        FROM sit_in_history s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.time_in DESC
    """)
    records = [dict(zip([column[0] for column in cur.description], row))
              for row in cur.fetchall()]

    return render_template('admin_sitin.html', stats=stats, records=records)

@app.route("/api/export_sitin_records")
@admin_required
def export_sitin_records():
    conn = get_db()
    cur = conn.cursor()

    # Get filter parameters
    date = request.args.get('date')
    status = request.args.get('status')
    search = request.args.get('search')

    # Base query
    query = """
        SELECT 
            u.username as student_id,
            u.firstname || ' ' || u.lastname as name,
            u.course,
            u.yearlevel,
            datetime(s.time_in) as time_in,
            datetime(s.time_out) as time_out,
            CASE 
                WHEN s.time_out IS NOT NULL 
                THEN round((julianday(s.time_out) - julianday(s.time_in)) * 24, 1)
                ELSE NULL 
            END as duration,
            s.status
        FROM sit_in_history s
        JOIN users u ON s.user_id = u.id
        WHERE 1=1
    """
    params = []

    # Add filters
    if date:
        query += " AND date(s.time_in) = ?"
        params.append(date)
    if status:
        query += " AND s.status = ?"
        params.append(status)
    if search:
        query += " AND (u.username LIKE ? OR u.firstname LIKE ? OR u.lastname LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])

    query += " ORDER BY s.time_in DESC"
    
    cur.execute(query, params)
    records = cur.fetchall()

    # Create CSV file
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Student ID', 'Name', 'Course', 'Year Level', 'Time In', 'Time Out', 'Duration (hours)', 'Status'])
    
    for record in records:
        writer.writerow([
            record[0],  # student_id
            record[1],  # name
            record[2],  # course
            record[3],  # year level
            record[4],  # time_in
            record[5],  # time_out
            record[6],  # duration
            record[7]   # status
        ])

    # Create response
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=sitin_records.csv'}
    )

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if "user" not in session:
        return jsonify({"error": "Please log in first."}), 401
    
    data = request.get_json()
    user_id = session["user"]["id"]
    current_time = datetime.now()
    
    try:
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Insert feedback
        cur.execute("""
            INSERT INTO feedback (user_id, rating, comments, created_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, data['rating'], data['comments'], current_time))
        
        con.commit()
        con.close()
        
        return jsonify({"success": True, "message": "Feedback submitted successfully"})
    except Exception as e:
        if con:
            con.close()
        return jsonify({"error": str(e)}), 500

@app.route("/api/get_feedback")
@admin_required
def get_feedback():
    try:
        con = sqlite3.connect("users.db")
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        
        # Get feedback with user details
        cur.execute("""
            SELECT 
                f.id,
                f.rating,
                f.comments,
                f.created_at,
                u.username,
                u.firstname,
                u.lastname
            FROM feedback f
            JOIN users u ON f.user_id = u.id
            ORDER BY f.created_at DESC
        """)
        feedback = [dict(row) for row in cur.fetchall()]
        
        # Get statistics
        cur.execute("""
            SELECT 
                ROUND(AVG(rating), 2) as avg_rating,
                COUNT(*) as total,
                SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive,
                SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) as recent
            FROM feedback
        """)
        stats = dict(cur.fetchone())
        
        con.close()
        
        return jsonify({
            'success': True,
            'feedback': feedback,
            'stats': {
                'average_rating': float(stats['avg_rating'] or 0),
                'total_feedback': stats['total'],
                'positive_ratings': stats['positive'],
                'recent_feedback': stats['recent']
            }
        })
    except Exception as e:
        if con:
            con.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/export_feedback")
@admin_required
def export_feedback():
    try:
        con = sqlite3.connect("users.db")
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        
        cur.execute("""
            SELECT 
                f.created_at,
                f.rating,
                f.comments,
                u.username,
                u.firstname,
                u.lastname
            FROM feedback f
            JOIN users u ON f.user_id = u.id
            ORDER BY f.created_at DESC
        """)
        
        feedback_data = cur.fetchall()
        con.close()
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Student ID', 'Name', 'Rating', 'Comments'])
        
        for feedback in feedback_data:
            writer.writerow([
                feedback['created_at'],
                feedback['username'],
                f"{feedback['firstname']} {feedback['lastname']}",
                feedback['rating'],
                feedback['comments']
            ])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=feedback_export.csv'}
        )
    except Exception as e:
        if con:
            con.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/admin/feedback")
@admin_required
def admin_feedback():
    return render_template("admin_feedback.html")

@app.route("/api/add_user", methods=["POST"])
@admin_required
def add_user():
    try:
        data = request.json
        
        # Generate a random password for the new user
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        
        # Generate a username (student ID) based on timestamp
        username = f"ST{datetime.now().strftime('%y%m%d%H%M%S')}"
        
        con = sqlite3.connect("users.db")
        cur = con.cursor()
        
        # Insert new user
        cur.execute("""
            INSERT INTO users (firstname, lastname, email, username, password, course, yearlevel, profile_pic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (data['firstname'], data['lastname'], data['email'], username, hashed_password, 
              data['course'], data['yearlevel'], "default.png"))
        
        user_id = cur.lastrowid
        con.commit()
        
        return jsonify({
            "success": True,
            "message": "User added successfully",
            "user": {
                "id": user_id,
                "username": username,
                "password": password  # Send the plain password back so admin can share it with the user
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        if 'con' in locals():
            con.close()

if __name__ == "__main__":
    app.run(debug=True)
