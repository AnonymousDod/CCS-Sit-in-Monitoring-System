from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flashing messages and session management

# Function to check login credentials
def check_login(username, password):
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    con.close()
    
    return row and row[0] == password  # Returns True if password matches

# Route for login page
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("un")
        password = request.form.get("pwd")

        # Check if both fields are filled out
        if not username or not password:
            flash('Please fill out both fields.', 'error')
            return redirect(url_for('login_page'))  # Redirect back to the login page
        
        if check_login(username, password):
            session["user"] = username  # Store username in session
            return redirect(url_for("home"))  # Redirect to home page if login is successful
        else:
            flash('Invalid Username or Password', 'error')  # Flash the error message
            return redirect(url_for('login_page'))  # Redirect back to the login page

    return render_template("index.html")  # Renders the login page for GET request

# Route for home page after successful login
@app.route("/home")
def home():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))  # Redirect to login if not logged in
    return render_template("homepage.html", user=session["user"])  # Pass user session to homepage

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login_page"))  # Redirect to login if not logged in
    return render_template("dashboard.html", user=session["user"])


# Route for logout
@app.route("/logout")
def logout():
    session.pop("user", None)  # Remove user from session
    flash("You have been logged out.", "success")
    return redirect(url_for("login_page"))  # Redirect to login page


# Route for signup (GET: Show form, POST: Process registration)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    return render_template("signup.html")  # Render the signup form for GET requests

# Route for handling registration form submission
@app.route("/register", methods=["POST"])
def register_user():
    if request.method == "POST":
        # Get form data
        idno = request.form.get("idno")
        lastname = request.form.get("lastname")
        firstname = request.form.get("firstname")
        midname = request.form.get("midname")
        course = request.form.get("course")
        yearlevel = request.form.get("yearlevel")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if username already exists
        con = sqlite3.connect("users.db")
        cur = con.cursor()

        # Check for existing username
        cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            flash('Username already taken. Please choose another one.', 'error')
            con.close()
            return redirect(url_for('signup'))  # Redirect to signup page if username exists

        # Save the new user to your database
        cur.execute(""" 
            INSERT INTO users (idno, lastname, firstname, midname, course, yearlevel, email, username, password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (idno, lastname, firstname, midname, course, yearlevel, email, username, password))

        con.commit()
        con.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for("login_page"))  # Redirect to login page after successful registration

# Ensure the database exists and create the table if it doesn't
def create_db():
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    
    cur.execute(""" 
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idno TEXT,
            lastname TEXT,
            firstname TEXT,
            midname TEXT,
            course TEXT,
            yearlevel TEXT,
            email TEXT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    
    con.commit()
    con.close()

if __name__ == "__main__":
    create_db()  # Ensure the database is created when the app starts
    app.run(debug=True)  # Runs Flask on http://127.0.0.1:5000
