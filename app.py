from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail, Message  # Added Flask-Mail for sending emails
import os
import logging
import random  # For generating OTP
from dotenv import load_dotenv
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings("ignore")

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

# MongoDB configuration
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/kira")
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
# Ensure indexes for optimized queries
mongo.db.users.create_index("email", unique=True)
mongo.db.questions.create_index("username")


# Configure Flask-Mail
app.config["MAIL_SERVER"] = "smtp.gmail.com"  # Replace with your email provider's SMTP server
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("EMAIL_USERNAME")  # Your email
app.config["MAIL_PASSWORD"] = os.getenv("EMAIL_PASSWORD")  # Your email password
mail = Mail(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Serve static files
@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

# Serve index.html (Login Page)
@app.route("/")
def index():
    return render_template("loginpage.html")

# Serve registration page
@app.route("/register-page")
def register_page():
    return render_template("registrationpage.html")

# User Registration Endpoint
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.json
        logger.debug(f"Received registration data: {data}")

        name = data.get("name")
        email = data.get("email")
        roll_number = data.get("rollNumber")
        password = data.get("password")

        if not all([name, email, roll_number, password]):
            logger.error("Missing required fields")
            return jsonify({"success": False, "message": "All fields are required"}), 400

        # Check if the user already exists
        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            logger.error("User already exists")
            return jsonify({"success": False, "message": "This email is already registered. Try logging in or using a different email."}), 400


        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Insert the new user into the database
        user_data = {
            "name": name,
            "email": email,
            "roll_number": roll_number,
            "password": hashed_password
        }
        mongo.db.users.insert_one(user_data)
        logger.debug(f"User registered successfully: {user_data}")

        return jsonify({"success": True, "message": "User registered successfully"}), 201

    except Exception as e:
        logger.error(f"Error during registration: {e}")
        return jsonify({"success": False, "message": "An error occurred during registration"}), 500

@app.route("/send-otp", methods=["POST"])
def send_otp():
    try:
        data = request.json
        email = data.get("email")

        if not email:
            return jsonify({"success": False, "message": "Email is required"}), 400

        # Generate a 4-digit OTP
        otp = str(random.randint(1000, 9999))
        expiry_time = datetime.utcnow() + timedelta(minutes=15)  # OTP expires in 15 minutes

        # Store OTP in the database
        mongo.db.otp_verification.update_one(
            {"email": email},
            {"$set": {"otp": otp, "expires_at": expiry_time}},
            upsert=True
        )

        # Send OTP via email
        msg = Message(
            subject="Your OTP Code",
            sender=app.config["MAIL_USERNAME"],
            recipients=[email],
            body=f"Your OTP for registration is: {otp}. It will expire in 15 minutes."
        )
        mail.send(msg)

        return jsonify({"success": True, "message": "OTP sent successfully"}), 200

    except Exception as e:
        logger.error(f"Error sending OTP: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500



@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        roll_number = data.get("rollNumber")
        password = data.get("password")
        otp = data.get("otp")

        # Validate all fields
        if not all([name, email, roll_number, password, otp]):
            return jsonify({"success": False, "message": "All fields are required"}), 400

        # Fetch OTP from the database
        otp_record = mongo.db.otp_verification.find_one({"email": email})

        if not otp_record or otp_record["otp"] != otp:
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        # Check if OTP has expired
        if otp_record["expires_at"] < datetime.utcnow():
            return jsonify({"success": False, "message": "OTP has expired"}), 400

        # Check if the user already exists
        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            return jsonify({"success": False, "message": "This email is already registered"}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Insert the user into the database
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "roll_number": roll_number,
            "password": hashed_password
        })

        # Remove OTP record after successful verification
        mongo.db.otp_verification.delete_one({"email": email})

        return jsonify({"success": True, "message": "User registered successfully"}), 201

    except Exception as e:
        logger.error(f"Error verifying OTP: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500


# User Login Endpoint
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        logger.debug(f"Received login data: {data}")

        email = data.get("email")
        password = data.get("password")

        if not all([email, password]):
            logger.error("Missing email or password")
            return jsonify({"success": False, "message": "Email and password are required"}), 400

        # Check if the user exists
        user = mongo.db.users.find_one({"email": email})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["user"] = email  # Store user email in session
            logger.debug(f"User logged in successfully: {email}")
            return jsonify({"success": True, "message": "Login successful", "redirect": url_for("chat")}), 200

        logger.error("Invalid credentials")
        return jsonify({"success": False, "message": "Incorrect email or password. Please check and try again."}), 401


    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"success": False, "message": "An error occurred during login"}), 500
    

@app.route("/ask", methods=["POST"])
def ask():
    if "user" not in session:
        return jsonify({"success": False, "message": "User not logged in"}), 401
    try:
        data = request.json
        question = data.get("question")
        if not question:
            return jsonify({"success": False, "message": "Question is required"}), 400

        username = session["user"]

        # Fetch user's existing questions
        user_query_doc = mongo.db.questions.find_one({"username": username})

        if user_query_doc:
            # Extract existing questions (ignoring case)
            existing_questions = {q["qns"].lower() for q in user_query_doc.get("queries", [])}

            if question.lower() not in existing_questions:
                # Append only if the question is new
                mongo.db.questions.update_one(
                    {"username": username},
                    {"$push": {"queries": {"qns": question, "timestamp": datetime.utcnow()}}}
                )
        else:
            # If no previous queries exist, create a new document
            query_data = {
                "username": username,
                "queries": [{"qns": question, "timestamp": datetime.utcnow()}]
            }
            mongo.db.questions.insert_one(query_data)

        # Simulated response (Replace this with chatbot logic)
        answer = f"I received your question: {question}"

        return jsonify({"success": True, "answer": answer}), 200

    except Exception as e:
        logger.error(f"Error saving query: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500


# Save User Query to MongoDB
@app.route("/save-query", methods=["POST"])
def save_query():
    if "user" not in session:
        return jsonify({"success": False, "message": "User not logged in"}), 401
    try:
        data = request.json
        query = data.get("query")
        if not query:
            return jsonify({"success": False, "message": "Query is required"}), 400

        query_data = {
            "email": session["user"],
            "query": query,
            "timestamp": datetime.utcnow()
        }
        mongo.db.questions.insert_one(query_data)
        return jsonify({"success": True, "message": "Query saved"}), 200
    except Exception as e:
        logger.error(f"Error saving query: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500

# Retrieve User Queries
@app.route("/get-queries", methods=["GET"])
def get_queries():
    if "user" not in session:
        return jsonify({"success": False, "message": "Please log in to view your queries."}), 401
    try:
        username = session["user"]

        # Fetch only queries belonging to the logged-in user
        user_query_doc = mongo.db.questions.find_one({"username": username})

        if not user_query_doc:
            return jsonify({"success": True, "queries": []}), 200

        # Extract queries specific to the logged-in user
        queries = user_query_doc.get("queries", [])

        # Convert timestamps to a readable format
        for query in queries:
            if "timestamp" in query:
                query["timestamp"] = query["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

        return jsonify({"success": True, "queries": queries}), 200

    except Exception as e:
        logger.error(f"Error retrieving queries: {e}")
        return jsonify({"success": False, "message": "Something went wrong. Please try again later."}), 500


# Serve chat.html (Chat Page)
@app.route("/chat")
def chat():
    if "user" in session:
        return render_template("chat.html")
    return redirect(url_for("index"))

# Serve about.html (About Page)
@app.route("/about")
def about():
    return render_template("about.html")

# Serve contact.html (Contact Page)
@app.route("/contact")
def contact():
    return render_template("contact.html")

# Serve forgotpassword.html (Forgot Password Page)
@app.route("/forgotpassword")
def forgot_password():
    return render_template("forgotpassword.html")

# Forgot Password Endpoint
@app.route("/forgot-password", methods=["POST"])
def forgot_password_submit():
    try:
        data = request.json
        email = data.get("email")

        if not email:
            return jsonify({"success": False, "message": "Email is required"}), 400

        user = mongo.db.users.find_one({"email": email})
        if not user:
            return jsonify({"success": False, "message": "Email not registered"}), 404

        # Generate a 4-digit OTP
        otp = str(random.randint(1000, 9999))
        expiry_time = datetime.utcnow() + timedelta(minutes=15)  # OTP expires in 15 mins
        otp_expires_at = datetime.utcnow() + timedelta(minutes=15) 

        # Store the OTP with expiry time
        mongo.db.users.update_one({"email": email}, {"$set": {"reset_otp": otp, "otp_expires_at": otp_expires_at}})

        # Send OTP via email
        msg = Message(
            subject="Password Reset OTP",
            sender="your-email@example.com",
            recipients=[email],
            body=f"Your OTP for password reset is: {otp}. It will expire in 15 minutes."
        )
        mail.send(msg)

        return jsonify({"success": True, "message": "OTP sent to your email"}), 200

    except Exception as e:
        logger.error(f"Error during forgot password: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500
    
# Reset Password Page
@app.route("/reset-password", methods=["POST"])
def reset_password():
    try:
        data = request.json
        email = data.get("email")
        new_password = data.get("new_password")

        if not all([email, new_password]):
            return jsonify({"success": False, "message": "Email and new password are required"}), 400

        # Update the password in the database
        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})

        return jsonify({"success": True, "message": "Password reset successfully"}), 200

    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500
    
# Verify OTP Endpoint
# Verify OTP for Password Reset (Rename this route)
@app.route("/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    try:
        data = request.json
        email = data.get("email")
        otp = data.get("otp")

        if not all([email, otp]):
            return jsonify({"success": False, "message": "Email and OTP are required"}), 400

        user = mongo.db.users.find_one({"email": email})
        if not user or "reset_otp" not in user or "otp_expires_at" not in user:
            return jsonify({"success": False, "message": "Invalid OTP request"}), 400

        # Check if OTP has expired
        if datetime.utcnow() > user["otp_expires_at"]:
            return jsonify({"success": False, "message": "OTP has expired. Please request a new one."}), 400

        # Check if OTP matches
        if user["reset_otp"] != otp:
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        # OTP is correct, clear OTP fields
        mongo.db.users.update_one({"email": email}, {"$unset": {"reset_otp": "", "otp_expires_at": ""}})

        return jsonify({"success": True, "message": "OTP verified successfully"}), 200

    except Exception as e:
        logger.error(f"Error during OTP verification: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500
    
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    user = mongo.db.users.find_one({"email": session['user']})
    if user:
        return render_template('profile.html')
    return redirect(url_for('index'))

@app.route('/get-profile')
def get_profile():
    if 'user' not in session:
        return jsonify({"success": False}), 401
    
    user = mongo.db.users.find_one({"email": session['user']}, {'_id': 0, 'password': 0})
    if user:
        return jsonify({"success": True, "user": user})
    return jsonify({"success": False}), 404


# Logout
@app.route("/logout")
def logout():
    session.pop("user", None)  # Remove user from session
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
