from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail, Message
import os
import logging
import random
from dotenv import load_dotenv
from datetime import datetime, timedelta
import warnings
import requests  
warnings.filterwarnings("ignore")
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

# MongoDB configuration
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/kira")
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mongo.db.users.create_index("email", unique=True)
mongo.db.questions.create_index("username")

# Configure Flask-Mail
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("EMAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("EMAIL_PASSWORD")
mail = Mail(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Ollama API configuration
OLLAMA_API_URL = "http://localhost:11434/api/generate"  # Ollama API endpoint

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

        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            logger.error("User already exists")
            return jsonify({"success": False, "message": "This email is already registered. Try logging in or using a different email."}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

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

# Send OTP Endpoint
@app.route("/send-otp", methods=["POST"])
def send_otp():
    try:
        data = request.json
        email = data.get("email")

        if not email:
            return jsonify({"success": False, "message": "Email is required"}), 400

        otp = str(random.randint(1000, 9999))
        expiry_time = datetime.utcnow() + timedelta(minutes=15)

        mongo.db.otp_verification.update_one(
            {"email": email},
            {"$set": {"otp": otp, "expires_at": expiry_time}},
            upsert=True
        )

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

# Verify OTP Endpoint
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        roll_number = data.get("rollNumber")
        password = data.get("password")
        otp = data.get("otp")

        if not all([name, email, roll_number, password, otp]):
            return jsonify({"success": False, "message": "All fields are required"}), 400

        otp_record = mongo.db.otp_verification.find_one({"email": email})

        if not otp_record or otp_record["otp"] != otp:
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        if otp_record["expires_at"] < datetime.utcnow():
            return jsonify({"success": False, "message": "OTP has expired"}), 400

        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            return jsonify({"success": False, "message": "This email is already registered"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "roll_number": roll_number,
            "password": hashed_password
        })

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

        user = mongo.db.users.find_one({"email": email})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["user"] = email
            logger.debug(f"User logged in successfully: {email}")
            return jsonify({"success": True, "message": "Login successful", "redirect": url_for("chat")}), 200

        logger.error("Invalid credentials")
        return jsonify({"success": False, "message": "Incorrect email or password. Please check and try again."}), 401

    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"success": False, "message": "An error occurred during login"}), 500

# Ask Endpoint (Updated to use Ollama)
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

        # Check if the question already exists for the user
        user_query_doc = mongo.db.questions.find_one({"username": username})
        if user_query_doc:
            existing_questions = {q["qns"].lower() for q in user_query_doc.get("queries", [])}
            if question.lower() not in existing_questions:
                mongo.db.questions.update_one(
                    {"username": username},
                    {"$push": {"queries": {"qns": question, "timestamp": datetime.utcnow()}}}
                )
        else:
            query_data = {
                "username": username,
                "queries": [{"qns": question, "timestamp": datetime.utcnow()}]
            }
            mongo.db.questions.insert_one(query_data)

        # Send the question to Ollama
        payload = {
            "model": "gemma:2b",  # Replace with your model name
            "prompt": question,
            "stream": False  # Set to True if you want streaming responses
        }
        response = requests.post(OLLAMA_API_URL, json=payload)
        response.raise_for_status()

        # Extract the generated response
        generated_text = response.json().get("response", "No response generated")

        return jsonify({"success": True, "answer": generated_text}), 200

    except Exception as e:
        logger.error(f"Error during question processing: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500
    

@app.route("/get-queries", methods=["GET"])
def get_queries():
    if "user" not in session:
        return jsonify({"success": False, "message": "User not logged in"}), 401
    try:
        username = session["user"]
        user_query_doc = mongo.db.questions.find_one({"username": username})

        if not user_query_doc:
            return jsonify({"success": True, "queries": []}), 200

        # Deduplicate while preserving order and keeping latest entries
        seen = set()
        deduped_queries = []
        
        # Reverse to process oldest first, then reverse again to maintain recent-first order
        for query in reversed(user_query_doc.get("queries", [])):
            clean_q = query["qns"].strip().lower()
            if clean_q not in seen:
                seen.add(clean_q)
                deduped_queries.append(query)
        
        # Reverse back to show most recent first
        deduped_queries.reverse()

        # Format timestamps
        for query in deduped_queries:
            if "timestamp" in query:
                query["timestamp"] = query["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

        return jsonify({"success": True, "queries": deduped_queries}), 200

    except Exception as e:
        logger.error(f"Error retrieving queries: {e}")
        return jsonify({"success": False, "message": "Something went wrong. Please try again later."}), 500
    

@app.route("/recent-questions", methods=["GET"])
def recent_questions():
    if "user" not in session:
        return jsonify({"success": False, "message": "User not logged in"}), 401

    try:
        username = session["user"]
        user_query_doc = mongo.db.questions.find_one({"username": username}, {"_id": 0, "queries": 1})

        if user_query_doc and "queries" in user_query_doc:
            # Remove duplicate questions while preserving order
            seen_questions = set()
            unique_queries = []
            for query in user_query_doc["queries"]:
                if query["qns"].lower() not in seen_questions:
                    seen_questions.add(query["qns"].lower())
                    unique_queries.append(query)

            # Sort by timestamp in descending order (most recent first)
            unique_queries.sort(key=lambda x: x["timestamp"], reverse=True)

            return jsonify({"success": True, "questions": unique_queries}), 200
        else:
            return jsonify({"success": True, "questions": []}), 200

    except Exception as e:
        logger.error(f"Error fetching recent questions: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500
    

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

        otp = str(random.randint(1000, 9999))
        expiry_time = datetime.utcnow() + timedelta(minutes=15)

        mongo.db.users.update_one({"email": email}, {"$set": {"reset_otp": otp, "otp_expires_at": expiry_time}})

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

# Reset Password Endpoint
@app.route("/reset-password", methods=["POST"])
def reset_password():
    try:
        data = request.json
        email = data.get("email")
        new_password = data.get("new_password")

        if not all([email, new_password]):
            return jsonify({"success": False, "message": "Email and new password are required"}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})

        return jsonify({"success": True, "message": "Password reset successfully"}), 200

    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500

# Verify OTP for Password Reset
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

        if datetime.utcnow() > user["otp_expires_at"]:
            return jsonify({"success": False, "message": "OTP has expired. Please request a new one."}), 400

        if user["reset_otp"] != otp:
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        mongo.db.users.update_one({"email": email}, {"$unset": {"reset_otp": "", "otp_expires_at": ""}})

        return jsonify({"success": True, "message": "OTP verified successfully"}), 200

    except Exception as e:
        logger.error(f"Error during OTP verification: {e}")
        return jsonify({"success": False, "message": "An error occurred"}), 500

# Profile Page
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('index'))

    user = mongo.db.users.find_one({"email": session['user']})
    if user:
        return render_template('profile.html')
    return redirect(url_for('index'))

# Get Profile Data
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
    session.pop("user", None)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)