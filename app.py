# -------------------- Import Required Libraries --------------------
import streamlit as st  # Streamlit for the web app interface
import hashlib  # To hash passwords and passkeys
import json  # For working with JSON data files
import os  # For checking file paths
from cryptography.fernet import Fernet  # To encrypt and decrypt data
from datetime import datetime, timedelta  # To manage time-based lockouts
import random  # For generating random strings (e.g., passwords)
import string  # For character sets used in password generation

# -------------------- Constants --------------------
USER_DB_FILE = "users.json"
DATA_DB_FILE = "stored_data.json"

# -------------------- Page Configuration --------------------
st.set_page_config(page_title="🔐 Secure Vault", layout="centered")
st.markdown("""
    <style>
        .stApp {
            background-color: #f5f6fa;
            color: #000000;
        }
        .main > div {
            background: linear-gradient(135deg, #ffffff, #e0e0f0);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0px 4px 30px rgba(0, 0, 0, 0.1);
        }
        h1 {
            text-align: center;
            font-size: 36px;
            font-weight: bold;
            color: #111111;
        }
        h2, h3, h4 {
            color: #222222;
        }
        p, label, span, li {
            color: #333333;
        }
        @media only screen and (max-width: 768px) {
            h1 {
                font-size: 24px !important;
                text-align: center;
            }
        }
        footer::after {
            content: "Created by HAMZA";
            display: block;
            text-align: center;
            color: #555;
            margin-top: 20px;
            font-size: 12px;
        }
        button[kind="primary"] {
            background-color: #1e88e5 !important;
            color: white !important;
            border-radius: 8px;
        }
        .stTextInput input, .stNumberInput input, .stPasswordInput input {
            background-color: #ffffff;
            color: #000000;
            border: 1px solid #ccc;
        }
    </style>
""", unsafe_allow_html=True)

# -------------------- Initialization Functions --------------------
def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return {}

def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

users = load_json(USER_DB_FILE)
stored_data = load_json(DATA_DB_FILE)

# -------------------- Session State Initialization --------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# -------------------- Helper Functions --------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def get_cipher(user_key):
    return Fernet(user_key.encode())

def generate_user_key():
    return Fernet.generate_key().decode()

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def evaluate_password_strength(password):
    feedback = []
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters.")
    if not any(c.isupper() for c in password):
        feedback.append("Add at least one uppercase letter.")
    if not any(c.islower() for c in password):
        feedback.append("Add at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        feedback.append("Add at least one number.")
    if not any(c in string.punctuation for c in password):
        feedback.append("Add at least one special character.")

    if feedback:
        return "Weak", "\n".join(feedback)
    return "Strong", "Great password!"

def encrypt_data(text, cipher):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    username = st.session_state.username
    user_data = stored_data.get(username, {})

    if encrypted_text in user_data:
        record = user_data[encrypted_text]
        if record["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            user_key = users[username]["key"]
            cipher = get_cipher(user_key)
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.session_state.lockout_time = datetime.now() + timedelta(seconds=30)
    return None
