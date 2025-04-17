# -------------------- Import Required Libraries --------------------
import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import random
import string

# -------------------- Constants --------------------
USER_DB_FILE = "users.json"
DATA_DB_FILE = "stored_data.json"

# -------------------- Load JSON Files --------------------
def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return {}

def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

# -------------------- Load Users and Data --------------------
users = load_json(USER_DB_FILE)
stored_data = load_json(DATA_DB_FILE)

# -------------------- Initialize Session --------------------
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

# -------------------- App Configuration --------------------
st.set_page_config(page_title="Ameer Hamza's Secure Vault", layout="centered")
st.markdown("""
    <style>
        .main {background-color: #fceae8; color: #1e1e1e; font-family: 'Arial';}
        h1, h2, h3 { color: #ff4b4b; }
        .stButton>button {
            background-color: #ffb3b3;
            color: white;
            border-radius: 10px;
        }
        .stTextInput>div>div>input {
            border: 2px solid #ff4b4b;
        }
    </style>
""", unsafe_allow_html=True)

# -------------------- Login and Sign Up --------------------
if not st.session_state.authenticated:
    st.title("🔐 Ameer Hamza's Secure Vault")
    st.info("Welcome! Please log in or create an account to continue.")
    tab1, tab2 = st.tabs(["Login", "Sign Up"])

    with tab2:
        st.subheader("🧾 Create New Account")
        new_user = st.text_input("Username")
        new_pass = st.text_input("Password", type="password")
        strength, feedback = evaluate_password_strength(new_pass)
        if new_pass:
            st.info(f"🔎 Strength: **{strength}**")
            for line in feedback.split("\n"):
                st.write(f"- {line}")
        if st.button("Register"):
            if new_user and strength == "Strong":
                if new_user in users:
                    st.error("⚠️ Username already exists.")
                else:
                    user_key = generate_user_key()
                    users[new_user] = {"password": hash_passkey(new_pass), "key": user_key}
                    stored_data[new_user] = {}
                    save_json(USER_DB_FILE, users)
                    save_json(DATA_DB_FILE, stored_data)
                    st.success("✅ Account created! Please log in.")
            else:
                st.error("❌ Please provide a unique username and strong password.")

    with tab1:
        st.subheader("🔐 User Login")
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            if username in users and users[username]["password"] == hash_passkey(password):
                st.session_state.authenticated = True
                st.session_state.username = username
                st.success("✅ Logged in successfully!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials.")

# -------------------- Main App After Login --------------------
else:
    st.title(f"🛡️ Welcome, {st.session_state.username} ✨")
    menu = ["Home", "Store Data", "Retrieve Data", "Download Data", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Logout":
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.success("✅ Logged out.")
        st.rerun()

    elif choice == "Home":
        st.subheader("🏠 Dashboard")
        st.success("✨ This app is developed and maintained by Ameer Hamza.")
        st.info("🔐 Use the sidebar to store and retrieve your secure data.")

    elif choice == "Store Data":
        st.subheader("📂 Store Your Data")
        text = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter passkey:", type="password")
        if st.button("Encrypt & Save"):
            if text and passkey:
                user = st.session_state.username
                user_key = users[user]["key"]
                cipher = get_cipher(user_key)
                encrypted = encrypt_data(text, cipher)
                hashed = hash_passkey(passkey)
                stored_data[user][encrypted] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed,
                    "timestamp": datetime.now().isoformat()
                }
                save_json(DATA_DB_FILE, stored_data)
                st.success("✅ Data encrypted and stored!")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ All fields are required.")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Encrypted Data")
        user = st.session_state.username
        user_data = stored_data.get(user, {})
        if user_data:
            st.write("🔐 Encrypted Entries:")
            encrypted_options = list(user_data.keys())
            selected_encrypted = st.selectbox("Select encrypted entry", encrypted_options)
            passkey = st.text_input("Enter passkey to decrypt:", type="password")
            if st.button("Decrypt"):
                decrypted_text = decrypt_data(selected_encrypted, passkey)
                if decrypted_text:
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Text", decrypted_text, height=150)
                else:
                    if st.session_state.lockout_time and datetime.now() < st.session_state.lockout_time:
                        remaining = (st.session_state.lockout_time - datetime.now()).seconds
                        st.error(f"⏳ Too many attempts! Try again in {remaining} seconds.")
                    else:
                        st.error("❌ Incorrect passkey.")
        else:
            st.info("📭 No data stored yet.")

    elif choice == "Download Data":
        st.subheader("📥 Download Stored Data")
        user = st.session_state.username
        user_data = stored_data.get(user, {})
        if user_data:
            data_text = json.dumps(user_data, indent=4)
            st.download_button(
                label="⬇️ Download Encrypted Data as JSON",
                data=data_text,
                file_name=f"{user}_encrypted_data.json",
                mime="application/json"
            )
        else:
            st.info("📭 No data available to download.")
