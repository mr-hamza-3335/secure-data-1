import streamlit as st
import hashlib, json, os, time, base64
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# ------------------ Utilities ------------------

DATA_FILE = "secure_data.json"
LOCKOUT_DURATION = 60  # seconds

def hash_passkey(passkey, salt):
    dk = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return dk.hex()

def get_cipher(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), b'streamlit_salt', 100000)
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_data(text, passkey):
    cipher = get_cipher(passkey)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    cipher = get_cipher(passkey)
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def is_locked_out(lockouts, username):
    if username in lockouts:
        elapsed = time.time() - lockouts[username]
        return elapsed < LOCKOUT_DURATION
    return False

def reset_lockout(lockouts, username):
    if username in lockouts:
        del lockouts[username]

# ------------------ App State ------------------

if "data" not in st.session_state:
    st.session_state.data = load_data()

if "login_user" not in st.session_state:
    st.session_state.login_user = None

if "attempts" not in st.session_state:
    st.session_state.attempts = {}

if "lockout" not in st.session_state:
    st.session_state.lockout = {}

# ------------------ UI ------------------

st.title("🔐 Secure Multi-User Data Vault by faj")

menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

# ------------------ Home Page ------------------

if choice == "Home":
    st.subheader("🏠 Home Page")
    st.markdown("""
    Welcome to the **Secure Multi-User Data Vault** app.  
    You can register, login, store encrypted data securely, and retrieve it anytime!
    """)

# ------------------ Register ------------------

elif choice == "Register":
    st.subheader("🧾 Register User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username in st.session_state.data:
            st.error("❌ Username already exists!")
        else:
            salt = "streamlit_salt"
            hashed_pass = hash_passkey(password, salt)
            st.session_state.data[username] = {
                "password": hashed_pass,
                "salt": salt,
                "data": []
            }
            save_data(st.session_state.data)
            st.success("✅ Registered successfully! Please login.")

# ------------------ Login ------------------

elif choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if is_locked_out(st.session_state.lockout, username):
        st.error("⛔ Locked out! Try again later.")
        st.stop()

    if st.button("Login"):
        user_data = st.session_state.data.get(username)
        if user_data:
            hashed_input = hash_passkey(password, user_data["salt"])
            if hashed_input == user_data["password"]:
                st.session_state.login_user = username
                st.session_state.attempts[username] = 0
                reset_lockout(st.session_state.lockout, username)
                st.success(f"✅ Welcome, {username}!")
            else:
                st.session_state.attempts[username] = st.session_state.attempts.get(username, 0) + 1
                attempts_left = 3 - st.session_state.attempts[username]
                st.error(f"❌ Incorrect password! Attempts left: {attempts_left}")
                if attempts_left <= 0:
                    st.session_state.lockout[username] = time.time()
        else:
            st.error("❌ User not found!")

# ------------------ Store Data ------------------

elif choice == "Store Data":
    if st.session_state.login_user:
        st.subheader("📥 Store Secure Data")
        entry_name = st.text_input("Enter Name for your data")
        data_input = st.text_area("Enter your secret data")
        passkey = st.text_input("Encryption Passkey", type="password")

        if st.button("Encrypt & Save"):
            if entry_name and data_input and passkey:
                encrypted = encrypt_data(data_input, passkey)
                st.session_state.data[st.session_state.login_user]["data"].append({
                    "name": entry_name,
                    "encrypted": encrypted
                })
                save_data(st.session_state.data)
                st.success("✅ Data encrypted and stored.")
            else:
                st.error("⚠️ All fields required.")
    else:
        st.warning("🔐 Please login to store data.")

# ------------------ Retrieve Data ------------------

elif choice == "Retrieve Data":
    if st.session_state.login_user:
        st.subheader("📤 Retrieve Your Data")
        user_data_list = st.session_state.data[st.session_state.login_user]["data"]

        if not user_data_list:
            st.info("ℹ️ No data found.")
        else:
            options = [
                item["name"] if isinstance(item, dict) and "name" in item else f"Entry {i+1}"
                for i, item in enumerate(user_data_list)
            ]
            selected = st.selectbox("Select Entry", options)
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                selected_entry = next(
                    (item for item in user_data_list if isinstance(item, dict) and item.get("name") == selected),
                    None
                )
                if not selected_entry:
                    selected_entry = user_data_list[options.index(selected)]

                encrypted_value = selected_entry["encrypted"] if isinstance(selected_entry, dict) else selected_entry
                decrypted = decrypt_data(encrypted_value, passkey)
                if decrypted:
                    st.success(f"✅ Decrypted Data: {decrypted}")
                else:
                    st.error("❌ Incorrect passkey.")
    else:
        st.warning("🔐 Please login to retrieve data.")
