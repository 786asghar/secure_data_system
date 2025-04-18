import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import json
import os
from hashlib import pbkdf2_hmac

# Initialize session state for persistent storage and tracking
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
    if os.path.exists('data.json'):
        try:
            with open('data.json', 'r') as f:
                st.session_state.stored_data = json.load(f)
        except json.JSONDecodeError:
            st.warning("⚠️ Failed to load data.json. Starting with empty storage.")
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"

# Load or generate Fernet key (persisted across sessions)
KEY_FILE = 'key.key'
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(KEY)
cipher = Fernet(KEY)

# Function to hash passkey using PBKDF2
def hash_passkey(passkey: str) -> str:
    return pbkdf2_hmac('sha256', passkey.encode(), b'salt', 100000).hex()

# Function to encrypt data
def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text: str, passkey: str) -> str:
    hashed_passkey = hash_passkey(passkey)
    
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            try:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
            except InvalidToken:
                st.session_state.failed_attempts += 1
                return None
    
    st.session_state.failed_attempts += 1
    return None

# Function to save data to JSON file
def save_to_json():
    with open('data.json', 'w') as f:
        json.dump(st.session_state.stored_data, f)

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Sidebar navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))

# Home Page
if choice == "Home":
    st.session_state.current_page = "Home"
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.info("Navigate using the sidebar to store or retrieve data.")

# Store Data Page
elif choice == "Store Data":
    st.session_state.current_page = "Store Data"
    st.subheader("📂 Store Data Securely")
    
    user_data = st.text_area("Enter Data to Encrypt:", height=100)
    passkey = st.text_input("Enter Passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_to_json()
            st.success("✅ Data stored securely!")
            st.write("Save this encrypted text to retrieve your data later:")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Please fill in both data and passkey fields!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3:
        st.session_state.current_page = "Login"
        st.rerun()  # Replaced experimental_rerun
    
    st.session_state.current_page = "Retrieve Data"
    st.subheader("🔍 Retrieve Your Data")
    
    encrypted_text = st.text_area("Enter Encrypted Data:", height=100)
    passkey = st.text_input("Enter Passkey:", type="password")
    
    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey or invalid encrypted data! Attempts remaining: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page...")
                    st.session_state.current_page = "Login"
                    st.rerun()  # Replaced experimental_rerun
        else:
            st.error("⚠️ Please fill in both encrypted data and passkey fields!")
    
    st.write(f"Failed attempts: {st.session_state.failed_attempts}/3")

# Login Page
elif choice == "Login":
    st.session_state.current_page = "Login"
    st.subheader("🔑 Reauthorization Required")
    
    login_pass = st.text_input("Enter Master Password:", type="password")
    
    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.current_page = "Retrieve Data"
            st.rerun()  # Replaced experimental_rerun
        else:
            st.error("❌ Incorrect master password!")

# Footer
st.markdown("---")
st.write("Built with Streamlit and Python 🐍 | Secure Data System v1.0")