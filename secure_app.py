
import streamlit as st
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import base64

# In-memory data and session tracking
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Utility functions
def generate_key(passkey: str, salt: bytes = b"static_salt"):
    """Generate a Fernet key from a passkey using PBKDF2."""
    key = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_data(data: str, key: bytes):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, key: bytes):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

# Pages
def home_page():
    st.title("🔐 Secure Data Storage System")
    choice = st.selectbox("Choose an action", ["Store New Data", "Retrieve Data"])
    if choice == "Store New Data":
        insert_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()

def insert_data_page():
    st.header("📥 Insert Data")
    key = st.text_input("Enter your passkey", type="password")
    text = st.text_area("Enter text to store")
    user_id = st.text_input("Enter a unique ID to store your data (e.g. username)")

    if st.button("Store"):
        if not user_id or not key or not text:
            st.warning("Please fill all fields.")
            return
        fernet_key = generate_key(key)
        encrypted_text = encrypt_data(text, fernet_key)
        st.session_state.stored_data[user_id] = {
            "encrypted_text": encrypted_text
        }
        st.success(f"Data stored successfully under ID: {user_id}")

def retrieve_data_page():
    st.header("🔍 Retrieve Data")

    if not st.session_state.authorized:
        login_page()
        return

    user_id = st.text_input("Enter your user ID")
    key = st.text_input("Enter your passkey", type="password")

    if st.button("Retrieve"):
        if user_id not in st.session_state.stored_data:
            st.error("No data found for this ID.")
            return

        fernet_key = generate_key(key)
        try:
            encrypted = st.session_state.stored_data[user_id]["encrypted_text"]
            decrypted = decrypt_data(encrypted, fernet_key)
            st.success("✅ Data decrypted successfully:")
            st.code(decrypted)
            st.session_state.failed_attempts = 0  # Reset on success
        except Exception:
            st.session_state.failed_attempts += 1
            st.error(f"❌ Decryption failed. Attempt {st.session_state.failed_attempts}/3")
            if st.session_state.failed_attempts >= 3:
                st.session_state.authorized = False
                st.warning("⚠️ Too many failed attempts. Redirecting to login page...")

def login_page():
    st.title("🔐 Login Required")
    user = st.text_input("Enter your username")
    password = st.text_input("Enter password", type="password")
    if st.button("Login"):
        if user == "admin" and password == "admin123":  # Simplified login
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
            st.success("Reauthorized! You can now retry.")
        else:
            st.error("Invalid credentials.")

# Main routing
def main():
    if st.session_state.authorized:
        home_page()
    else:
        login_page()

if __name__ == "__main__":
    main()


