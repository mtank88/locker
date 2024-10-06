import streamlit as st
import os
from werkzeug.security import generate_password_hash, check_password_hash

# User storage file
USER_STORAGE_FILE = "users.txt"

# Function to read users from the file
def read_users():
    users = {}
    if os.path.exists(USER_STORAGE_FILE):
        with open(USER_STORAGE_FILE, "r") as f:
            for line in f:
                email, password_hash = line.strip().split(",")
                users[email] = password_hash
    return users

# Function to write a new user to the file
def write_user(email, password):
    with open(USER_STORAGE_FILE, "a") as f:
        f.write(f"{email},{generate_password_hash(password)}\n")

# Function to register a user
def register_user(email, password):
    users = read_users()
    if email in users:
        return False  # User already exists
    write_user(email, password)
    return True

# Function to authenticate a user
def authenticate_user(email, password):
    users = read_users()
    if email in users and check_password_hash(users[email], password):
        return True
    return False

# Function to upload a file
def upload_file(file):
    if file is not None:
        with open(os.path.join("uploads", file.name), "wb") as f:
            f.write(file.getbuffer())
        return True
    return False

# Function to list uploaded files
def list_uploaded_files():
    return os.listdir("uploads")

# Streamlit App
st.title("DocuVault")

# Sidebar for authentication
st.sidebar.header("Authentication")
auth_choice = st.sidebar.selectbox("Choose an action", ["Login", "Register"])

if auth_choice == "Register":
    st.sidebar.subheader("Register")
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Register"):
        if register_user(email, password):
            st.sidebar.success("Registration successful!")
        else:
            st.sidebar.error("User already exists!")

elif auth_choice == "Login":
    st.sidebar.subheader("Login")
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Login"):
        if authenticate_user(email, password):
            st.sidebar.success("Login successful!")
            st.session_state['logged_in'] = True
        else:
            st.sidebar.error("Invalid email or password!")

# Main content
if 'logged_in' in st.session_state and st.session_state['logged_in']:
    st.header("Upload Document")

    uploaded_file = st.file_uploader("Choose a file", type=["pdf", "docx", "txt", "jpg", "jpeg", "png", "gif", "mp4", "avi", "mov"])

    if st.button("Upload"):
        if upload_file(uploaded_file):
            st.success("File uploaded successfully!")
        else:
            st.error("Failed to upload file.")

    # List uploaded files
    st.header("Uploaded Files")
    uploaded_files = list_uploaded_files()

    if uploaded_files:
        selected_file = st.selectbox("Select a file to download", uploaded_files)
        file_path = os.path.join("uploads", selected_file)
        with open(file_path, "rb") as f:
            st.download_button(
                label=f"Download {selected_file}",
                data=f,
                file_name=selected_file,
                mime="application/octet-stream"
            )
    else:
        st.info("No files uploaded yet.")

    # Logout button
    if st.button("Logout"):
        st.session_state['logged_in'] = False
        st.sidebar.success("Logout successful!")

else:
    st.info("Please log in to upload or download documents.")
