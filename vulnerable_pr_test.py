import os
import sqlite3
import hashlib

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    os.system(f"echo {user_input}")

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

API_SECRET = "sk-live-test-123456"
