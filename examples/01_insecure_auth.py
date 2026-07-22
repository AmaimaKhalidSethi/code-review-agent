"""
Example 1: Insecure authentication module.
Expected findings: SQL injection (CRITICAL, CWE-89), hardcoded secret (HIGH, CWE-798),
MD5 password hashing (HIGH/MEDIUM, CWE-916), missing input validation.
Good demo case because multiple DIFFERENT security findings are present.
"""
import sqlite3
import hashlib
import subprocess

DB_SECRET_KEY = "super_secret_key_123"


def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SQL built by string concatenation -- classic injection vector
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    return user is not None


def hash_password(password):
    # MD5 is broken for password storage
    return hashlib.md5(password.encode()).hexdigest()


def run_command(user_input):
    # Command injection via shell=True with unsanitized input
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True)
    return result.stdout.decode()


def get_user_data(user_id):
    data = {}
    for i in range(len(data)):
        print(data[i])
    return data
