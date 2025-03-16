"""
This file contains intentional vulnerabilities for testing CodeGuardian.
DO NOT USE THIS CODE IN PRODUCTION!
"""

import os
import subprocess
import sqlite3
import pickle
import yaml
import random
import hashlib

# Hardcoded credentials (vulnerability)
DB_USERNAME = "admin"
DB_PASSWORD = "super_secret_password123"
API_KEY = "1234567890abcdef"

def connect_to_database(user_input):
    """Connect to a database with user input."""
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(query)  # Vulnerable to SQL injection
    return cursor.fetchall()

def run_command(command):
    """Run a system command."""
    # Command injection vulnerability
    os.system("ls " + command)  # Vulnerable to command injection
    
    # Another command injection vulnerability
    subprocess.call("echo " + command, shell=True)  # Vulnerable to command injection

def load_config(config_file):
    """Load a YAML configuration file."""
    # YAML deserialization vulnerability
    with open(config_file, 'r') as f:
        return yaml.load(f)  # Vulnerable to YAML deserialization attacks

def load_object(filename):
    """Load a pickled object from a file."""
    # Pickle deserialization vulnerability
    with open(filename, 'rb') as f:
        return pickle.load(f)  # Vulnerable to pickle deserialization attacks

def generate_token():
    """Generate a random token."""
    # Insecure randomness
    return random.randint(10000, 99999)  # Not cryptographically secure

def hash_password(password):
    """Hash a password."""
    # Weak hash algorithm
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is cryptographically weak

def execute_code(code_string):
    """Execute a string as code."""
    # Code execution vulnerability
    exec(code_string)  # Vulnerable to code execution attacks

def read_file(filename):
    """Read a file."""
    # Path traversal vulnerability
    with open("data/" + filename, 'r') as f:  # Vulnerable to path traversal
        return f.read()

def debug_mode():
    """Set debug mode."""
    # Debug mode enabled in production
    DEBUG = True  # Should not be enabled in production
    return DEBUG

def main():
    """Main function."""
    print("Running vulnerable code...")
    
    # Call vulnerable functions
    connect_to_database("user' OR '1'='1")
    run_command("-la; cat /etc/passwd")
    
    try:
        load_config("config.yml")
    except:
        pass
    
    try:
        load_object("data.pickle")
    except:
        pass
    
    token = generate_token()
    print(f"Generated token: {token}")
    
    password_hash = hash_password("password123")
    print(f"Password hash: {password_hash}")
    
    try:
        execute_code("print('Executing arbitrary code')")
    except:
        pass
    
    try:
        read_file("../../../etc/passwd")
    except:
        pass
    
    debug_enabled = debug_mode()
    print(f"Debug mode: {debug_enabled}")

if __name__ == "__main__":
    main() 