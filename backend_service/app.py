"""
JWT: JSON Web Tokens

This python code implements an authentication wrapper using JWT

Questions: 
1. Identify potential security issues in JWT and database interactions.
2. Describe all attack scenarios in as much detail as possible using the security issues reported.
3. Provide fixes for all the identified issues.

How: 
Research on common SQL and JWT issues and bypasses.
"""

from flask import Flask, request, make_response, jsonify
import jwt
import pickle
from http import HTTPStatus
import sqlite3
import logging
import os
from utils.db_utils import DatabaseUtils
from utils.file_storage import FileStorage
from werkzeug.security import generate_password_hash
from datetime import timedelta
import datetime

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename='app.log',
                    filemode='a')

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout
app.config['WTF_CSRF_ENABLED'] = False

# Removed the hardcoded secret with a random secure key
SECRET_KEY = os.urandom(17)

logging.basicConfig(level=logging.INFO)
db = DatabaseUtils()
fs = FileStorage()

def _init_app():
    db.update_data("DROP TABLE IF EXISTS users;", [])
    db.update_data('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            password TEXT NOT NULL,
                            privilege INTEGER
                        );''', [])

    # Encrypt the password before storing
    admin_password = generate_password_hash('password1')
    user_password = generate_password_hash('adminpassword1')

    db.update_data(f"INSERT INTO users (username, password, privilege) VALUES (?,?,?)", ['user1', user_password, 0])
    db.update_data(f"INSERT INTO users (username, password, privilege) VALUES (?,?,?)", ['admin1', admin_password,1])

def get_token_expiry_time():
    return datetime.datetime.utcnow() + datetime.timedelta(minutes=20)

def _check_login():
    auth_token = request.cookies.get('token', None)
    if not auth_token:
        app.logger.error("Missing token cookie")
        return jsonify({'error': "Missing token cookie"}), HTTPStatus.UNAUTHORIZED
    try:
        # Decode JWT token
        data = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
        if isinstance(data, dict):
            return data
        else:
            app.logger.error("Invalid token structure")
            return jsonify({'error': "Invalid token structure"}), HTTPStatus.UNAUTHORIZED
    except jwt.DecodeError:
        app.logger.error("Token is invalid")
        return jsonify({'error': "Token is invalid"}), HTTPStatus.UNAUTHORIZED


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    hashed_password = generate_password_hash(password)
    # use hashed password and username to check if the user exists.
    rows = db.fetch_data(f"SELECT * FROM users where username= ? AND password= ?", [username, hashed_password])

    if len(rows) != 1:
        app.logger.error("Invalid credentials")
        return jsonify({'error': "Invalid credentials"}), HTTPStatus.UNAUTHORIZED

    is_user_admin = True if rows[0][-1] == 1 else False
    expiry_time = get_token_expiry_time()
    token = jwt.encode({ 
        "username": username ,
        "is_admin": is_user_admin,
        "expiry": expiry_time
    }, SECRET_KEY, algorithm="HS256")

    # We are only setting 1 http cookie which will have information along with the expiration time
    res = make_response()
    res.set_cookie("token", value=token, expires=expiry_time, httponly=True, secure=True, samesite="strict",)

    return res


@app.route("/file", methods=["GET", "POST", "DELETE"])
def store_file():
    """
    Only admins can upload/delete files.
    All users can read files.
    """
    # We are handling the scenario if user is not logged it. Not raising the error from _check_login function.
    data = _check_login()
    ## User is not logged in
    ## NEED TO TEST THIS OUT, this method will change
    if isinstance(data, jsonify):
        app.logger.error("Failed to authenticate user")
        return jsonify({'error': "Failed to authenticate user"}), HTTPStatus.UNAUTHORIZED

    is_admin = data["is_admin"]
    expiry_time = data["expiry"]
    if expiry_time < datetime.datetime.utcnow():
        app.logger.error("Authentication token has expired, login again")
        return jsonify({'error': "Authentication token has expired, login again"}), HTTPStatus.UNAUTHORIZED

    if request.method == 'GET':
        filename = request.args.get('filename')
        return fs.get(filename)
    elif request.method == 'POST':
        if not is_admin:
            app.logger.error("Need admin access")
            return jsonify({'error': "Need admin access"}), HTTPStatus.UNAUTHORIZED

        uploaded_files = request.files
        for f in uploaded_files:
            fs.store(uploaded_files[f].name, uploaded_files[f].read())
        app.logger.info("Files uploaded successfully")
        return jsonify({'info': "Files uploaded successfully"}), HTTPStatus.OK
    elif request.method == 'DELETE':
        if not is_admin:
            app.logger.error("Need admin access")
            return jsonify({'error': "Need admin access"}), HTTPStatus.UNAUTHORIZED

        filename = request.args.get('filename')
        fs.delete(filename)
        app.logger.info(f"{filename} deleted successfully")
        return jsonify({'info': f"{filename} deleted successfully"}), HTTPStatus.OK
    else:
        app.logger.error("Method not implemented")
        return jsonify({'error': "Method not implemented"}), HTTPStatus.BAD_REQUEST


if __name__ == "__main__":
    _init_app()
    app.run(host='0.0.0.0', debug=True, port=9090)