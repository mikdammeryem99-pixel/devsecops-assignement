from flask import Flask, request
import sqlite3
import bcrypt
import os
import logging
import subprocess

app = Flask(__name__)

# Secret via environment variable
API_KEY = os.getenv("API_KEY", "default_key")

logging.basicConfig(level=logging.INFO)

@app.route("/auth", methods=["POST"])
def auth():
    data = request.json
    username = data.get("username")
    password = data.get("password", "").encode()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()

    if row and bcrypt.checkpw(password, row[0]):
        return {"status": "authenticated"}

    return {"status": "denied"}, 401


@app.route("/exec", methods=["POST"])
def exec_cmd():
    return {"error": "command execution disabled"}, 403


@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.json.get("text", "").encode()
    hashed = bcrypt.hashpw(text, bcrypt.gensalt())
    return {"hash": hashed.decode()}


@app.route("/file", methods=["POST"])
def read_file():
    return {"error": "file access disabled"}, 403


@app.route("/debug", methods=["GET"])
def debug():
    return {"status": "debug disabled"}, 403


@app.route("/log", methods=["POST"])
def log_data():
    logging.info("Log received")
    return {"status": "logged"}


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Secure DevSecOps API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
