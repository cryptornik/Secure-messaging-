
from pathlib import Path
from flask import Flask, request, jsonify
from auth import register_user, authenticate_user
from database import init_db

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    success, message = register_user(username, password)

    return jsonify({"message": message}), (201 if success else 400)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    success, message = authenticate_user(username, password)

    return jsonify({"message": message}), (200 if success else 401)


if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
