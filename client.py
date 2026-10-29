
import getpass
import json
import urllib.error
import urllib.request

SERVER_URL = "http://127.0.0.1:5000"


def post_json(path, payload):
    body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        SERVER_URL + path,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as error:
        try:
            return json.loads(error.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {"message": "Server returned an error."}

    except (urllib.error.URLError, TimeoutError):
        return {
            "message": "Cannot connect to server. "
                       "Make sure relay_server.py is running."
        }


def register():
    print("\n--- Register ---")

    username = input("Choose a username: ").strip()
    password = getpass.getpass("Choose a password (12+ characters): ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    result = post_json(
        "/register",
        {"username": username, "password": password}
    )

    print(result.get("message", "Registration failed."))


def login():
    print("\n--- Login ---")

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    result = post_json(
        "/login",
        {"username": username, "password": password}
    )

    print(result.get("message", "Login failed."))


def main():
    while True:
        print("\n=== SecureChat ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid option. Enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
