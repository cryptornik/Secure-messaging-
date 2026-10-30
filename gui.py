
import base64
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox, simpledialog

from client.cli import (
    SERVER,
    api_request,
    fingerprint_from_private_keys,
    verify_trusted_fingerprint,
    save_trusted_fingerprint,
    load_trusted_fingerprints,
)
from client.crypto import (
    generate_identity,
    export_public_bundle,
    public_key_fingerprint,
    decrypt_message,
    encrypt_message,
)
from client.key_storage import load_private_keys, save_private_keys


DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class SecureChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat")
        self.root.geometry("800x550")
        self.root.minsize(650, 450)

        self.username = None
        self.token = None
        self.private_keys = None

        self.style = ttk.Style()
        self.style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"))

        self.show_login()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="SecureChat", style="Title.TLabel").pack(pady=10)
        ttk.Label(frame, text="Username").pack(anchor="w")
        self.username_entry = ttk.Entry(frame, width=35)
        self.username_entry.pack(pady=(4, 12))

        ttk.Label(frame, text="Password").pack(anchor="w")
        self.password_entry = ttk.Entry(frame, width=35, show="*")
        self.password_entry.pack(pady=(4, 18))

        ttk.Button(frame, text="Login", command=self.login).pack(fill="x", pady=4)
        ttk.Button(
            frame, text="Create an account", command=self.show_register
        ).pack(fill="x", pady=4)

    def show_register(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="Create Account", style="Title.TLabel").pack(pady=10)

        ttk.Label(frame, text="Username (3–32 letters, numbers or underscores)").pack(
            anchor="w"
        )
        self.register_username = ttk.Entry(frame, width=38)
        self.register_username.pack(pady=(4, 12))

        ttk.Label(frame, text="Password (at least 12 characters)").pack(anchor="w")
        self.register_password = ttk.Entry(frame, width=38, show="*")
        self.register_password.pack(pady=(4, 12))

        ttk.Label(frame, text="Confirm password").pack(anchor="w")
        self.register_confirm = ttk.Entry(frame, width=38, show="*")
        self.register_confirm.pack(pady=(4, 18))

        ttk.Button(frame, text="Register", command=self.register).pack(fill="x", pady=4)
        ttk.Button(frame, text="Back to login", command=self.show_login).pack(
            fill="x", pady=4
        )

    def register(self):
        username = self.register_username.get().strip().lower()
        password = self.register_password.get()
        confirmation = self.register_confirm.get()

        if password != confirmation:
            messagebox.showerror("Registration failed", "Passwords do not match.")
            return
        if len(password) < 12:
            messagebox.showerror(
                "Registration failed", "Password must be at least 12 characters."
            )
            return

        key_file = DATA_DIR / username / "private_keys.enc"
        if key_file.exists():
            messagebox.showerror(
                "Registration failed",
                "A local key file already exists for this username. "
                "Do not overwrite existing keys.",
            )
            return

        try:
            identity = generate_identity()
            public_bundle = export_public_bundle(identity)

            api_request(
                "POST",
                "/register",
                payload={
                    "username": username,
                    "password": password,
                    **public_bundle,
                },
            )

            save_private_keys(identity, password, str(key_file))
            fingerprint = fingerprint_from_private_keys(identity)

            messagebox.showinfo(
                "Registration successful",
                f"Account '{username}' created.\n\n"
                f"Your fingerprint:\n{fingerprint}\n\n"
                "Verify fingerprints through a trusted separate channel.",
            )
            self.show_login()

        except (RuntimeError, OSError, ValueError, KeyError) as exc:
            messagebox.showerror("Registration failed", str(exc))

    def login(self):
        username = self.username_entry.get().strip().lower()
        password = self.password_entry.get()
        token = None

        try:
            result = api_request(
                "POST",
                "/login",
                payload={"username": username, "password": password},
            )
            token = result["token"]

            key_file = DATA_DIR / username / "private_keys.enc"
            if not key_file.exists():
                raise RuntimeError(
                    "Local private-key file not found. "
                    "Do not generate replacement keys for an existing account."
                )

            private_keys = load_private_keys(str(key_file), password)

            self.username = username
            self.token = token
            self.private_keys = private_keys
            self.show_home()

        except (RuntimeError, OSError, ValueError, KeyError) as exc:
            if token:
                try:
                    api_request("POST", "/logout", token=token)
                except RuntimeError:
                    pass
            messagebox.showerror("Login failed", str(exc))

    
    def show_home(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill="both", expand=True)

        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 12))

        ttk.Label(
            header,
            text=f"SecureChat — {self.username}",
            style="Title.TLabel",
        ).pack(side="left")

        ttk.Button(
            header, text="Logout", command=self.logout
        ).pack(side="right")

        ttk.Label(frame, text="Recipient username").pack(anchor="w")
        self.recipient_entry = ttk.Entry(frame)
        self.recipient_entry.pack(fill="x", pady=(3, 10))

        ttk.Label(frame, text="Conversation / Inbox").pack(anchor="w")

        self.chat_display = tk.Text(
            frame, height=15, wrap="word", state="disabled"
        )
        self.chat_display.pack(fill="both", expand=True, pady=6)

        ttk.Label(frame, text="Message").pack(anchor="w")
        self.message_entry = ttk.Entry(frame)
        self.message_entry.pack(fill="x", pady=(3, 10))
        self.message_entry.bind(
            "<Return>", lambda event: self.send_chat_message()
        )

        actions = ttk.Frame(frame)
        actions.pack(fill="x")

        ttk.Button(
            actions, text="Send", command=self.send_chat_message
        ).pack(side="left")

        ttk.Button(
            actions, text="Refresh Inbox", command=self.refresh_inbox
        ).pack(side="left", padx=8)

        ttk.Button(
            actions,
            text="My Fingerprint",
            command=self.show_my_fingerprint,
        ).pack(side="right")

        self.append_chat("SecureChat is ready.")
        self.append_chat(
            "Verify contact fingerprints through a trusted separate channel."
        )

    def append_chat(self, text):
        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", text + "\n\n")
        self.chat_display.see("end")
        self.chat_display.configure(state="disabled")

    def show_my_fingerprint(self):
        fingerprint = fingerprint_from_private_keys(self.private_keys)
        messagebox.showinfo(
            "Your public-key fingerprint",
            f"{self.username}\n\n{fingerprint}\n\n"
            "Compare this fingerprint through a trusted separate channel.",
        )
    def get_contact_public_keys(self, contact):
        try:
            public_data = api_request(
                "GET",
                f"/users/{contact}/public-key",
                token=self.token,
            )

            encryption_public = base64.b64decode(
                public_data["encryption_public_key"], validate=True
            )
            signing_public = base64.b64decode(
                public_data["signing_public_key"], validate=True
            )

            fingerprint = public_key_fingerprint(
                encryption_public, signing_public
            )
            trust = verify_trusted_fingerprint(
                self.username, contact, fingerprint
            )

            if trust == "mismatch":
                messagebox.showerror(
                    "Fingerprint mismatch",
                    f"The saved fingerprint for {contact} has changed. "
                    "Do not send or accept messages from this contact.",
                )
                return None

            if trust == "unknown":
                confirmed = messagebox.askyesno(
                    "Verify contact fingerprint",
                    f"Contact: {contact}\n\n"
                    f"Fingerprint:\n{fingerprint}\n\n"
                    "Have you verified this fingerprint through a "
                    "trusted separate channel?",
                )

                if not confirmed:
                    return None

                save_trusted_fingerprint(
                    self.username, contact, fingerprint
                )

            return encryption_public, signing_public

        except Exception as error:
            messagebox.showerror(
                "Contact error", str(error)
            )
            return None

    def send_chat_message(self):
        recipient = self.recipient_entry.get().strip()
        plaintext = self.message_entry.get().strip()

        if not recipient or not plaintext:
            messagebox.showwarning(
                "Missing information",
                "Enter a recipient and a message.",
            )
            return

        if recipient == self.username:
            messagebox.showwarning(
                "Invalid recipient",
                "You cannot send a message to yourself.",
            )
            return

        try:
            public_keys = self.get_contact_public_keys(recipient)
            if public_keys is None:
                return

            recipient_encryption_public, _ = public_keys

            envelope = encrypt_message(
                plaintext=plaintext,
                recipient_encryption_public=recipient_encryption_public,
                sender_signing_private=self.private_keys[
                    "signing_private"
                ],
                sender_username=self.username,
                recipient_username=recipient,
            )

            api_request(
                "POST",
                "/messages",
                token=self.token,
                payload={
                    "recipient": recipient,
                    "envelope": envelope,
                },
            )

            self.append_chat(f"You → {recipient}: {plaintext}")
            self.message_entry.delete(0, "end")

        except Exception as error:
            messagebox.showerror("Send failed", str(error))

    def refresh_inbox(self):
        try:
            result = api_request(
                "GET", "/messages", token=self.token
            )

            messages = result.get("messages", [])
            if not messages:
                self.append_chat("Inbox refreshed. No new messages.")
                return

            received = 0

            for message in messages:
                sender = message["sender"]

                public_keys = self.get_contact_public_keys(sender)
                if public_keys is None:
                    continue

                _, sender_signing_public = public_keys

                plaintext = decrypt_message(
                    envelope=message["envelope"],
                    recipient_encryption_private=self.private_keys[
                        "encryption_private"
                    ],
                    sender_signing_public=sender_signing_public,
                    expected_sender=sender,
                    expected_recipient=self.username,
                )

                api_request(
                    "POST",
                    f"/messages/{message['id']}/ack",
                    token=self.token,
                )

                self.append_chat(f"{sender} → You: {plaintext}")
                received += 1

            if received:
                self.append_chat(
                    f"Inbox refreshed. Received {received} message(s)."
                )

        except Exception as error:
            messagebox.showerror(
                "Inbox error",
                str(error),
            )

    

    def logout(self):
        try:
            api_request("POST", "/logout", token=self.token)
        except RuntimeError as exc:
            messagebox.showwarning("Logout", f"Server logout failed: {exc}")
        finally:
            self.username = None
            self.token = None
            self.private_keys = None
            self.show_login()


def main():
    root = tk.Tk()
    SecureChatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
