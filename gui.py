import base64
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox

from client.cli import (
    SERVER, api_request, fingerprint_from_private_keys,
    verify_trusted_fingerprint, save_trusted_fingerprint,
)
from client.crypto import (
    generate_identity, export_public_bundle, public_key_fingerprint,
    decrypt_message, encrypt_message,
)
from client.key_storage import load_private_keys, save_private_keys

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
BG = "#0B1220"
PANEL = "#121D33"
SIDEBAR = "#14213A"
INPUT = "#1E304E"
TEXT = "#F2F6FF"
MUTED = "#9EB1CF"
ACCENT = "#3B82F6"
ACCENT_HOVER = "#60A5FA"
OUTGOING = "#155BE6"
INCOMING = "#243B66"
BORDER = "#304769"
SUCCESS = "#7DD3FC"


class SecureChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat • Secure Messaging")
        self.root.geometry("1080x710")
        self.root.minsize(800, 540)
        self.root.configure(bg=BG)
        self.username = None
        self.token = None
        self.private_keys = None
        self.active_contact = None
        self.conversations = {}  # Session-only UI messages; not server history
        self.contact_buttons = {}
        self.show_login()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def label(self, parent, text, size=11, color=TEXT, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), **kwargs)

    def entry(self, parent, show=None):
        return tk.Entry(parent, bg=INPUT, fg=TEXT, insertbackground=TEXT,
                        relief="flat", highlightthickness=1,
                        highlightbackground=BORDER, highlightcolor=ACCENT,
                        font=("Segoe UI", 11), show=show, bd=10)

    def button(self, parent, text, command, primary=False, **kwargs):
        return tk.Button(parent, text=text, command=command, relief="flat", bd=0,
                         bg=ACCENT if primary else INPUT, fg="#FFFFFF" if primary else TEXT,
                         activebackground=ACCENT_HOVER if primary else BORDER,
                         activeforeground="#FFFFFF", cursor="hand2",
                         font=("Segoe UI", 10, "bold"), padx=13, pady=9, **kwargs)

    def avatar(self, parent, name, size=38):
        canvas = tk.Canvas(parent, width=size, height=size, bg=parent.cget("bg"),
                           highlightthickness=0, bd=0)
        canvas.create_oval(1, 1, size-1, size-1, fill="#31558C", outline="")
        canvas.create_text(size/2, size/2, text=(name[:1] or "?").upper(),
                           fill="#FFFFFF", font=("Segoe UI", max(10, size//3), "bold"))
        return canvas

    def auth_card(self, title):
        self.clear_window()
        outer = tk.Frame(self.root, bg=PANEL, padx=36, pady=34,
                         highlightbackground=BORDER, highlightthickness=1)
        outer.place(relx=0.5, rely=0.5, anchor="center", width=445)
        self.label(outer, "SecureChat", 23, ACCENT_HOVER, True).pack(anchor="center")
        self.label(outer, title, 24, TEXT, True).pack(anchor="w", pady=(15, 25))
        return outer

    def show_login(self):
        card = self.auth_card("Welcome back")
        self.label(card, "Username", 10, MUTED).pack(anchor="w")
        self.username_entry = self.entry(card)
        self.username_entry.pack(fill="x", pady=(6, 17))
        self.label(card, "Password", 10, MUTED).pack(anchor="w")
        self.password_entry = self.entry(card, show="*")
        self.password_entry.pack(fill="x", pady=(6, 23))
        self.password_entry.bind("<Return>", lambda _e: self.login())
        self.button(card, "Log in", self.login, primary=True).pack(fill="x", pady=(0, 10))
        self.button(card, "Create an account", self.show_register).pack(fill="x")
        self.username_entry.focus_set()

    def show_register(self):
        card = self.auth_card("Create account")
        self.label(card, "Username (3–32 letters, numbers or underscores)", 9, MUTED).pack(anchor="w")
        self.register_username = self.entry(card)
        self.register_username.pack(fill="x", pady=(5, 13))
        self.label(card, "Password (at least 12 characters)", 10, MUTED).pack(anchor="w")
        self.register_password = self.entry(card, show="*")
        self.register_password.pack(fill="x", pady=(5, 13))
        self.label(card, "Confirm password", 10, MUTED).pack(anchor="w")
        self.register_confirm = self.entry(card, show="*")
        self.register_confirm.pack(fill="x", pady=(5, 20))
        self.button(card, "Register", self.register, primary=True).pack(fill="x", pady=(0, 10))
        self.button(card, "Back to login", self.show_login).pack(fill="x")

    def register(self):
        username = self.register_username.get().strip().lower()
        password = self.register_password.get()
        confirmation = self.register_confirm.get()
        if not username:
            messagebox.showerror("Registration failed", "Username cannot be empty.")
            return
        if password != confirmation:
            messagebox.showerror("Registration failed", "Passwords do not match.")
            return
        if len(password) < 12:
            messagebox.showerror("Registration failed", "Password must be at least 12 characters.")
            return
        key_file = DATA_DIR / username / "private_keys.enc"
        if key_file.exists():
            messagebox.showerror("Registration failed", "A local key file already exists for this username. Do not overwrite existing keys.")
            return
        try:
            identity = generate_identity()
            public_bundle = export_public_bundle(identity)
            api_request("POST", "/register", payload={"username": username, "password": password, **public_bundle})
            save_private_keys(identity, password, str(key_file))
            fingerprint = fingerprint_from_private_keys(identity)
            messagebox.showinfo("Registration successful", f"Account '{username}' created.\n\nYour fingerprint:\n{fingerprint}\n\nVerify fingerprints through a trusted separate channel.")
            self.show_login()
        except (RuntimeError, OSError, ValueError, KeyError) as exc:
            messagebox.showerror("Registration failed", str(exc))

    def login(self):
        username = self.username_entry.get().strip().lower()
        password = self.password_entry.get()
        token = None
        try:
            result = api_request("POST", "/login", payload={"username": username, "password": password})
            token = result["token"]
            key_file = DATA_DIR / username / "private_keys.enc"
            if not key_file.exists():
                raise RuntimeError("Local private-key file not found. Do not generate replacement keys for an existing account.")
            private_keys = load_private_keys(str(key_file), password)
            self.username = username
            self.token = token
            self.private_keys = private_keys
            self.active_contact = None
            self.conversations = {}
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
        top = tk.Frame(self.root, bg=PANEL, padx=20, pady=13)
        top.pack(fill="x")
        self.label(top, "SecureChat", 17, TEXT, True).pack(side="left")
        self.button(top, "Logout", self.logout).pack(side="right")
        self.button(top, "Security details", self.show_security_details).pack(side="right", padx=(0, 10))

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True)
        sidebar = tk.Frame(body, bg=SIDEBAR, width=270, padx=13, pady=16)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self.label(sidebar, "CHATS", 10, MUTED, True).pack(anchor="w", pady=(0, 11))
        self.contact_entry = self.entry(sidebar)
        self.contact_entry.pack(fill="x", pady=(0, 8))
        self.contact_entry.bind("<Return>", lambda _e: self.open_contact_from_entry())
        self.button(sidebar, "+ Open chat", self.open_contact_from_entry, primary=True).pack(fill="x", pady=(0, 14))
        self.contact_list = tk.Frame(sidebar, bg=SIDEBAR)
        self.contact_list.pack(fill="both", expand=True)
        self.label(sidebar, f"Signed in as {self.username}", 9, MUTED).pack(anchor="w", pady=(12, 0))

        main = tk.Frame(body, bg=BG)
        main.pack(side="left", fill="both", expand=True)
        chat_header = tk.Frame(main, bg=PANEL, padx=17, pady=10)
        chat_header.pack(fill="x")
        self.chat_avatar_holder = tk.Frame(chat_header, bg=PANEL)
        self.chat_avatar_holder.pack(side="left", padx=(0, 10))
        self.chat_header_text = self.label(chat_header, "Choose a conversation", 13, TEXT, True)
        self.chat_header_text.pack(side="left")
        self.button(chat_header, "Refresh inbox", self.refresh_inbox).pack(side="right")

        chat_shell = tk.Frame(main, bg=BG)
        chat_shell.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(chat_shell, bg=BG, highlightthickness=0, bd=0)
        scrollbar = tk.Scrollbar(chat_shell, orient="vertical", command=self.canvas.yview,
                                 bg=PANEL, troughcolor=BG, activebackground=ACCENT)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.message_container = tk.Frame(self.canvas, bg=BG)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.message_container, anchor="nw")
        self.message_container.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self.resize_chat)

        composer = tk.Frame(main, bg=PANEL, padx=16, pady=13)
        composer.pack(fill="x")
        self.message_entry = self.entry(composer)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.message_entry.bind("<Return>", lambda _e: self.send_chat_message())
        self.button(composer, "Send  ➤", self.send_chat_message, primary=True).pack(side="right")
        self.render_conversation()

    def resize_chat(self, event):
        self.canvas.itemconfigure(self.canvas_window, width=event.width)
        self.render_conversation()

    def open_contact_from_entry(self):
        contact = self.contact_entry.get().strip().lower()
        if not contact:
            messagebox.showwarning("Contact", "Enter a contact username.")
            return
        if contact == self.username:
            messagebox.showwarning("Contact", "You cannot chat with yourself.")
            return
        self.select_contact(contact)
        self.contact_entry.delete(0, "end")

    def select_contact(self, contact):
        if contact not in self.conversations:
            self.conversations[contact] = []
        self.active_contact = contact
        self.update_contacts()
        for child in self.chat_avatar_holder.winfo_children():
            child.destroy()
        self.avatar(self.chat_avatar_holder, contact, 35).pack()
        self.chat_header_text.configure(text=contact.capitalize())
        self.render_conversation()
        self.message_entry.focus_set()

    def update_contacts(self):
        for child in self.contact_list.winfo_children():
            child.destroy()
        for contact in self.conversations:
            selected = contact == self.active_contact
            color = "#24477D" if selected else SIDEBAR
            item = tk.Frame(self.contact_list, bg=color, padx=9, pady=8, cursor="hand2")
            item.pack(fill="x", pady=2)
            av = self.avatar(item, contact, 34)
            av.pack(side="left", padx=(0, 10))
            name = tk.Label(item, text=contact.capitalize(), bg=color, fg=TEXT,
                            font=("Segoe UI", 11, "bold"), anchor="w")
            name.pack(side="left", fill="x", expand=True)
            for widget in (item, av, name):
                widget.bind("<Button-1>", lambda _e, c=contact: self.select_contact(c))

    def scroll_to_bottom(self):
        self.root.update_idletasks()
        self.canvas.yview_moveto(1.0)

    def append_chat(self, text):
        # Informational notices are deliberately not stored as chat messages.
        self.status_message = text
        self.render_conversation()

    def append_message(self, sender, text, outgoing=False):
        contact = self.active_contact if outgoing else sender.strip().lower()
        if not contact:
            return
        self.conversations.setdefault(contact, []).append({
            "sender": self.username if outgoing else sender,
            "text": text,
            "outgoing": outgoing,
            "time": datetime.now().strftime("%I:%M %p").lstrip("0"),
        })
        self.update_contacts()
        if self.active_contact == contact:
            self.render_conversation()

    def render_conversation(self):
        if not hasattr(self, "message_container") or not self.message_container.winfo_exists():
            return
        for child in self.message_container.winfo_children():
            child.destroy()
        if not self.active_contact:
            self.label(self.message_container, "Select a contact or open a new chat", 12, MUTED).pack(pady=65)
            return
        messages = self.conversations.get(self.active_contact, [])
        if not messages:
            self.label(self.message_container, "No messages in this session yet", 11, MUTED).pack(pady=55)
        for item in messages:
            outgoing = item["outgoing"]
            color = OUTGOING if outgoing else INCOMING
            row = tk.Frame(self.message_container, bg=BG, pady=6)
            row.pack(fill="x", padx=18)
            bubble = tk.Frame(row, bg=color, padx=14, pady=10)
            bubble.pack(side="right" if outgoing else "left")
            tk.Label(bubble, text=item["sender"].capitalize(), bg=color,
                     fg="#DBEAFE" if outgoing else "#93C5FD",
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(anchor="w", pady=(0, 4))
            wrap = max(200, min(460, self.canvas.winfo_width() - 115))
            tk.Label(bubble, text=item["text"], bg=color, fg=TEXT,
                     font=("Segoe UI", 11), justify="left", anchor="w",
                     wraplength=wrap).pack(anchor="w")
            tk.Label(bubble, text=item["time"], bg=color, fg="#C7D9F5",
                     font=("Segoe UI", 8)).pack(anchor="e", pady=(5, 0))
        self.root.after_idle(self.scroll_to_bottom)

    def show_my_fingerprint(self):
        fingerprint = fingerprint_from_private_keys(self.private_keys)
        messagebox.showinfo("Your public-key fingerprint", f"{self.username}\n\n{fingerprint}\n\nCompare this fingerprint through a trusted separate channel.")

    def show_security_details(self):
        if not self.private_keys:
            return
        win = tk.Toplevel(self.root)
        win.title("SecureChat • Security details")
        win.geometry("570x445")
        win.minsize(490, 390)
        win.configure(bg=BG)
        win.transient(self.root)
        panel = tk.Frame(win, bg=PANEL, padx=24, pady=22)
        panel.pack(fill="both", expand=True, padx=16, pady=16)
        self.label(panel, "Security details", 19, TEXT, True).pack(anchor="w", pady=(0, 16))
        self.label(panel, "Signed-in user", 9, MUTED).pack(anchor="w")
        self.label(panel, self.username, 12, TEXT, True).pack(anchor="w", pady=(3, 12))
        self.label(panel, "Your public-key fingerprint", 9, MUTED).pack(anchor="w")
        fingerprint = fingerprint_from_private_keys(self.private_keys)
        self.label(panel, fingerprint, 10, TEXT, wraplength=480, justify="left").pack(anchor="w", pady=(3, 14))
        self.label(panel, "Message cryptography", 9, MUTED).pack(anchor="w")
        self.label(panel, "X25519 • HKDF-SHA256 • AES-256-GCM • Ed25519", 10, TEXT).pack(anchor="w", pady=(4, 12))
        self.label(panel, "Contact fingerprint", 9, MUTED).pack(anchor="w")
        if self.active_contact:
            self.label(panel, f"Contact: {self.active_contact}", 10, TEXT).pack(anchor="w", pady=(4, 6))
            self.button(panel, "Check contact key and fingerprint", self.check_active_contact).pack(anchor="w")
        else:
            self.label(panel, "Select a conversation to inspect its contact key.", 10, TEXT).pack(anchor="w", pady=(4, 8))
        self.label(panel, "Verify fingerprints using a separate trusted channel.", 9, MUTED).pack(anchor="w", pady=(14, 0))

    def check_active_contact(self):
        if not self.active_contact:
            return
        keys = self.get_contact_public_keys(self.active_contact)
        if keys is not None:
            fingerprint = public_key_fingerprint(*keys)
            messagebox.showinfo("Contact fingerprint", f"{self.active_contact}\n\n{fingerprint}\n\nCompare this fingerprint through a trusted separate channel.")

    def get_contact_public_keys(self, contact):
        try:
            public_data = api_request("GET", f"/users/{contact}/public-key", token=self.token)
            encryption_public = base64.b64decode(public_data["encryption_public_key"], validate=True)
            signing_public = base64.b64decode(public_data["signing_public_key"], validate=True)
            fingerprint = public_key_fingerprint(encryption_public, signing_public)
            trust = verify_trusted_fingerprint(self.username, contact, fingerprint)
            if trust == "mismatch":
                messagebox.showerror("Fingerprint mismatch", f"The saved fingerprint for {contact} has changed. Do not send or accept messages from this contact.")
                return None
            if trust == "unknown":
                confirmed = messagebox.askyesno("Verify contact fingerprint", f"Contact: {contact}\n\nFingerprint:\n{fingerprint}\n\nHave you verified this fingerprint through a trusted separate channel?")
                if not confirmed:
                    return None
                save_trusted_fingerprint(self.username, contact, fingerprint)
            return encryption_public, signing_public
        except Exception as error:
            messagebox.showerror("Contact error", str(error))
            return None

    def send_chat_message(self):
        recipient = self.active_contact
        plaintext = self.message_entry.get().strip()
        if not recipient or not plaintext:
            messagebox.showwarning("Missing information", "Select a contact and enter a message.")
            return
        if recipient == self.username:
            messagebox.showwarning("Invalid recipient", "You cannot send a message to yourself.")
            return
        try:
            public_keys = self.get_contact_public_keys(recipient)
            if public_keys is None:
                return
            recipient_encryption_public, _ = public_keys
            envelope = encrypt_message(
                plaintext=plaintext,
                recipient_encryption_public=recipient_encryption_public,
                sender_signing_private=self.private_keys["signing_private"],
                sender_username=self.username,
                recipient_username=recipient,
            )
            api_request("POST", "/messages", token=self.token,
                        payload={"recipient": recipient, "envelope": envelope})
            self.append_message(self.username, plaintext, outgoing=True)
            self.message_entry.delete(0, "end")
        except Exception as error:
            messagebox.showerror("Send failed", str(error))

    def refresh_inbox(self):
        try:
            result = api_request("GET", "/messages", token=self.token)
            messages = result.get("messages", [])
            if not messages:
                messagebox.showinfo("Inbox", "No new messages.")
                return
            received = 0
            failed = 0
            for message in messages:
                try:
                    sender = message["sender"].strip().lower()
                    public_keys = self.get_contact_public_keys(sender)
                    if public_keys is None:
                        failed += 1
                        continue
                    _, sender_signing_public = public_keys
                    plaintext = decrypt_message(
                        envelope=message["envelope"],
                        recipient_encryption_private=self.private_keys["encryption_private"],
                        sender_signing_public=sender_signing_public,
                        expected_sender=sender,
                        expected_recipient=self.username,
                    )
                    api_request("POST", f"/messages/{message['id']}/ack", token=self.token)
                    self.append_message(sender, plaintext, outgoing=False)
                    received += 1
                except Exception as error:
                    failed += 1
                    messagebox.showerror("Message processing failed", str(error))
            if received:
                messagebox.showinfo("Inbox", f"Received {received} message(s)." +
                                    (f" {failed} message(s) were not processed." if failed else ""))
            elif failed:
                messagebox.showwarning("Inbox", f"Could not process {failed} message(s).")
        except Exception as error:
            messagebox.showerror("Inbox error", str(error))

    def logout(self):
        try:
            api_request("POST", "/logout", token=self.token)
        except RuntimeError as exc:
            messagebox.showwarning("Logout", f"Server logout failed: {exc}")
        finally:
            self.username = None
            self.token = None
            self.private_keys = None
            self.active_contact = None
            self.conversations = {}
            self.show_login()


def main():
    root = tk.Tk()
    SecureChatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
