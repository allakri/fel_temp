import csv
import hashlib
from tkinter import messagebox
import tkinter as tk
from tkinter import ttk
from server4b import CommanderGUI

CSV_FILE = 'server_credentials.csv'

class SystemAuthGUI:
    def __init__(self, root, on_login_success):
        self.root = root
        self.on_login_success = on_login_success
        self.root.title("Commander Authentication")
        self.root.geometry("800x600")
        self.setup_styles()
        self.show_login_screen()

    def setup_styles(self):
        """Setup custom styles for the GUI"""
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=("Arial", 12))
        style.configure("TButton", font=("Arial", 12, "bold"), padding=10)
        style.configure("Header.TLabel", font=("Arial", 24, "bold"), background="#4CAF50", foreground="white")
        style.configure("Login.TButton", background="#2196F3", foreground="white")
        style.configure("Signup.TButton", background="#4CAF50", foreground="white")
        style.configure("Back.TButton", background="#f44336", foreground="white")

    def show_login_screen(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main container with gradient background
        main_frame = ttk.Frame(self.root, style="TFrame")
        main_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Header
        header_frame = ttk.Frame(main_frame, style="TFrame")
        header_frame.pack(pady=20)
        ttk.Label(header_frame, text="Commander Control", style="Header.TLabel").pack()

        # Buttons container
        button_frame = ttk.Frame(main_frame, padding=30, relief="raised", style="TFrame")
        button_frame.pack(padx=20, pady=20)

        login_button = ttk.Button(
            button_frame, 
            text="LOGIN", 
            style="Login.TButton", 
            command=self.show_login_window,
            width=20
        )
        login_button.pack(pady=10)

        signup_button = ttk.Button(
            button_frame, 
            text="SIGNUP", 
            style="Signup.TButton", 
            command=self.show_signup_window,
            width=20
        )
        signup_button.pack(pady=10)

    def show_login_window(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()

        frame = ttk.Frame(self.root, padding=20)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="Login", style="Header.TLabel").pack(pady=20)

        ttk.Label(frame, text="Username:", style="TLabel").pack(pady=5)
        username_entry = ttk.Entry(frame, font=("Arial", 12), width=30)
        username_entry.pack(pady=5)

        ttk.Label(frame, text="Password:", style="TLabel").pack(pady=5)
        password_entry = ttk.Entry(frame, show="*", font=("Arial", 12), width=30)
        password_entry.pack(pady=5)

        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)

        def login():
            username = username_entry.get()
            password = password_entry.get()
            if self.verify_login(username, password):
                self.on_login_success("tank", username)
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")

        ttk.Button(
            button_frame, 
            text="Login", 
            style="Login.TButton", 
            command=login
        ).pack(side="left", padx=5)

        ttk.Button(
            button_frame, 
            text="Back", 
            style="Back.TButton", 
            command=self.show_login_screen
        ).pack(side="left", padx=5)

    def show_signup_window(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()

        frame = ttk.Frame(self.root, padding=20)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="Sign Up", style="Header.TLabel").pack(pady=20)

        ttk.Label(frame, text="Username:", style="TLabel").pack(pady=5)
        username_entry = ttk.Entry(frame, font=("Arial", 12), width=30)
        username_entry.pack(pady=5)

        ttk.Label(frame, text="Password:", style="TLabel").pack(pady=5)
        password_entry = ttk.Entry(frame, show="*", font=("Arial", 12), width=30)
        password_entry.pack(pady=5)

        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)

        def signup():
            username = username_entry.get()
            password = password_entry.get()
            if self.username_exists(username):
                messagebox.showerror("Signup Failed", "Username already exists.")
            else:
                self.store_credentials(username, password)
                messagebox.showinfo("Signup Successful", "Account created successfully!")
                self.show_login_screen()

        ttk.Button(
            button_frame, 
            text="Sign Up", 
            style="Signup.TButton", 
            command=signup
        ).pack(side="left", padx=5)

        ttk.Button(
            button_frame, 
            text="Back", 
            style="Back.TButton", 
            command=self.show_login_screen
        ).pack(side="left", padx=5)

    def username_exists(self, username: str) -> bool:
        try:
            with open(CSV_FILE, 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username:
                        return True
        except FileNotFoundError:
            pass
        return False

    def store_credentials(self, username: str, password: str) -> None:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open(CSV_FILE, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([username, hashed_password])

    def verify_login(self, username: str, password: str) -> bool:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            with open(CSV_FILE, 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0] == username and row[1] == hashed_password:
                        return True
        except FileNotFoundError:
            pass
        return False

if __name__ == "__main__":
    def on_login_success(user_type, username):
        root.destroy()
        tank_root = tk.Tk()
        CommanderGUI(tank_root)
        tank_root.mainloop()

    root = tk.Tk()
    app = SystemAuthGUI(root, on_login_success)
    root.mainloop()