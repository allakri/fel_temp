import csv
import hashlib
from tkinter import messagebox
import tkinter as tk
from client4b import TankClientGUI  # Import the TankClientGUI class

CSV_FILE = 'client_credentials.csv'

class SystemAuthGUI:
    def __init__(self, root, on_login_success):
        self.root = root
        self.on_login_success = on_login_success
        self.root.title("Tank Client Authentication")
        self.root.geometry("800x600")
        
        # Configure colors
        self.colors = {
            'primary': '#2196F3',
            'success': '#4CAF50',
            'error': '#f44336',
            'warning': '#ff9800',
            'background': '#f5f5f5',
            'card': '#ffffff',
            'text': '#333333'
        }
        
        # Configure styles
        self.style = {
            'font_large': ('Arial', 16, 'bold'),
            'font_medium': ('Arial', 12, 'bold'),
            'font_small': ('Arial', 10),
            'padding': 20,
            'button_width': 15,
            'button_height': 2
        }
        
        self.root.configure(bg=self.colors['background'])
        self.show_login_screen()

    def show_login_screen(self) -> None:
        self.clear_screen()
        
        # Main container
        container = tk.Frame(self.root, bg=self.colors['background'])
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        title = tk.Label(
            container,
            text="Tank Authentication System",
            font=self.style['font_large'],
            bg=self.colors['background'],
            fg=self.colors['text']
        )
        title.pack(pady=(0, 30))
        
        # Buttons container
        button_frame = tk.Frame(container, bg=self.colors['background'])
        button_frame.pack(pady=20)
        
        # Login button
        login_button = tk.Button(
            button_frame,
            text="LOGIN",
            font=self.style['font_medium'],
            bg=self.colors['primary'],
            fg='white',
            width=self.style['button_width'],
            height=self.style['button_height'],
            command=self.show_login_window,
            cursor='hand2'
        )
        login_button.grid(row=0, column=0, padx=10)
        
        # Signup button
        signup_button = tk.Button(
            button_frame,
            text="SIGNUP",
            font=self.style['font_medium'],
            bg=self.colors['success'],
            fg='white',
            width=self.style['button_width'],
            height=self.style['button_height'],
            command=self.show_signup_window,
            cursor='hand2'
        )
        signup_button.grid(row=0, column=1, padx=10)

    def show_login_window(self) -> None:
        self.clear_screen()
        
        # Main container
        container = tk.Frame(self.root, bg=self.colors['card'], padx=40, pady=40)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        title = tk.Label(
            container,
            text="Login",
            font=self.style['font_large'],
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        title.pack(pady=(0, 20))
        
        # Username field
        tk.Label(
            container,
            text="Username:",
            font=self.style['font_small'],
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor='w')
        
        username_entry = tk.Entry(container, font=self.style['font_small'])
        username_entry.pack(fill='x', pady=(5, 15))
        
        # Password field
        tk.Label(
            container,
            text="Password:",
            font=self.style['font_small'],
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor='w')
        
        password_entry = tk.Entry(container, show="*", font=self.style['font_small'])
        password_entry.pack(fill='x', pady=(5, 20))
        
        # Buttons container
        button_frame = tk.Frame(container, bg=self.colors['card'])
        button_frame.pack(fill='x', pady=(20, 0))
        
        # Back button
        back_button = tk.Button(
            button_frame,
            text="Back",
            font=self.style['font_small'],
            command=self.show_login_screen,
            bg=self.colors['warning'],
            fg='white',
            cursor='hand2'
        )
        back_button.pack(side='left')
        
        # Login button
        def login():
            username = username_entry.get()
            password = password_entry.get()
            if self.verify_login(username, password):
                messagebox.showinfo("Success", "Login successful!")
                self.on_login_success(username)
            else:
                messagebox.showerror("Error", "Invalid username or password.")

        login_button = tk.Button(
            button_frame,
            text="Login",
            font=self.style['font_small'],
            command=login,
            bg=self.colors['primary'],
            fg='white',
            cursor='hand2'
        )
        login_button.pack(side='right')

    def show_signup_window(self) -> None:
        self.clear_screen()
        
        # Main container
        container = tk.Frame(self.root, bg=self.colors['card'], padx=40, pady=40)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        title = tk.Label(
            container,
            text="Sign Up",
            font=self.style['font_large'],
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        title.pack(pady=(0, 20))
        
        # Username field
        tk.Label(
            container,
            text="Username:",
            font=self.style['font_small'],
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor='w')
        
        username_entry = tk.Entry(container, font=self.style['font_small'])
        username_entry.pack(fill='x', pady=(5, 15))
        
        # Password field
        tk.Label(
            container,
            text="Password:",
            font=self.style['font_small'],
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor='w')
        
        password_entry = tk.Entry(container, show="*", font=self.style['font_small'])
        password_entry.pack(fill='x', pady=(5, 20))
        
        # Buttons container
        button_frame = tk.Frame(container, bg=self.colors['card'])
        button_frame.pack(fill='x', pady=(20, 0))
        
        # Back button
        back_button = tk.Button(
            button_frame,
            text="Back",
            font=self.style['font_small'],
            command=self.show_login_screen,
            bg=self.colors['warning'],
            fg='white',
            cursor='hand2'
        )
        back_button.pack(side='left')
        
        # Signup button
        def signup():
            username = username_entry.get()
            password = password_entry.get()
            if self.username_exists(username):
                messagebox.showerror("Error", "Username already exists.")
            else:
                self.store_credentials(username, password)
                messagebox.showinfo("Success", "Account created successfully!")
                self.show_login_screen()

        signup_button = tk.Button(
            button_frame,
            text="Sign Up",
            font=self.style['font_small'],
            command=signup,
            bg=self.colors['success'],
            fg='white',
            cursor='hand2'
        )
        signup_button.pack(side='right')

    def clear_screen(self):
        """Clear all widgets from the screen"""
        for widget in self.root.winfo_children():
            widget.destroy()

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
    def on_login_success(username):
        root.withdraw()  # Hide the login window instead of destroying it
        tank_root = tk.Tk()
        tank_client = TankClientGUI(tank_root, username)
        tank_root.protocol("WM_DELETE_WINDOW", lambda: on_client_close(tank_root))
        tank_root.mainloop()

    def on_client_close(tank_root):
        tank_root.destroy()
        root.deiconify()  # Show the login window again

    root = tk.Tk()
    app = SystemAuthGUI(root, on_login_success)
    root.mainloop()