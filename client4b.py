import socket
import logging
import random
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from typing import Optional, Dict
from tkintermapview import TkinterMapView
import csv
import time
import json
import threading

# Import cryptographic modules
from key_loader import get_random_keys
from encryption import encrypt_data
from decryption import decrypt_data
from digital_signature import generate_signature, verify_signature
from quantum_generator import get_random_sequence_from_csv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log'),
        logging.StreamHandler()
    ]
)

class TankClientGUI:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title(f"Tank Client - {username}")
        self.root.geometry("1200x800")
        
        # Configure grid weight
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # Initialize variables
        self.client_socket = None
        self.connected = False
        self.location_timer = None
        self.current_interval = 5  # Default to 5 seconds
        self.auto_send_location = True
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 5  # seconds
        self.authenticated = False
        self.connection_lock = threading.Lock()

        # Create main frames
        self.create_frames()
        self.setup_styles()
        self.create_widgets()
        
        # Initialize cryptographic components
        self._initialize_crypto()

        # Start connection attempt
        self.attempt_connection()

        # Set up connection monitoring
        self.setup_connection_monitor()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """Handle window closing"""
        if self.connected:
            self.disconnect()
        self.root.destroy()

    def disconnect(self):
        """Disconnect from server"""
        with self.connection_lock:
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
                self.client_socket = None
            self.connected = False
            self.authenticated = False

    def setup_connection_monitor(self):
        """Setup periodic connection monitoring"""
        def check_connection():
            if not self.connected or (self.connected and not self.authenticated):
                self.attempt_connection()
            self.root.after(5000, check_connection)
        check_connection()

    def attempt_connection(self):
        """Attempt to connect to server"""
        with self.connection_lock:
            if self.connected:
                return

            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.settimeout(10)  # 10 second timeout
                self.client_socket.connect(("localhost", 12345))
                self.connected = True
                self.log("Connected to server")

                # Send tank ID
                self.client_socket.send(self.username.encode())

                # Start message handler
                threading.Thread(target=self.handle_server_messages, daemon=True).start()

            except Exception as e:
                self.log(f"Connection failed: {e}", "ERROR")
                self.connected = False
                self.authenticated = False
                if self.client_socket:
                    try:
                        self.client_socket.close()
                    except:
                        pass
                    self.client_socket = None

    def handle_server_messages(self):
        """Handle incoming server messages"""
        while self.connected:
            try:
                message = self.client_socket.recv(1024).decode()
                if not message:
                    raise ConnectionError("Connection lost")

                self.log(f"Received: {message}")

                if message.startswith("Challenge:"):
                    self.handle_challenge(message)
                elif message == "Authentication Successful":
                    self.authenticated = True
                    self.log("Authentication successful")
                    self.reconnect_attempts = 0
                elif message == "Are you ready?":
                    self.client_socket.send("yes".encode())
                elif message == "Give me your location":
                    self.send_location()

            except Exception as e:
                self.log(f"Connection error: {e}", "ERROR")
                self.connected = False
                self.authenticated = False
                break

        # Try to reconnect if connection lost
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            self.root.after(self.reconnect_delay * 1000, self.attempt_connection)

    def handle_challenge(self, message):
        """Handle authentication challenge"""
        try:
            parts = message.split(": ")[1].split()
            challenge_type = int(parts[0])
            challenge_num = int(parts[1]) if len(parts) > 1 else 0
            
            response = self.calculate_challenge_response(challenge_type, challenge_num)
            if self.connected:
                self.client_socket.send(str(response).encode())
                self.log("Challenge response sent")
                
        except Exception as e:
            self.log(f"Error handling challenge: {e}", "ERROR")

    def calculate_challenge_response(self, challenge_type, num):
        """Calculate response for server challenge"""
        if challenge_type == 0:
            return "OK"
        elif challenge_type == 1:
            return str(num ** 2)
        elif challenge_type == 2:
            return str(num ** 3)
        elif challenge_type == 3:
            return str(num * (num + 1) // 2)
        elif challenge_type == 4:
            return str(num % 2 == 0)
        elif challenge_type == 5:
            return str(num % 2 != 0)
        elif challenge_type == 6:
            return str(num * 2)
        elif challenge_type == 7:
            return "Prime" if all(num % i != 0 for i in range(2, int(num**0.5) + 1)) and num > 1 else "Not Prime"
        elif challenge_type == 8:
            return "".join(reversed(str(num)))
        elif challenge_type == 9:
            return str(len(bin(num)) - 2)
        return "OK"

    def send_location(self):
        """Send encrypted location to server"""
        if not self.connected or not self.authenticated:
            return

        try:
            location = self.get_random_location()
            if not location:
                location = "17.385044,78.486671"  # Default location

            # Create signature
            signature = generate_signature(location, self.private_key_rsa)

            # Encrypt location
            ivs, encrypted_data, tags = encrypt_data(
                location,
                self.methods,
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.public_key_rsa,
                self.public_key_ecc
            )

            # Prepare payload
            payload = {
                "ivs": ivs,
                "data": encrypted_data,
                "tags": tags,
                "signature": signature,
                "random_index": self.random_index,
                "sequence_hash": self.sequence_hash
            }

            # Send encrypted location
            if self.connected:
                self.client_socket.sendall(f"{json.dumps(payload)}\n".encode())
                self.log("Location sent")

                # Update map
                try:
                    lat, lon = map(float, location.split(","))
                    self.map_widget.set_position(lat, lon)
                    self.map_widget.set_marker(lat, lon, text="Current Location")
                except ValueError:
                    self.log("Invalid location format", "ERROR")

        except Exception as e:
            self.log(f"Error sending location: {e}", "ERROR")
            if "forcibly closed" in str(e):
                self.connected = False
                self.authenticated = False

    def get_random_location(self):
        """Get random location from CSV"""
        try:
            with open("tank_locations.csv", "r") as file:
                reader = csv.reader(file)
                locations = [row[1] for row in reader if row[0] == self.username]
                if locations:
                    return random.choice(locations)
        except FileNotFoundError:
            self.log("Location file not found", "ERROR")
        return None

    def _initialize_crypto(self):
        """Initialize cryptographic components"""
        try:
            keys = get_random_keys()
            (
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.private_key_rsa,
                self.public_key_rsa,
                self.private_key_ecc,
                self.public_key_ecc,
                self.random_index
            ) = keys
            
            self.methods, self.sequence_hash = get_random_sequence_from_csv()
            self.crypto_initialized = True
            self.log("Cryptography initialized successfully")
        except Exception as e:
            self.log(f"Failed to initialize cryptography: {e}", "ERROR")
            self.crypto_initialized = False

    def create_frames(self):
        # Left Panel (Map)
        self.left_frame = ttk.Frame(self.root)
        self.left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Right Panel (Logs and Controls)
        self.right_frame = ttk.Frame(self.root)
        self.right_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

    def setup_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", font=("Arial", 12))
        style.configure("TButton", padding=5)
        style.configure("Log.TFrame", background="#ffffff")

    def create_widgets(self):
        # Map Section
        self.create_map_section()
        
        # Client Controls and Logs Section
        self.create_client_section()

    def create_map_section(self):
        map_frame = ttk.LabelFrame(self.left_frame, text="Map View", padding=10)
        map_frame.pack(fill="both", expand=True)

        self.map_widget = TkinterMapView(map_frame, width=600, height=600)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(17.3850, 78.4867)
        self.map_widget.set_zoom(10)

    def create_client_section(self):
        # Timer Selection
        timer_frame = ttk.LabelFrame(self.right_frame, text="Location Update Interval", padding=10)
        timer_frame.pack(fill="x", pady=(0, 10))

        self.timer_var = tk.StringVar(value="5s")
        timer_options = [
            ("5 seconds", "5s"),
            ("30 seconds", "30s"),
            ("1 minute", "1m"),
            ("10 minutes", "10m"),
            ("30 minutes", "30m"),
            ("1 hour", "1h")
        ]

        for text, value in timer_options:
            ttk.Radiobutton(timer_frame, text=text, value=value, 
                          variable=self.timer_var, 
                          command=self.update_timer).pack(anchor="w")

        # Auto-send control
        self.auto_send_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(timer_frame, text="Auto-send Location", 
                       variable=self.auto_send_var,
                       command=self.toggle_auto_send).pack(pady=5)

        # Log Section
        log_frame = ttk.LabelFrame(self.right_frame, text="Client Logs", padding=10)
        log_frame.pack(fill="both", expand=True)

        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, 
                                                font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True)

    def toggle_auto_send(self):
        """Toggle automatic location sending"""
        self.auto_send_location = self.auto_send_var.get()
        if self.auto_send_location:
            self.restart_location_timer()
        elif self.location_timer:
            self.location_timer.cancel()

    def update_timer(self):
        """Update the location sending interval"""
        intervals = {
            "5s": 5,
            "30s": 30,
            "1m": 60,
            "10m": 600,
            "30m": 1800,
            "1h": 3600
        }
        
        new_interval = intervals.get(self.timer_var.get())
        if new_interval != self.current_interval:
            self.current_interval = new_interval
            self.restart_location_timer()
            self.log(f"Location update interval changed to {self.timer_var.get()}")

    def restart_location_timer(self):
        """Restart the location sending timer"""
        if self.location_timer:
            self.location_timer.cancel()
        
        if self.current_interval and self.connected and self.authenticated and self.auto_send_location:
            self.location_timer = threading.Timer(self.current_interval, self.send_location_loop)
            self.location_timer.daemon = True
            self.location_timer.start()

    def send_location_loop(self):
        """Send location periodically"""
        if self.connected and self.authenticated and self.auto_send_location:
            self.send_location()
            self.restart_location_timer()

    def log(self, message, level="INFO"):
        """Add message to log area with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        self.log_area.insert(tk.END, log_entry)
        self.log_area.see(tk.END)
        
        logging.log(
            getattr(logging, level),
            message
        )

if __name__ == "__main__":
    root = tk.Tk()
    app = TankClientGUI(root, "TestTank")
    root.mainloop()