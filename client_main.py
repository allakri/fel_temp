import socket
import logging
import random
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from typing import Optional, Dict, List
from tkintermapview import TkinterMapView
import csv
import time
import json
import threading
from datetime import datetime

# Import cryptographic modules
from key_loader import get_random_keys, get_keys_by_index
from encryption import encrypt_data
from decryption import decrypt_data
from digital_signature import generate_signature, verify_signature
from quantum_generator import get_random_sequence_from_csv
from sequence_utils import find_sequence_by_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log'),
        logging.StreamHandler()
    ]
)

# class TankClientGUI:
#     def __init__(self, root, username):
#         self.root = root
#         self.root.title(f"Tank Client - {username}")
#         self.root.geometry("1200x800")
        
#         # Initialize variables
#         self.username = username
#         self.client_socket = None
#         self.connected = False
#         self.authenticated = False
#         self.location_timer = None
#         self.reconnect_attempts = 0
#         self.auto_send_location = True
#         self.location_active = True
#         self.current_interval = 30  # Default interval in seconds
#         self.last_location_time = 0
#         self.message_processing = False
#         self.client_socket = None
#         self.connected = False
#         self.location_timer = None
#         self.current_interval = 1000  # Default to 30 seconds
#         self.auto_send_location = True
#         self.reconnect_attempts = 0
#         self.max_reconnect_attempts = 5
#         self.reconnect_delay = 5  # seconds
#         self.authenticated = False
#         self.connection_lock = threading.Lock()
#         self.manual_send_button = None
#         self.current_marker = None
#         self.log_area = None  # Initialize log_area before it's used

       
#         # Location tracking
#         self.locations: List[str] = []
#         self.current_location_index = 0

#         # Create main frames
#         # self.create_frames()
#         self.setup_styles()
#         # self.create_widgets()
        
#         # Load locations after widgets are created (since we need log_area)
#         self.load_tank_locations()
        
#         # Initialize cryptographic components
#         self._initialize_crypto()

#         # Start connection attempt
#         self.attempt_connection()

#         # Bind window close event
#         self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

#         # Initialize crypto components
#         self._initialize_crypto()
        
#         # Create notebook for tabs
#         self.notebook = ttk.Notebook(self.root)
#         self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
#         # Create tabs
#         self.map_tab = ttk.Frame(self.notebook)
#         self.chat_tab = ttk.Frame(self.notebook)
        
#         self.notebook.add(self.map_tab, text='Map View')
#         self.notebook.add(self.chat_tab, text='Chat')
        
#         # Create layouts for each tab
#         self.create_map_tab()
#         self.create_chat_tab()
        
#         # Connect to server
#         self.connect_to_server()
        
#         # Start message receiver thread
#         threading.Thread(target=self.receive_messages, daemon=True).start()
class TankClientGUI:
    def __init__(self, root, username):
        self.root = root
        self.root.title(f"Tank Client - {username}")
        self.root.geometry("1200x800")
        
        # # Initialize variables
        # self.username = username
        # self.client_socket = None
        # self.connected = False
        # self.authenticated = False
        # self.location_timer = None
        # self.reconnect_attempts = 0
        # self.auto_send_location = True
        # self.location_active = True
        # self.current_interval = 30  # Default interval in seconds
        # self.last_location_time = 0
        # self.message_processing = False
        # self.client_socket = None
        # self.connected = False
        # self.location_timer = None
        # self.current_interval = 1000  # Default to 30 seconds
        # self.auto_send_location = True
        # self.reconnect_attempts = 0
        # self.max_reconnect_attempts = 5
        # self.reconnect_delay = 5  # seconds
        # self.authenticated = False
        # self.connection_lock = threading.Lock()
        # self.manual_send_button = None
        # self.current_marker = None

         # Initialize variables
        self.username = username
        self.client_socket = None
        self.connected = False
        self.authenticated = False
        self.location_timer = None
        self.reconnect_attempts = 0
        self.auto_send_location = True
        self.location_active = True
        self.current_interval = 30  # Default interval in seconds
        self.last_location_time = 0
        self.message_processing = False
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 5  # seconds
        self.connection_lock = threading.Lock()
        self.manual_send_button = None
        self.current_marker = None

        # Initialize log_area early to avoid NoneType errors
        self.log_area = None

        # Location tracking
        self.locations: List[str] = []
        self.current_location_index = 0

        # Setup styles
        self.setup_styles()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.map_tab = ttk.Frame(self.notebook)
        self.chat_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.map_tab, text='Map View')
        self.notebook.add(self.chat_tab, text='Chat')
        
        # Create layouts for each tab
        self.create_map_tab()  # This initializes self.log_area
        self.create_chat_tab()
        
        # Load locations after widgets are created (since we need log_area)
        self.load_tank_locations()
        
        # Initialize cryptographic components
        self._initialize_crypto()

        # Start connection attempt
        self.attempt_connection()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """Handle the window close event"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # Close the client socket if connected
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
            self.root.destroy()
            
    def create_map_tab(self):
        # Left Panel (Map)
        left_frame = ttk.Frame(self.map_tab)
        left_frame.pack(side="left", fill="both", expand=True)

        # Map widget
        map_frame = ttk.LabelFrame(left_frame, text="Map View", padding=10)
        map_frame.pack(fill="both", expand=True)

        self.map_widget = TkinterMapView(map_frame, width=800, height=600)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(17.3850, 78.4867)
        self.map_widget.set_zoom(10)

        # Right Panel (Controls and Logs)
        right_frame = ttk.Frame(self.map_tab)
        right_frame.pack(side="right", fill="y", padx=5)

        # Log Section
        log_frame = ttk.LabelFrame(right_frame, text="Client Logs", padding=10)
        log_frame.pack(fill="both", expand=True)

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=40,
            height=20,
            font=("Consolas", 10)
        )
        self.log_area.pack(fill="both", expand=True)

    def setup_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", font=("Arial", 12))
        style.configure("TButton", padding=5)
        style.configure("Log.TFrame", background="#ffffff")


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
            logging.info("Cryptography initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize cryptography: {e}")
            self.show_error("Crypto Error", "Failed to initialize cryptography")

    def create_map_tab(self):
        # Left Panel (Map)
        left_frame = ttk.Frame(self.map_tab)
        left_frame.pack(side="left", fill="both", expand=True)

        # Map widget
        map_frame = ttk.LabelFrame(left_frame, text="Map View", padding=10)
        map_frame.pack(fill="both", expand=True)

        self.map_widget = TkinterMapView(map_frame, width=800, height=600)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(17.3850, 78.4867)
        self.map_widget.set_zoom(10)

        # Right Panel (Controls and Logs)
        right_frame = ttk.Frame(self.map_tab)
        right_frame.pack(side="right", fill="y", padx=5)

        # Location Controls
        control_frame = ttk.LabelFrame(right_frame, text="Location Controls", padding=10)
        control_frame.pack(fill="x", pady=5)

        # Location Activation Switch
        self.location_active_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            control_frame,
            text="Location Active",
            variable=self.location_active_var,
            command=self.toggle_location_active
        ).pack(fill="x", pady=5)

        # Timer Selection
        timer_frame = ttk.LabelFrame(control_frame, text="Update Interval", padding=5)
        timer_frame.pack(fill="x", pady=5)

        self.timer_var = tk.StringVar(value="30")
        intervals = [
            ("5 seconds", "5"),
            ("30 seconds", "30"),
            ("1 minute", "60"),
            ("5 minutes", "300"),
            ("10 minutes", "600"),
            ("30 minutes", "1800")
        ]

        for text, value in intervals:
            ttk.Radiobutton(
                timer_frame,
                text=text,
                value=value,
                variable=self.timer_var,
                command=self.update_timer
            ).pack(anchor="w")

        # Mode Selection
        mode_frame = ttk.LabelFrame(control_frame, text="Send Mode", padding=5)
        mode_frame.pack(fill="x", pady=5)

        self.auto_mode_var = tk.BooleanVar(value=True)
        ttk.Radiobutton(
            mode_frame,
            text="Automatic",
            value=True,
            variable=self.auto_mode_var,
            command=self.toggle_send_mode
        ).pack(anchor="w")

        ttk.Radiobutton(
            mode_frame,
            text="Manual",
            value=False,
            variable=self.auto_mode_var,
            command=self.toggle_send_mode
        ).pack(anchor="w")

        self.manual_send_button = ttk.Button(
            mode_frame,
            text="Send Location",
            command=self.send_location,
            state="disabled"
        )
        self.manual_send_button.pack(fill="x", pady=5)

        # Log Section
        log_frame = ttk.LabelFrame(right_frame, text="Client Logs", padding=10)
        log_frame.pack(fill="both", expand=True)

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=40,
            height=20,
            font=("Consolas", 10)
        )
        self.log_area.pack(fill="both", expand=True)

    def create_chat_tab(self):
        chat_frame = ttk.Frame(self.chat_tab)
        chat_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            height=20,
            font=("Consolas", 10)
        )
        self.chat_display.pack(fill="both", expand=True, pady=(0, 10))

        # Message input area
        input_frame = ttk.Frame(chat_frame)
        input_frame.pack(fill="x")

        self.message_input = ttk.Entry(input_frame)
        self.message_input.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Button(
            input_frame,
            text="Send",
            command=self.send_chat_message
        ).pack(side="right")

    def load_tank_locations(self):
        """Load locations for this tank from CSV"""
        try:
            with open("tank_locations.csv", "r") as file:
                reader = csv.reader(file)
                next(reader)  # Skip header
                for row in reader:
                    if row[0] == self.username:
                        # Extract and clean locations
                        self.locations = [
                            loc.strip().strip('"') for loc in row[1:11]  # Get exactly 10 locations
                            if loc.strip()
                        ]
                        self.log(f"Loaded {len(self.locations)} locations for {self.username}")
                        break
                if not self.locations:
                    self.log(f"No locations found for {self.username}", "ERROR")
        except Exception as e:
            self.log(f"Error loading locations: {e}", "ERROR")
            self.locations = []

    def get_next_location(self) -> str:
        """Get the next location in sequence"""
        if not self.locations:
            return "17.385044,78.486671"  # Default location
        
        location = self.locations[self.current_location_index]
        self.current_location_index = (self.current_location_index + 1) % len(self.locations)
        return location

    def update_map_marker(self, lat: float, lon: float):
        """Update marker on map"""
        try:
            if self.current_marker:
                self.current_marker.delete()
            
            self.current_marker = self.map_widget.set_marker(
                lat, lon,
                text=f"{self.username} Current Position"
            )
            self.map_widget.set_position(lat, lon)
        except Exception as e:
            self.log(f"Error updating map marker: {e}", "ERROR")

    def connect_to_server(self):
        """Connect to the server"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('localhost', 5000))
            self.connected = True
            self.client_socket.send(self.username.encode())
            self.log("Connected to server")
        except Exception as e:
            self.log(f"Connection error: {e}", "ERROR")
            self.reconnect_after_delay()

    def reconnect_after_delay(self):
        """Attempt to reconnect after a delay"""
        if self.reconnect_attempts < 5:
            self.reconnect_attempts += 1
            delay = min(30, 2 ** self.reconnect_attempts)
            self.log(f"Reconnecting in {delay} seconds...")
            self.root.after(delay * 1000, self.connect_to_server)
        else:
            self.log("Max reconnection attempts reached", "ERROR")

    def toggle_location_active(self):
        """Toggle location sending capability"""
        self.location_active = self.location_active_var.get()
        if self.location_active:
            self.log("Location sending activated")
            if self.auto_mode_var.get():
                self.restart_location_timer()
        else:
            self.log("Location sending deactivated")
            if self.location_timer:
                self.root.after_cancel(self.location_timer)
                self.location_timer = None

    def update_timer(self):
        """Update the location sending interval"""
        try:
            self.current_interval = int(self.timer_var.get())
            self.log(f"Timer updated to {self.current_interval} seconds")
            if self.auto_mode_var.get() and self.location_active:
                self.restart_location_timer()
        except ValueError:
            self.log("Invalid timer value", "ERROR")

    def toggle_send_mode(self):
        """Toggle between automatic and manual location sending"""
        is_auto = self.auto_mode_var.get()
        self.manual_send_button.configure(state="disabled" if is_auto else "normal")
        
        if is_auto and self.location_active:
            self.restart_location_timer()
        elif not is_auto and self.location_timer:
            self.root.after_cancel(self.location_timer)
            self.location_timer = None
        
        self.log(f"Switched to {'automatic' if is_auto else 'manual'} mode")

    def restart_location_timer(self):
        """Restart the location sending timer"""
        if self.location_timer:
            self.root.after_cancel(self.location_timer)
        
        if self.auto_mode_var.get() and self.location_active:
            self.location_timer = self.root.after(
                self.current_interval * 1000,
                self.timer_callback
            )
            self.log(f"Timer restarted with interval: {self.current_interval} seconds")

    def timer_callback(self):
        """Handle timer-triggered location sending"""
        if self.location_active and self.auto_mode_var.get():
            self.send_location()
            self.restart_location_timer()

    def send_location(self):
        """Send encrypted location to server"""
        if not self.connected or not self.authenticated or not self.location_active:
            return

        current_time = time.time()
        if not self.auto_mode_var.get() and current_time - self.last_location_time < 1:
            return  # Prevent spam in manual mode

        try:
            location = self.get_next_location()
            if not location:
                return

            # Get new encryption sequence for this location
            methods, sequence_hash = get_random_sequence_from_csv()

            # Create signature
            signature = generate_signature(location, self.private_key_rsa)

            # Encrypt location
            ivs, encrypted_data, tags = encrypt_data(
                location,
                methods,
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.public_key_rsa,
                self.public_key_ecc
            )

            # Prepare payload
            payload = {
                "type": "location",
                "ivs": ivs,
                "data": encrypted_data,
                "tags": tags,
                "signature": signature,
                "random_index": self.random_index,
                "sequence_hash": sequence_hash
            }

            # Send encrypted location
            if self.connected:
                self.client_socket.sendall(f"{json.dumps(payload)}\n".encode())
                self.log("Location sent")

                # Update map
                try:
                    lat, lon = map(float, location.split(","))
                    self.update_map_marker(lat, lon)
                except ValueError:
                    self.log("Invalid location format", "ERROR")

            self.last_location_time = current_time

        except Exception as e:
            self.log(f"Error sending location: {e}", "ERROR")
            if "forcibly closed" in str(e):
                self.connected = False
                self.authenticated = False

    # def get_next_location(self):
    #     """Get next location from predefined path or random location"""
    #     # For demo purposes, return random location around Hyderabad
    #     base_lat, base_lon = 17.3850, 78.4867
    #     lat = base_lat + random.uniform(-0.1, 0.1)
    #     lon = base_lon + random.uniform(-0.1, 0.1)
    #     return f"{lat},{lon}"

    # def update_map_marker(self, lat, lon):
    #     """Update tank marker on map"""
    #     self.map_widget.delete_all_marker()
    #     self.map_widget.set_marker(lat, lon, text="Tank")

    def send_chat_message(self):
        """Send encrypted chat message"""
        if not self.connected or not self.authenticated:
            messagebox.showerror("Error", "Not connected to server")
            return

        message = self.message_input.get().strip()
        if not message:
            return

        try:
            # Get new encryption sequence for this message
            methods, sequence_hash = get_random_sequence_from_csv()

            # Create signature
            signature = generate_signature(message, self.private_key_rsa)

            # Encrypt message
            ivs, encrypted_data, tags = encrypt_data(
                message,
                methods,
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.public_key_rsa,
                self.public_key_ecc
            )

            # Prepare payload
            payload = {
                "type": "chat",
                "ivs": ivs,
                "data": encrypted_data,
                "tags": tags,
                "signature": signature,
                "random_index": self.random_index,
                "sequence_hash": sequence_hash,
                "sender": self.username
            }

            # Send encrypted message
            self.client_socket.sendall(f"{json.dumps(payload)}\n".encode())

            # Add message to chat display
            self.add_chat_message("You", message)

            # Clear input field
            self.message_input.delete(0, tk.END)

        except Exception as e:
            self.log(f"Error sending message: {e}", "ERROR")

    def receive_messages(self):
        """Handle incoming messages"""
        while self.connected:
            try:
                data = ""
                while self.connected:
                    chunk = self.client_socket.recv(1024).decode()
                    if not chunk:
                        raise ConnectionError("Connection lost")
                    
                    data += chunk
                    if "\n" in data:
                        break

                if not data:
                    continue

                try:
                    payload = json.loads(data.strip())
                    
                    if payload.get("type") == "chat":
                        # Handle chat message
                        decrypted_message = self.decrypt_message(payload)
                        if decrypted_message:
                            self.root.after(0, lambda: self.show_notification(
                                "New Message",
                                f"From {payload['sender']}: {decrypted_message[:50]}..."
                            ))
                            self.root.after(0, lambda: self.add_chat_message(
                                payload['sender'],
                                decrypted_message
                            ))
                    else:
                        # Handle server commands
                        self.handle_server_command(data.strip())

                except json.JSONDecodeError:
                    # Handle regular server commands
                    self.handle_server_command(data.strip())

            except Exception as e:
                if self.connected:
                    self.log(f"Connection error: {e}", "ERROR")
                    self.connected = False
                    self.authenticated = False
                break

    def decrypt_message(self, payload):
        """Decrypt incoming message"""
        try:
            index = payload["random_index"]
            hash_value = payload["sequence_hash"]
            methods = find_sequence_by_hash(hash_value)

            if not methods:
                return None

            keys = get_keys_by_index(index)
            if not keys or len(keys) != 7:
                return None

            key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc = keys

            decrypted_message = decrypt_data(
                payload["ivs"],
                payload["data"],
                payload["tags"],
                methods,
                key_aes,
                key_des,
                key_tdes,
                private_key_rsa,
                private_key_ecc
            )

            is_valid = verify_signature(
                decrypted_message,
                payload["signature"],
                public_key_rsa
            )

            if not is_valid:
                return None

            return decrypted_message

        except Exception as e:
            self.log(f"Decryption error: {e}", "ERROR")
            return None

    # def handle_server_command(self, message):
    #     """Handle non-chat server messages"""
    #     if message.startswith("Challenge:"):
    #         self.handle_challenge(message)
    #     elif message == "Authentication Successful":
    #         if not self.authenticated:
    #             self.authenticated = True
    #             self.log("Authentication successful")
    #             self.reconnect_attempts = 0
    #             if self.auto_mode_var.get() and self.location_active:
    #                 self.restart_location_timer()
    #     elif message == "Are you ready?":
    #         self.client_socket.send("yes".encode())
    #     elif message == "Give me your location":
    #         if self.location_active:
    #             self.send_location()

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
                    if not self.authenticated:
                        self.authenticated = True
                        self.log("Authentication successful")
                        self.reconnect_attempts = 0
                        # Start location timer if auto-send is enabled
                        if self.auto_send_location:
                            self.restart_location_timer()
                elif message == "Are you ready?":
                    self.client_socket.send("yes".encode())
                elif message == "Give me your location":
                    # self.send_location()
                    # Respect the timer interval
                    current_time = time.time()
                    if current_time - self.last_location_time >= self.current_interval:
                        self.send_location()
                        self.last_location_time = current_time
                        self.log("Location sent")
                    else:
                        self.log("Skipping location send due to timer interval")
                elif message == "Location received successfully":
                    self.log("Server confirmed location received")

            except Exception as e:
                self.log(f"Connection error: {e}", "ERROR")
                self.connected = False
                self.authenticated = False
                break

        # Try to reconnect if connection lost
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            self.root.after(self.reconnect_delay * 1000, self.attempt_connection)

    # def handle_challenge(self, message):
    #     """Handle authentication challenge"""
    #     challenge = message.split(": ")[1]
    #     # Simple challenge response for demo
    #     response = str(int(challenge) + 1)
    #     self.client_socket.send(response.encode())

    def attempt_connection(self):
        """Attempt to connect to server"""
        with self.connection_lock:
            if self.connected and self.authenticated:
                return

            try:
                if self.client_socket:
                    try:
                        self.client_socket.close()
                    except:
                        pass
                
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.settimeout(10)  # 10 second timeout
                self.client_socket.connect(("localhost", 5000))  # Updated port to match the server
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

                # Try to reconnect
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
    
    def show_notification(self, title, message):
        """Show popup notification"""
        messagebox.showinfo(title, message)

    def add_chat_message(self, sender, message):
        """Add message to chat display"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
        self.chat_display.see(tk.END)

    def log(self, message, level="INFO"):
        """Add message to log area"""
        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {level}: {message}\n"
        self.log_area.insert(tk.END, log_message)
        self.log_area.see(tk.END)
        logging.log(
            getattr(logging, level),
            message
        )

if __name__ == "__main__":
    root = tk.Tk()
    app = TankClientGUI(root, "TestTank")
    root.mainloop()
