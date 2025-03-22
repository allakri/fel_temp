import socket
import random
import logging
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from typing import Optional, Dict
from tkintermapview import TkinterMapView
import time
import json

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
        logging.FileHandler('secure_comm.log'),
        logging.StreamHandler()
    ]
)

def generate_challenge():
    """Generates a random challenge and expected answer."""
    challenge_types = [
        (0, "OK"),
        (1, lambda x: str(x**2)),  # Square
        (2, lambda x: str(x**3)),  # Cube
        (3, lambda x: str(x * (x + 1) // 2)),  # Sum of first N numbers
        (4, lambda x: str(x % 2 == 0)),  # Even check
        (5, lambda x: str(x % 2 != 0)),  # Odd check
        (6, lambda x: str(x * 2)),  # Double
        (7, lambda x: "Prime" if all(x % i != 0 for i in range(2, int(x**0.5) + 1)) and x > 1 else "Not Prime"),  # Prime check
        (8, lambda x: "".join(reversed(str(x)))),  # Reverse a number
        (9, lambda x: str(len(bin(x)) - 2))  # Number of bits in binary representation
    ]

    challenge_index, challenge_func = random.choice(challenge_types)
    if challenge_index in [1, 2, 3, 4, 5, 6, 7, 8, 9]:
        num = random.randint(2, 20)
        expected_answer = challenge_func(num)
        return f"{challenge_index} {num}", expected_answer
    else:
        return f"{challenge_index}", challenge_func

class CommanderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Commander Control Center")
        self.root.geometry("1400x800")
        
        # Configure grid weights for responsive layout
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=3)
        self.root.grid_columnconfigure(2, weight=1)

        # Initialize variables
        self.server_socket = None
        self.client_conn = None
        self.client_addr = None
        self.challenge = None
        self.expected_answer = None
        self.connected_tanks = {}
        self.server_running = False

        # Initialize crypto components
        self.last_encryption: Optional[Dict] = None
        self.crypto_initialized = False

        # Create main layout first
        self.create_layout()
        self.setup_styles()

        # Initialize crypto after GUI elements are created
        self._initialize_crypto()

    def setup_styles(self):
        """Configure ttk styles for widgets"""
        style = ttk.Style()
        
        # Configure frame styles
        style.configure("Server.TFrame", background="#f0f0f0")
        
        # Configure label styles
        style.configure("Header.TLabel", 
                       font=("Arial", 12, "bold"), 
                       padding=5)
        
        # Configure button styles
        style.configure("Action.TButton",
                       font=("Arial", 10),
                       padding=5)
        style.configure("Start.TButton",
                       background="#4CAF50",
                       font=("Arial", 11, "bold"),
                       padding=10)

    def create_layout(self):
        """Create the main application layout"""
        # Left Panel - Tank Management
        self.left_panel = ttk.Frame(self.root, style="Server.TFrame", padding=10)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.create_tank_management_section()

        # Center Panel - Map View
        self.center_panel = ttk.Frame(self.root, style="Server.TFrame", padding=10)
        self.center_panel.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.create_map_section()

        # Right Panel - Logs and Controls
        self.right_panel = ttk.Frame(self.root, style="Server.TFrame", padding=10)
        self.right_panel.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        self.create_control_section()

    def create_tank_management_section(self):
        """Create the tank management section"""
        # Header
        ttk.Label(self.left_panel, 
                 text="Tank Management", 
                 style="Header.TLabel").pack(fill="x", pady=(0, 10))

        # Available Tanks
        tank_frame = ttk.LabelFrame(self.left_panel, text="Available Tanks", padding=5)
        tank_frame.pack(fill="x", expand=True, pady=5)

        self.available_tanks_list = tk.Listbox(tank_frame, 
                                             height=8,
                                             selectmode=tk.SINGLE,
                                             font=("Arial", 10))
        self.available_tanks_list.pack(fill="both", expand=True, pady=5)

        # Online Tanks
        online_frame = ttk.LabelFrame(self.left_panel, text="Online Tanks", padding=5)
        online_frame.pack(fill="x", expand=True, pady=5)

        self.online_tanks_list = tk.Listbox(online_frame,
                                          height=6,
                                          selectmode=tk.SINGLE,
                                          font=("Arial", 10),
                                          bg="#d4edda")
        self.online_tanks_list.pack(fill="both", expand=True, pady=5)

        # Offline Tanks
        offline_frame = ttk.LabelFrame(self.left_panel, text="Offline Tanks", padding=5)
        offline_frame.pack(fill="x", expand=True, pady=5)

        self.offline_tanks_list = tk.Listbox(offline_frame,
                                           height=6,
                                           selectmode=tk.SINGLE,
                                           font=("Arial", 10),
                                           bg="#f8d7da")
        self.offline_tanks_list.pack(fill="both", expand=True, pady=5)

    def create_map_section(self):
        """Create the map section"""
        # Map Container
        map_container = ttk.LabelFrame(self.center_panel, text="Tactical Map", padding=10)
        map_container.pack(fill="both", expand=True)

        # Map Widget
        self.map_widget = TkinterMapView(map_container, width=800, height=600)
        self.map_widget.pack(fill="both", expand=True, padx=5, pady=5)
        self.map_widget.set_position(17.385044, 78.486671)
        self.map_widget.set_zoom(10)

        # Map Controls
        controls_frame = ttk.Frame(map_container)
        controls_frame.pack(fill="x", pady=5)

        ttk.Button(controls_frame,
                  text="Reset View",
                  style="Action.TButton",
                  command=self.reset_map_view).pack(side="left", padx=5)

        ttk.Button(controls_frame,
                  text="Track Selected Tank",
                  style="Action.TButton",
                  command=self.track_selected_tank).pack(side="left", padx=5)

    def create_control_section(self):
        """Create the control section"""
        # Server Controls
        control_frame = ttk.LabelFrame(self.right_panel, text="Server Controls", padding=10)
        control_frame.pack(fill="x", pady=5)

        self.server_status = ttk.Label(control_frame,
                                     text="Server Status: Stopped",
                                     font=("Arial", 10))
        self.server_status.pack(fill="x", pady=5)

        self.start_button = ttk.Button(control_frame,
                                     text="Start Server",
                                     style="Start.TButton",
                                     command=self.start_server)
        self.start_button.pack(fill="x", pady=5)

        # Log Section
        log_frame = ttk.LabelFrame(self.right_panel, text="Server Logs", padding=10)
        log_frame.pack(fill="both", expand=True, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_frame,
                                                wrap=tk.WORD,
                                                font=("Consolas", 9))
        self.log_area.pack(fill="both", expand=True)

        # Add log filters
        filter_frame = ttk.Frame(log_frame)
        filter_frame.pack(fill="x", pady=5)

        self.log_filter = ttk.Combobox(filter_frame,
                                     values=["All", "Info", "Warning", "Error"],
                                     state="readonly")
        self.log_filter.set("All")
        self.log_filter.pack(side="left", padx=5)
        self.log_filter.bind("<<ComboboxSelected>>", self.filter_logs)

        ttk.Button(filter_frame,
                  text="Clear Logs",
                  command=self.clear_logs).pack(side="right", padx=5)

    def _initialize_crypto(self):
        """Initialize cryptographic components"""
        try:
            (
                self.key_aes,
                self.key_des,
                self.key_tdes,
                self.private_key_rsa,
                self.public_key_rsa,
                self.private_key_ecc,
                self.public_key_ecc,
            ) = get_random_keys()
            
            self.methods, self.sequence_hash = get_random_sequence_from_csv()
            self.crypto_initialized = True
            self.log("Cryptography initialized successfully")
        except Exception as e:
            self.log(f"Failed to initialize cryptography: {e}", level="ERROR")
            self.crypto_initialized = False

    def start_server(self):
        """Start the server and listen for connections"""
        if not self.server_running:
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.bind(("127.0.0.1", 12345))
                self.server_socket.listen(5)
                self.server_running = True
                
                self.start_button.config(text="Stop Server", style="Stop.TButton")
                self.server_status.config(text="Server Status: Running")
                self.log("Server started successfully")
                
                # Start accepting connections in a separate thread
                threading.Thread(target=self.accept_connections, daemon=True).start()
            except Exception as e:
                self.log(f"Failed to start server: {e}", level="ERROR")
        else:
            self.stop_server()

    def stop_server(self):
        """Stop the server"""
        if self.server_running:
            try:
                self.server_socket.close()
                self.server_running = False
                self.start_button.config(text="Start Server", style="Start.TButton")
                self.server_status.config(text="Server Status: Stopped")
                self.log("Server stopped")
            except Exception as e:
                self.log(f"Error stopping server: {e}", level="ERROR")

    def accept_connections(self):
        """Accept incoming connections"""
        while self.server_running:
            try:
                conn, addr = self.server_socket.accept()
                self.log(f"New connection from {addr}")
                
                # Start a new thread to handle the client
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.server_running:
                    self.log(f"Connection error: {e}", level="ERROR")

    def handle_client(self, conn, addr):
        """Handle client connection"""
        try:
            # Send initial prompt
            conn.send("Enter Tank ID:".encode())
            
            # Receive tank ID
            tank_id = conn.recv(1024).decode().strip()
            self.log(f"Tank {tank_id} connected from {addr}")
            
            # Generate and send challenge
            challenge_msg, self.expected_answer = generate_challenge()
            conn.send(f"Challenge: {challenge_msg}".encode())
            self.log(f"Sent challenge to Tank {tank_id}")
            
            # Handle authentication
            self.handle_authentication(conn, tank_id, addr)
            
        except Exception as e:
            self.log(f"Error handling client {addr}: {e}", level="ERROR")
        finally:
            conn.close()

    def handle_authentication(self, conn, tank_id, addr):
        """Handle tank authentication process"""
        try:
            # Receive response
            response = conn.recv(1024).decode().strip()
            self.log(f"Received response from Tank {tank_id}: {response}")
            
            if response == self.expected_answer:
                conn.send("Authentication Successful".encode())
                self.log(f"Tank {tank_id} authenticated successfully")
                
                # Update GUI
                self.root.after(0, lambda: self.update_tank_status(tank_id, "online"))
                
                # Handle readiness check
                self.handle_readiness(conn, tank_id)
            else:
                conn.send("Authentication Failed".encode())
                self.log(f"Tank {tank_id} authentication failed")
                self.root.after(0, lambda: self.update_tank_status(tank_id, "offline"))
        
        except Exception as e:
            self.log(f"Authentication error for Tank {tank_id}: {e}", level="ERROR")

    def handle_readiness(self, conn, tank_id):
        """Handle tank readiness check"""
        try:
            conn.send("Are you ready?".encode())
            readiness = conn.recv(1024).decode().strip().lower()
            
            if readiness in ["yes", "ready", "ok"]:
                self.log(f"Tank {tank_id} is ready")
                self.handle_location_request(conn, tank_id)
            else:
                self.log(f"Tank {tank_id} is not ready")
        
        except Exception as e:
            self.log(f"Readiness check error for Tank {tank_id}: {e}", level="ERROR")

    def handle_location_request(self, conn, tank_id):
        """Handle tank location request and updates"""
        try:
            conn.send("Give me your location".encode())
            
            # Initialize buffer for receiving data
            buffer = ""
            
            while True:
                chunk = conn.recv(1024).decode()
                if not chunk:
                    break
                
                buffer += chunk
                
                # Check for message terminator
                if "\n" in buffer:
                    # Extract the complete message
                    message = buffer[:buffer.index("\n")]
                    
                    try:
                        # Parse the JSON payload
                        payload = json.loads(message)
                        logging.info(f"Received location payload from Tank {tank_id}")
                        
                        # Decrypt and process location
                        location = self.decrypt_location(payload, tank_id)
                        
                        if location:
                            # Send acknowledgment to client
                            conn.send("RECEIVED".encode())
                            
                            # Update tank location immediately
                            self.update_tank_location(tank_id, location)
                        else:
                            logging.error(f"Failed to decrypt location for Tank {tank_id}")
                            conn.send("ERROR".encode())
                            
                        # Clear buffer after processing
                        buffer = buffer[buffer.index("\n") + 1:]
                        
                    except json.JSONDecodeError as e:
                        logging.error(f"Invalid JSON payload from Tank {tank_id}: {str(e)}")
                        conn.send("ERROR".encode())
                    
            
        except Exception as e:
            logging.error(f"Location handling error for Tank {tank_id}: {str(e)}")
            try:
                conn.send("ERROR".encode())
            except:
                pass

    def decrypt_location(self, payload, tank_id):
        """Decrypt the location data"""
        try:
            # No need to parse JSON again since payload is already a dict
            logging.info(f"Received payload for Tank {tank_id}: {payload}")
            
            # Load keys based on the received index
            index = payload["random_index"]
            hash_value = payload["sequence_hash"]
            methods = find_sequence_by_hash(hash_value)
            
            if not methods:
                logging.error(f"Could not find encryption sequence for hash: {hash_value}")
                return None
                
            keys = get_keys_by_index(index)
            if not keys or len(keys) != 7:
                logging.error(f"Invalid keys retrieved for index: {index}")
                return None
                
            key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc = keys
            
            # Log decryption attempt
            logging.info(f"Attempting to decrypt data for Tank {tank_id} using methods: {methods}")
            
            decrypted_location = decrypt_data(
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
            
            # Verify signature
            is_valid = verify_signature(
                decrypted_location,
                payload["signature"],
                public_key_rsa
            )
            
            if not is_valid:
                logging.warning(f"Invalid signature from Tank {tank_id}")
                return None
                
            logging.info(f"Successfully decrypted location for Tank {tank_id}: {decrypted_location}")
            return decrypted_location
            
        except Exception as e:
            logging.error(f"Decryption error for Tank {tank_id}: {str(e)}")
            return None

    def update_tank_location(self, tank_id, location):
        """Update tank location on the map"""
        try:
            lat, lon = map(float, location.split(","))
            
            # Update map in the main thread
            self.root.after(0, lambda: self.update_map_marker(tank_id, lat, lon))
            self.log(f"Updated location for Tank {tank_id}: {location}")
            
        except ValueError:
            self.log(f"Invalid location format from Tank {tank_id}: {location}", level="ERROR")

    def update_map_marker(self, tank_id, lat, lon):
        """Update or create map marker for tank"""
        marker = self.map_widget.set_marker(
            lat, lon,
            text=f"Tank {tank_id}",
            command=lambda: self.show_tank_info(tank_id)
        )
        
        # Store marker reference
        self.connected_tanks[tank_id] = {
            "marker": marker,
            "position": (lat, lon)
        }

    def show_tank_info(self, tank_id):
        """Show tank information in a popup"""
        if tank_id in self.connected_tanks:
            tank_data = self.connected_tanks[tank_id]
            info = f"Tank ID: {tank_id}\n"
            info += f"Position: {tank_data['position']}\n"
            messagebox.showinfo("Tank Information", info)

    def update_tank_status(self, tank_id, status):
        """Update tank status in GUI lists"""
        # Remove from all lists first
        for lst in [self.available_tanks_list, self.online_tanks_list, self.offline_tanks_list]:
            for i in range(lst.size()):
                if tank_id in lst.get(i):
                    lst.delete(i)
                    break
        
        # Add to appropriate list
        if status == "online":
            self.online_tanks_list.insert(tk.END, f"Tank {tank_id} ✅")
        elif status == "offline":
            self.offline_tanks_list.insert(tk.END, f"Tank {tank_id} ❌")
        else:
            self.available_tanks_list.insert(tk.END, f"Tank {tank_id}")

    def reset_map_view(self):
        """Reset map to default view"""
        self.map_widget.set_position(17.385044, 78.486671)
        self.map_widget.set_zoom(10)

    def track_selected_tank(self):
        """Center map on selected tank"""
        selection = self.online_tanks_list.curselection()
        if selection:
            tank_id = self.online_tanks_list.get(selection[0]).split()[1]
            if tank_id in self.connected_tanks:
                lat, lon = self.connected_tanks[tank_id]["position"]
                self.map_widget.set_position(lat, lon)
                self.map_widget.set_zoom(15)

    def log(self, message, level="INFO"):
        """Add message to log area with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        self.log_area.insert(tk.END, log_entry)
        self.log_area.see(tk.END)
        
        # Also log to file
        logging.log(
            getattr(logging, level),
            message
        )

    def filter_logs(self, event=None):
        """Filter log messages based on selected level"""
        selected = self.log_filter.get()
        self.log_area.delete(1.0, tk.END)
        
        with open('secure_comm.log', 'r') as log_file:
            for line in log_file:
                if selected == "All" or selected.upper() in line:
                    self.log_area.insert(tk.END, line)

    def clear_logs(self):
        """Clear the log area"""
        self.log_area.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = CommanderGUI(root)
    root.mainloop()
