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
import PIL.Image
import PIL.ImageDraw
import PIL.ImageTk

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
        
        # Configure window
        self.root.geometry("1400x800")
        self.root.minsize(1000, 600)  # Set minimum window size
        
        # Configure colors
        self.colors = {
            'primary': '#2196F3',
            'success': '#4CAF50',
            'error': '#f44336',
            'warning': '#ff9800',
            'background': '#f5f5f5',
            'card': '#ffffff',
            'text': '#333333',
            'border': '#e0e0e0'
        }
        
        # Configure styles
        self.style = {
            'font_large': ('Arial', 16, 'bold'),
            'font_medium': ('Arial', 12, 'bold'),
            'font_small': ('Arial', 10),
            'padding': 20
        }
        
        # Configure grid weights for responsive layout
        self.root.grid_rowconfigure(0, weight=0)  # Top bar
        self.root.grid_rowconfigure(1, weight=1)  # Main content
        self.root.grid_columnconfigure(0, weight=1)  # Left panel
        self.root.grid_columnconfigure(1, weight=3)  # Center panel
        self.root.grid_columnconfigure(2, weight=1)  # Right panel
        
        # Initialize variables
        self.server_socket = None
        self.client_conn = None
        self.client_addr = None
        self.challenge = None
        self.expected_answer = None
        self.connected_tanks = {}
        self.server_running = False
        self.selected_tank = None
        self.message_processing = False
        self.image_references = []  # Keep track of image references
        
        # Initialize default available tanks
        self.default_tanks = [f"Tk{i}" for i in range(1, 13)]
        
        # Initialize crypto components
        self.last_encryption: Optional[Dict] = None
        self.crypto_initialized = False
        
        # Create main layout
        self.create_layout()
        self.setup_styles()
        
        # Initialize crypto after GUI elements are created
        self._initialize_crypto()
        
        # Add default tanks to available list
        self.populate_default_tanks()

    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        
        # Configure frame styles
        style.configure(
            "Card.TFrame",
            background=self.colors['card']
        )
        
        # Configure label styles
        style.configure(
            "Header.TLabel",
            font=self.style['font_medium'],
            padding=5
        )
        
        # Configure button styles
        style.configure(
            "Primary.TButton",
            font=self.style['font_small'],
            padding=5
        )
        
        style.configure(
            "Success.TButton",
            font=self.style['font_small'],
            padding=5,
            background=self.colors['success']
        )

    def create_layout(self):
        """Create the main application layout"""
        # Create top bar
        self.create_top_bar()
        
        # Left Panel - Tank Management
        self.left_panel = ttk.Frame(
            self.root,
            style="Card.TFrame",
            padding="10"
        )
        self.left_panel.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.create_tank_management_section()
        
        # Center Panel - Tabbed Interface
        self.center_panel = ttk.Frame(
            self.root,
            style="Card.TFrame",
            padding="10"
        )
        self.center_panel.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.center_panel)
        self.notebook.pack(fill="both", expand=True)
        
        # Map tab
        self.map_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.map_tab, text="Map View")
        self.create_map_section(self.map_tab)
        
        # Chat tab
        self.chat_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.chat_tab, text="Secure Chat")
        self.create_chat_section(self.chat_tab)
        
        # Right Panel - Logs and Controls
        self.right_panel = ttk.Frame(
            self.root,
            style="Card.TFrame",
            padding="10"
        )
        self.right_panel.grid(row=1, column=2, sticky="nsew", padx=5, pady=5)
        self.create_control_section()

    def create_top_bar(self):
        """Create top bar with status and controls"""
        top_bar = ttk.Frame(self.root, style="Card.TFrame", padding="5")
        top_bar.grid(row=0, column=0, columnspan=3, sticky="ew")
        
        # Title
        title_label = ttk.Label(
            top_bar,
            text="Commander Control Center",
            font=self.style['font_large']
        )
        title_label.pack(side="left", padx=10)
        
        # Server status
        self.status_label = ttk.Label(
            top_bar,
            text="Server Status: Stopped",
            font=self.style['font_small']
        )
        self.status_label.pack(side="left", padx=20)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            top_bar,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side="left", padx=10)
        
        # Logout button
        self.logout_button = ttk.Button(
            top_bar,
            text="Logout",
            style="Primary.TButton",
            command=self.logout
        )
        self.logout_button.pack(side="right", padx=10)

    def create_tank_management_section(self):
        """Create the tank management section"""
        # Header
        ttk.Label(
            self.left_panel,
            text="Tank Management",
            style="Header.TLabel"
        ).pack(fill="x", pady=(0, 10))
        
        # Available Tanks
        tank_frame = ttk.LabelFrame(
            self.left_panel,
            text="Available Tanks",
            padding="5"
        )
        tank_frame.pack(fill="x", expand=True, pady=5)
        
        self.available_tanks_list = tk.Listbox(
            tank_frame,
            height=8,
            selectmode=tk.SINGLE,
            font=self.style['font_small'],
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        self.available_tanks_list.pack(fill="both", expand=True, pady=5)
        self.available_tanks_list.bind('<<ListboxSelect>>', self.on_tank_selected)
        
        # Online Tanks
        online_frame = ttk.LabelFrame(
            self.left_panel,
            text="Online Tanks",
            padding="5"
        )
        online_frame.pack(fill="x", expand=True, pady=5)
        
        self.online_tanks_list = tk.Listbox(
            online_frame,
            height=6,
            selectmode=tk.SINGLE,
            font=self.style['font_small'],
            bg=self.colors['success'],
            fg='white'
        )
        self.online_tanks_list.pack(fill="both", expand=True, pady=5)
        self.online_tanks_list.bind('<<ListboxSelect>>', self.on_tank_selected)
        
        # Offline Tanks
        offline_frame = ttk.LabelFrame(
            self.left_panel,
            text="Offline Tanks",
            padding="5"
        )
        offline_frame.pack(fill="x", expand=True, pady=5)
        
        self.offline_tanks_list = tk.Listbox(
            offline_frame,
            height=6,
            selectmode=tk.SINGLE,
            font=self.style['font_small'],
            bg=self.colors['error'],
            fg='white'
        )
        self.offline_tanks_list.pack(fill="both", expand=True, pady=5)

    def create_map_section(self, parent):
        """Create the map section with error handling"""
        # Map Container
        map_container = ttk.LabelFrame(
            parent,
            text="Tactical Map",
            padding="10"
        )
        map_container.pack(fill="both", expand=True)
        
        # Map Widget
        self.map_widget = TkinterMapView(
            map_container,
            width=800,
            height=600,
            corner_radius=0
        )
        self.map_widget.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Set initial position and zoom
        self.map_widget.set_position(17.385044, 78.486671)
        self.map_widget.set_zoom(10)
        
        # Configure error handler
        self.map_widget.set_tile_server(
            "https://mt0.google.com/vt/lyrs=m&hl=en&x={x}&y={y}&z={z}",
            max_zoom=22
        )
        
        # Map Controls
        controls_frame = ttk.Frame(map_container)
        controls_frame.pack(fill="x", pady=5)
        
        ttk.Button(
            controls_frame,
            text="Reset View",
            style="Primary.TButton",
            command=self.reset_map_view
        ).pack(side="left", padx=5)
        
        ttk.Button(
            controls_frame,
            text="Track Selected Tank",
            style="Primary.TButton",
            command=self.track_selected_tank
        ).pack(side="left", padx=5)

    def create_chat_section(self, parent):
        """Create the chat interface"""
        chat_frame = ttk.Frame(parent)
        chat_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Chat display
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            height=20,
            font=("Consolas", 10),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        self.chat_display.pack(fill="both", expand=True, pady=5)
        
        # Message input frame
        input_frame = ttk.Frame(chat_frame)
        input_frame.pack(fill="x", pady=5)
        
        self.message_input = ttk.Entry(
            input_frame,
            font=self.style['font_small']
        )
        self.message_input.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        send_button = ttk.Button(
            input_frame,
            text="Send",
            style="Primary.TButton",
            command=self.send_encrypted_message
        )
        send_button.pack(side="right")
        
        # Bind Enter key
        self.message_input.bind("<Return>", lambda e: self.send_encrypted_message())

    def create_control_section(self):
        """Create the control section"""
        # Server Controls
        control_frame = ttk.LabelFrame(
            self.right_panel,
            text="Server Controls",
            padding="10"
        )
        control_frame.pack(fill="x", pady=5)
        
        self.start_button = ttk.Button(
            control_frame,
            text="Start Server",
            style="Primary.TButton",
            command=self.start_server
        )
        self.start_button.pack(fill="x", pady=5)
        
        # Log Section
        log_frame = ttk.LabelFrame(
            self.right_panel,
            text="Server Logs",
            padding="10"
        )
        log_frame.pack(fill="both", expand=True, pady=5)
        
        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        self.log_area.pack(fill="both", expand=True)
        
        # Add log filters
        filter_frame = ttk.Frame(log_frame)
        filter_frame.pack(fill="x", pady=5)
        
        self.log_filter = ttk.Combobox(
            filter_frame,
            values=["All", "Info", "Warning", "Error"],
            state="readonly"
        )
        self.log_filter.set("All")
        self.log_filter.pack(side="left", padx=5)
        self.log_filter.bind("<<ComboboxSelected>>", self.filter_logs)
        
        ttk.Button(
            filter_frame,
            text="Clear Logs",
            command=self.clear_logs,
            style="Primary.TButton"
        ).pack(side="right", padx=5)

    def populate_default_tanks(self):
        """Add default tanks to the available tanks list"""
        for tank_id in self.default_tanks:
            self.available_tanks_list.insert(tk.END, f"Tank {tank_id}")

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
            self.log(f"Failed to initialize cryptography: {e}", level="ERROR")
            self.crypto_initialized = False

    def start_server(self):
        """Start the server and listen for connections"""
        if not self.server_running:
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.bind(("localhost", 12345))
                self.server_socket.listen(5)
                self.server_running = True
                
                self.start_button.config(text="Stop Server")
                self.status_label.config(text="Server Status: Running")
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
                self.start_button.config(text="Start Server")
                self.status_label.config(text="Server Status: Stopped")
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
                messagebox.showinfo("Authentication", f"Tank {tank_id} authenticated successfully!")
                self.log(f"Tank {tank_id} authenticated successfully")
                
                # Store connection in tank data
                if tank_id not in self.connected_tanks:
                    self.connected_tanks[tank_id] = {}
                self.connected_tanks[tank_id]["connection"] = conn
                
                # Update GUI
                self.root.after(0, lambda: self.update_tank_status(tank_id, "online"))
                
                # Handle readiness check
                self.handle_readiness(conn, tank_id)
            else:
                conn.send("Authentication Failed".encode())
                messagebox.showerror("Authentication", f"Tank {tank_id} authentication failed!")
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
                self.handle_tank_communication(conn, tank_id)
            else:
                self.log(f"Tank {tank_id} is not ready")
        
        except Exception as e:
            self.log(f"Readiness check error for Tank {tank_id}: {e}", level="ERROR")

    def handle_tank_communication(self, conn, tank_id):
        """Handle ongoing communication with tank"""
        conn.send("Give me your location".encode())
        
        while True:
            try:
                # Initialize buffer for receiving data
                buffer = ""
                
                while True:
                    chunk = conn.recv(1024).decode()
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    
                    buffer += chunk
                    if "\n" in buffer:
                        # Extract the complete message
                        message = buffer[:buffer.index("\n")]
                        buffer = buffer[buffer.index("\n") + 1:]
                        
                        # Parse and process the message
                        payload = json.loads(message)
                        
                        if payload.get("type") == "location":
                            self.handle_location_update(payload, tank_id, conn)
                        elif payload.get("type") == "chat":
                            self.handle_chat_message(payload, tank_id)
                
            except json.JSONDecodeError as e:
                self.log(f"Invalid message format from Tank {tank_id}: {str(e)}", level="ERROR")
            except ConnectionError:
                self.log(f"Tank {tank_id} disconnected", level="WARNING")
                self.root.after(0, lambda: self.update_tank_status(tank_id, "offline"))
                break
            except Exception as e:
                self.log(f"Error handling tank communication: {str(e)}", level="ERROR")
                break

    def handle_location_update(self, payload, tank_id, conn):
        """Handle location update from tank"""
        try:
            # Decrypt location
            location = self.decrypt_message(payload)
            if location:
                # Send acknowledgment
                conn.send("RECEIVED".encode())
                
                # Update tank location
                try:
                    lat, lon = map(float, location.split(","))
                    self.update_tank_marker(tank_id, lat, lon)
                    self.log(f"Updated location for Tank {tank_id}: {location}")
                except ValueError:
                    self.log(f"Invalid location format from Tank {tank_id}: {location}", level="ERROR")
                
                # Show notification
                messagebox.showinfo("Location Update", f"Received new location from Tank {tank_id}")
            else:
                conn.send("ERROR".encode())
        except Exception as e:
            self.log(f"Error handling location update: {str(e)}", level="ERROR")
            conn.send("ERROR".encode())

    def handle_chat_message(self, payload, tank_id):
        """Handle chat message from tank"""
        try:
            # Decrypt message
            message = self.decrypt_message(payload)
            if message:
                # Add message to chat display
                self.root.after(0, lambda: self.add_chat_message(f"Tank {tank_id}", message))
                # Show notification
                messagebox.showinfo("New Message", f"Received message from Tank {tank_id}")
        except Exception as e:
            self.log(f"Error handling chat message: {str(e)}", level="ERROR")

    def decrypt_message(self, payload):
        """Decrypt message from tank"""
        try:
            # Load keys based on the received index
            index = payload["random_index"]
            hash_value = payload["sequence_hash"]
            methods = find_sequence_by_hash(hash_value)
            
            if not methods:
                self.log(f"Could not find encryption sequence for hash: {hash_value}", level="ERROR")
                return None
            
            keys = get_keys_by_index(index)
            if not keys or len(keys) != 7:
                self.log(f"Invalid keys retrieved for index: {index}", level="ERROR")
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
            
            # Verify signature
            is_valid = verify_signature(
                decrypted_message,
                payload["signature"],
                public_key_rsa
            )
            
            if not is_valid:
                self.log("Invalid message signature", level="WARNING")
                return None
            
            return decrypted_message
            
        except Exception as e:
            self.log(f"Message decryption error: {str(e)}", level="ERROR")
            return None

    def send_encrypted_message(self):
        """Send encrypted message to selected tank"""
        if not self.selected_tank or self.selected_tank not in self.connected_tanks:
            messagebox.showwarning("Warning", "Please select an online tank first")
            return
        
        message = self.message_input.get().strip()
        if not message:
            return
        
        try:
            tank_conn = self.connected_tanks[self.selected_tank].get("connection")
            if not tank_conn:
                messagebox.showerror("Error", "Tank connection not found")
                return
            
            # Get new encryption sequence for this message
            methods, sequence_hash = get_random_sequence_from_csv()
            
            # Encrypt the message
            signature = generate_signature(message, self.private_key_rsa)
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
                "sender": "commander"
            }
            
            # Send encrypted message
            json_payload = json.dumps(payload)
            tank_conn.send(f"{json_payload}\n".encode())
            
            # Add message to chat display
            self.add_chat_message("You", message)
            
            # Clear input field
            self.message_input.delete(0, tk.END)
            
        except Exception as e:
            self.log(f"Error sending message: {str(e)}", level="ERROR")

    def update_tank_marker(self, tank_id, lat, lon):
        """Update tank marker on map"""
        try:
            if tank_id not in self.connected_tanks:
                self.connected_tanks[tank_id] = {}
            
            # Create marker image
            marker_image = PIL.Image.new('RGBA', (32, 32), (0, 0, 0, 0))
            draw = PIL.ImageDraw.Draw(marker_image)
            draw.polygon([(16, 0), (32, 32), (0, 32)], fill='red')
            
            # Convert to PhotoImage and keep reference
            marker_photo = PIL.ImageTk.PhotoImage(marker_image)
            self.image_references.append(marker_photo)
            
            # Update map
            if "marker" in self.connected_tanks[tank_id]:
                self.map_widget.delete(self.connected_tanks[tank_id]["marker"])
            
            marker = self.map_widget.set_marker(
                lat, lon,
                text=f"Tank {tank_id}",
                image=marker_photo,
                command=lambda tank=tank_id: self.show_tank_info(tank)
            )
            
            # Store marker and position
            self.connected_tanks[tank_id].update({
                "marker": marker,
                "position": (lat, lon)
            })
            
        except Exception as e:
            self.log(f"Error updating map marker: {str(e)}", level="ERROR")

    def handle_map_error(self, error_tile):
        """Handle map tile loading errors"""
        try:
            # Create a default tile image
            img = PIL.Image.new('RGB', (256, 256), color='lightgray')
            draw = PIL.ImageDraw.Draw(img)
            draw.text((128, 128), "Map Unavailable", fill='black', anchor='center')
            error_image = PIL.ImageTk.PhotoImage(img)
            
            # Keep a reference to prevent garbage collection
            self.image_references.append(error_image)
            
            return error_image
            
        except Exception as e:
            self.log(f"Error creating error tile: {str(e)}", level="ERROR")
            return None

    def show_tank_info(self, tank_id):
        """Show tank information in a popup"""
        if tank_id in self.connected_tanks:
            tank_data = self.connected_tanks[tank_id]
            info = f"Tank ID: {tank_id}\n"
            if "position" in tank_data:
                lat, lon = tank_data["position"]
                info += f"Position: {lat:.6f}, {lon:.6f}\n"
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
            # Remove from connected tanks if present
            if tank_id in self.connected_tanks:
                if "marker" in self.connected_tanks[tank_id]:
                    self.map_widget.delete(self.connected_tanks[tank_id]["marker"])
                del self.connected_tanks[tank_id]
        else:
            self.available_tanks_list.insert(tk.END, f"Tank {tank_id}")

    def on_tank_selected(self, event):
        """Handle tank selection from lists"""
        widget = event.widget
        selection = widget.curselection()
        if selection:
            tank_text = widget.get(selection[0])
            tank_id = tank_text.split()[1]  # Extract tank ID from "Tank {id}"
            self.selected_tank = tank_id
            self.update_chat_display()

    def update_chat_display(self):
        """Update chat display when tank is selected"""
        if self.selected_tank:
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.insert(tk.END, f"Chat with Tank {self.selected_tank}\n")
            self.chat_display.insert(tk.END, "-" * 50 + "\n")

    def add_chat_message(self, sender, message):
        """Add message to chat display"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
        self.chat_display.see(tk.END)
        self.log(f"Chat - {sender}: {message}")

    def reset_map_view(self):
        """Reset map to default view"""
        self.map_widget.set_position(17.385044, 78.486671)
        self.map_widget.set_zoom(10)

    def track_selected_tank(self):
        """Center map on selected tank"""
        if self.selected_tank and self.selected_tank in self.connected_tanks:
            tank_data = self.connected_tanks[self.selected_tank]
            if "position" in tank_data:
                lat, lon = tank_data["position"]
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

    def logout(self):
        """Handle logout"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
            self.root.destroy()

    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CommanderGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()