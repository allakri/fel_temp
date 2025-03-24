import socket
import logging
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from typing import Optional, Dict
from tkintermapview import TkinterMapView
import time
import json
import threading
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
        logging.FileHandler('tank_client.log'),
        logging.StreamHandler()
    ]
)

class TankClientGUI:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title(f"Tank Client - {username}")
        
        # Configure window
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)  # Set minimum window size
        
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
        self.last_encryption: Optional[Dict] = None
        self.crypto_initialized = False
        self.client_socket = None
        self.connection_retry_count = 0
        self.MAX_RETRIES = 5
        self.connected = False
        self.message_processing = False
        self.image_references = []  # Keep track of image references
        
        # Create main frames
        self.create_frames()
        self.create_widgets()
        self.setup_styles()
        
        # Initialize cryptographic components
        self._initialize_crypto()
        
        # Start connection attempt
        self.attempt_connection()

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

    def create_frames(self):
        """Create the main application frames"""
        # Top bar
        self.create_top_bar()
        
        # Left Panel
        self.left_frame = ttk.Frame(
            self.root,
            style="Card.TFrame",
            padding="10"
        )
        self.left_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Center Panel (Tabbed interface)
        self.center_frame = ttk.Frame(
            self.root,
            style="Card.TFrame",
            padding="10"
        )
        self.center_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.center_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Map tab
        self.map_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.map_tab, text="Map View")
        
        # Chat tab
        self.chat_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.chat_tab, text="Secure Chat")
        
        # Right Panel
        self.right_frame = ttk.Frame(
            self.root,
            style="Card.TFrame",
            padding="10"
        )
        self.right_frame.grid(row=1, column=2, sticky="nsew", padx=5, pady=5)

    def create_top_bar(self):
        """Create top bar with status and controls"""
        top_bar = ttk.Frame(self.root, style="Card.TFrame", padding="5")
        top_bar.grid(row=0, column=0, columnspan=3, sticky="ew")
        
        # Tank ID label
        tank_label = ttk.Label(
            top_bar,
            text=f"Tank ID: {self.username}",
            font=self.style['font_medium']
        )
        tank_label.pack(side="left", padx=10)
        
        # Connection status
        self.status_label = ttk.Label(
            top_bar,
            text="Status: Disconnected",
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

    def create_widgets(self):
        """Create all GUI widgets"""
        self.create_auth_widgets()
        self.create_map_widget()
        self.create_chat_widget()
        self.create_status_widgets()

    def create_auth_widgets(self):
        """Create authentication related widgets"""
        auth_frame = ttk.LabelFrame(
            self.left_frame,
            text="Authentication",
            padding="10"
        )
        auth_frame.pack(fill="x", pady=5)
        
        # Tank ID Entry
        ttk.Label(
            auth_frame,
            text="Tank ID:",
            font=self.style['font_small']
        ).pack(fill="x", pady=2)
        
        self.entry_tank_id = ttk.Entry(auth_frame)
        self.entry_tank_id.insert(0, self.username)
        self.entry_tank_id.config(state="disabled")
        self.entry_tank_id.pack(fill="x", pady=5)
        
        self.submit_tank_id = ttk.Button(
            auth_frame,
            text="Submit",
            style="Primary.TButton",
            command=self.send_tank_id
        )
        self.submit_tank_id.pack(fill="x", pady=5)
        
        # Challenge Response
        ttk.Label(
            auth_frame,
            text="Challenge Response:",
            font=self.style['font_small']
        ).pack(fill="x", pady=2)
        
        self.entry_response = ttk.Entry(auth_frame, state="disabled")
        self.entry_response.pack(fill="x", pady=5)
        
        self.submit_response = ttk.Button(
            auth_frame,
            text="Send Response",
            style="Primary.TButton",
            command=self.send_response,
            state="disabled"
        )
        self.submit_response.pack(fill="x", pady=5)
        
        # Location Entry
        ttk.Label(
            auth_frame,
            text="Location (lat,lon):",
            font=self.style['font_small']
        ).pack(fill="x", pady=2)
        
        self.entry_location = ttk.Entry(auth_frame, state="disabled")
        self.entry_location.pack(fill="x", pady=5)
        
        self.submit_location = ttk.Button(
            auth_frame,
            text="Send Location",
            style="Primary.TButton",
            command=self.send_location,
            state="disabled"
        )
        self.submit_location.pack(fill="x", pady=5)

    def create_map_widget(self):
        """Create the map widget with error handling"""
        map_frame = ttk.LabelFrame(
            self.map_tab,
            text="Map View",
            padding="10"
        )
        map_frame.pack(fill="both", expand=True)
        
        # Create map widget with error handler
        self.map_widget = TkinterMapView(
            map_frame,
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
        
        # Add map controls
        control_frame = ttk.Frame(map_frame)
        control_frame.pack(fill="x", pady=5)
        
        ttk.Button(
            control_frame,
            text="Reset View",
            style="Primary.TButton",
            command=self.reset_map_view
        ).pack(side="left", padx=5)
        
        ttk.Button(
            control_frame,
            text="Current Location",
            style="Primary.TButton",
            command=self.center_on_location
        ).pack(side="left", padx=5)

    def create_chat_widget(self):
        """Create the secure chat interface"""
        chat_frame = ttk.Frame(self.chat_tab)
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

    def create_status_widgets(self):
        """Create status and message widgets"""
        status_frame = ttk.LabelFrame(
            self.right_frame,
            text="Status & Messages",
            padding="10"
        )
        status_frame.pack(fill="both", expand=True)
        
        self.message_label = ttk.Label(
            status_frame,
            text="Waiting for connection...",
            wraplength=250,
            font=self.style['font_small']
        )
        self.message_label.pack(fill="x", pady=5)
        
        # Add log area
        self.log_area = scrolledtext.ScrolledText(
            status_frame,
            wrap=tk.WORD,
            height=10,
            font=("Consolas", 9),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        self.log_area.pack(fill="both", expand=True, pady=5)

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
            logging.info("Cryptography initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize cryptography: {e}")
            self.crypto_initialized = False

    def attempt_connection(self):
        """Attempt to connect to the server with retry mechanism"""
        if self.connection_retry_count >= self.MAX_RETRIES:
            self.message_label.config(
                text="Failed to connect to server. Please restart the application."
            )
            self.progress.stop()
            return
        
        try:
            self.progress.start()
            if self.client_socket:
                self.client_socket.close()
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(("localhost", 12345))
            self.connected = True
            
            self.progress.stop()
            self.status_label.config(text="Status: Connected")
            self.message_label.config(text="Connected to server successfully!")
            
            # Start message receiver
            self.start_message_receiver()
            self.receive_initial_message()
            
        except ConnectionRefusedError:
            self.connected = False
            self.connection_retry_count += 1
            self.status_label.config(text="Status: Connecting...")
            self.message_label.config(
                text=f"Connection attempt {self.connection_retry_count}/{self.MAX_RETRIES}. Retrying..."
            )
            self.root.after(2000, self.attempt_connection)
            
        except Exception as e:
            self.connected = False
            self.status_label.config(text="Status: Error")
            self.message_label.config(text=f"Connection error: {str(e)}")
            self.progress.stop()

    def receive_initial_message(self):
        """Receive and handle initial server message"""
        try:
            message = self.client_socket.recv(1024).decode()
            self.message_label.config(text=message)
            self.log_message("Server", message)
        except Exception as e:
            self.log_message("Error", f"Error receiving message: {str(e)}")

    def send_tank_id(self):
        """Send tank ID to server"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        tank_id = self.entry_tank_id.get()
        if tank_id:
            try:
                self.client_socket.send(tank_id.encode())
                self.entry_tank_id.config(state="disabled")
                self.submit_tank_id.config(state="disabled")
                self.receive_challenge()
            except Exception as e:
                self.message_label.config(text=f"Error sending Tank ID: {str(e)}")
                self.connected = False
                self.attempt_connection()
        else:
            messagebox.showwarning("Input Required", "Please enter a Tank ID.")

    def receive_challenge(self):
        """Receive and handle authentication challenge"""
        try:
            challenge_msg = self.client_socket.recv(1024).decode()
            self.message_label.config(text=challenge_msg)
            self.log_message("Server", challenge_msg)
            
            challenge_parts = challenge_msg.split(":")[-1].strip().split()
            challenge = int(challenge_parts[0])
            random_number = int(challenge_parts[1]) if len(challenge_parts) > 1 else None
            
            response = self.compute_response(challenge, random_number)
            
            self.entry_response.config(state="normal")
            self.entry_response.insert(0, response)
            self.submit_response.config(state="normal")
            
        except Exception as e:
            self.log_message("Error", f"Error receiving challenge: {str(e)}")

    def compute_response(self, challenge, random_number):
        """Compute response to authentication challenge"""
        if challenge == 0:
            return "OK"
        elif challenge == 1:
            return str(random_number ** 2)
        elif challenge == 2:
            return str(random_number ** 3)
        elif challenge == 3:
            return str(random_number * (random_number + 1) // 2)
        elif challenge == 4:
            return str(random_number % 2 == 0)
        elif challenge == 5:
            return str(random_number % 2 != 0)
        elif challenge == 6:
            return str(random_number * 2)
        elif challenge == 7:
            return "Prime" if all(random_number % i != 0 for i in range(2, int(random_number ** 0.5) + 1)) and random_number > 1 else "Not Prime"
        elif challenge == 8:
            return "".join(reversed(str(random_number)))
        elif challenge == 9:
            return str(len(bin(random_number)) - 2)
        else:
            return "Unknown"

    def send_response(self):
        """Send challenge response to server"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        response = self.entry_response.get()
        if response:
            try:
                self.client_socket.send(response.encode())
                self.entry_response.config(state="disabled")
                self.submit_response.config(state="disabled")
                self.receive_authentication()
            except Exception as e:
                self.message_label.config(text=f"Error sending response: {str(e)}")
                self.connected = False
                self.attempt_connection()
        else:
            messagebox.showwarning("Input Required", "Please enter a response.")

    def receive_authentication(self):
        """Handle authentication response"""
        try:
            auth_response = self.client_socket.recv(1024).decode()
            self.message_label.config(text=auth_response)
            self.log_message("Server", auth_response)
            
            if auth_response == "Authentication Successful":
                readiness_prompt = self.client_socket.recv(1024).decode()
                self.message_label.config(text=readiness_prompt)
                self.log_message("Server", readiness_prompt)
                
                readiness_response = messagebox.askquestion("Readiness", "Are you ready?")
                if readiness_response == "yes":
                    self.client_socket.send("yes".encode())
                    self.receive_location_request()
                else:
                    self.client_socket.send("no".encode())
            
        except Exception as e:
            self.log_message("Error", f"Authentication error: {str(e)}")

    def receive_location_request(self):
        """Handle location request from server"""
        try:
            location_request = self.client_socket.recv(1024).decode()
            self.message_label.config(text=location_request)
            self.log_message("Server", location_request)
            
            self.entry_location.config(state="normal")
            self.submit_location.config(state="normal")
            
        except Exception as e:
            self.log_message("Error", f"Error receiving location request: {str(e)}")

    def send_encrypted_message(self):
        """Send encrypted message to commander"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        message = self.message_input.get().strip()
        if not message:
            return
        
        try:
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
                "sender": "tank"
            }
            
            # Send encrypted message
            json_payload = json.dumps(payload)
            self.client_socket.send(f"{json_payload}\n".encode())
            
            # Add message to chat display
            self.add_chat_message("You", message)
            
            # Clear input field
            self.message_input.delete(0, tk.END)
            
        except Exception as e:
            self.log_message("Error", f"Error sending message: {str(e)}")

    def send_location(self):
        """Send encrypted location to commander"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        location = self.entry_location.get()
        if location:
            try:
                # Get new encryption sequence for this location update
                methods, sequence_hash = get_random_sequence_from_csv()
                
                # Encrypt the location
                signature = generate_signature(location, self.private_key_rsa)
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
                json_payload = json.dumps(payload)
                self.client_socket.send(f"{json_payload}\n".encode())
                
                # Wait for acknowledgment
                ack = self.client_socket.recv(1024).decode()
                if ack == "RECEIVED":
                    # Update map if valid coordinates
                    try:
                        lat, lon = map(float, location.split(","))
                        self.update_map_marker(lat, lon)
                        self.message_label.config(text="Location sent successfully!")
                        self.log_message("Info", "Location updated successfully")
                    except ValueError:
                        messagebox.showerror(
                            "Error",
                            "Invalid location format. Use 'latitude,longitude'"
                        )
                    
                    # Clear the location entry field
                    self.entry_location.delete(0, tk.END)
                else:
                    self.message_label.config(
                        text="Server did not acknowledge the location data"
                    )
                
            except Exception as e:
                self.log_message("Error", f"Error sending location: {str(e)}")
                self.connected = False
                self.attempt_connection()
        else:
            messagebox.showwarning("Input Required", "Please enter your location.")

    def update_map_marker(self, lat, lon):
        """Update tank marker on map"""
        try:
            # Create marker image
            marker_image = PIL.Image.new('RGBA', (32, 32), (0, 0, 0, 0))
            draw = PIL.ImageDraw.Draw(marker_image)
            draw.polygon([(16, 0), (32, 32), (0, 32)], fill='blue')
            
            # Convert to PhotoImage and keep reference
            marker_photo = PIL.ImageTk.PhotoImage(marker_image)
            self.image_references.append(marker_photo)
            
            # Update map
            self.map_widget.delete_all_marker()
            self.map_widget.set_marker(
                lat, lon,
                text=f"Tank {self.username}",
                image=marker_photo
            )
            self.map_widget.set_position(lat, lon)
            self.map_widget.set_zoom(15)
            
        except Exception as e:
            self.log_message("Error", f"Error updating map marker: {str(e)}")

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
            self.log_message("Error", f"Error creating error tile: {str(e)}")
            return None

    def reset_map_view(self):
        """Reset map to default view"""
        self.map_widget.set_position(17.385044, 78.486671)
        self.map_widget.set_zoom(10)

    def center_on_location(self):
        """Center map on current location"""
        location = self.entry_location.get()
        if location:
            try:
                lat, lon = map(float, location.split(","))
                self.map_widget.set_position(lat, lon)
                self.map_widget.set_zoom(15)
            except ValueError:
                messagebox.showerror(
                    "Error",
                    "Invalid location format. Use 'latitude,longitude'"
                )

    def start_message_receiver(self):
        """Start a thread to receive messages"""
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        """Receive and process incoming messages"""
        while self.connected and not self.message_processing:
            try:
                self.message_processing = True
                message = ""
                while True:
                    chunk = self.client_socket.recv(1024).decode()
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    
                    message += chunk
                    if "\n" in message:
                        break
                
                # Process complete message
                payload = json.loads(message[:message.index("\n")])
                
                if payload.get("type") == "chat":
                    # Decrypt and display chat message
                    decrypted_message = self.decrypt_message(payload)
                    if decrypted_message:
                        self.root.after(
                            0,
                            lambda: self.add_chat_message("Commander", decrypted_message)
                        )
                
            except json.JSONDecodeError as e:
                self.root.after(
                    0,
                    lambda: self.log_message("Error", f"Invalid message format: {str(e)}")
                )
            except ConnectionError:
                self.connected = False
                self.root.after(0, self.attempt_connection)
                break
            except Exception as e:
                self.root.after(
                    0,
                    lambda: self.log_message("Error", f"Error receiving message: {str(e)}")
                )
            finally:
                self.message_processing = False

    def decrypt_message(self, payload):
        """Decrypt message from commander"""
        try:
            # Load keys based on the received index
            index = payload["random_index"]
            hash_value = payload["sequence_hash"]
            methods = find_sequence_by_hash(hash_value)
            
            if not methods:
                self.log_message(
                    "Error",
                    f"Could not find encryption sequence for hash: {hash_value}"
                )
                return None
            
            keys = get_keys_by_index(index)
            if not keys or len(keys) != 7:
                self.log_message(
                    "Error",
                    f"Invalid keys retrieved for index: {index}"
                )
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
                self.log_message("Warning", "Invalid message signature")
                return None
            
            return decrypted_message
            
        except Exception as e:
            self.log_message("Error", f"Message decryption error: {str(e)}")
            return None

    def add_chat_message(self, sender, message):
        """Add message to chat display"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
        self.chat_display.see(tk.END)
        self.log_message("Chat", f"{sender}: {message}")

    def log_message(self, category, message):
        """Add message to log area"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {category}: {message}\n"
        self.log_area.insert(tk.END, log_entry)
        self.log_area.see(tk.END)

    def logout(self):
        """Handle logout"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
            self.root.destroy()

    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = TankClientGUI(root, "tank1")
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()