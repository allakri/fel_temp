import socket
import logging
import tkinter as tk
from tkinter import Toplevel, messagebox, ttk, scrolledtext
from typing import Optional, Dict
from tkintermapview import TkinterMapView, OfflineLoader
import time
import json
import base64
import threading
import os

# Import cryptographic modules
from key_loader import get_random_keys, get_keys_by_index
from encryption import encrypt_data
from decryption import decrypt_data
from digital_signature import generate_signature, verify_signature
from quantum_generator import get_random_sequence_from_csv

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('client_secure_comm.log'),
        logging.StreamHandler()
    ]
)

class TankClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Tank Authentication System")
        self.root.geometry("1200x800")
        
        # Configure grid weight
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # Initialize class variables
        self.last_encryption: Optional[Dict] = None
        self.crypto_initialized = False
        self.client_socket = None
        self.connection_retry_count = 0
        self.MAX_RETRIES = 5
        self.connected = False
        self.tank_id = None
        self.chat_messages = []
        self.message_receiver_thread = None
        self.running = True

        # Create main frames
        self.create_frames()
        self.create_widgets()
        
        # Initialize offline map loader
        self.init_offline_maps()
        
        # Initialize cryptographic components
        self._initialize_crypto()

        # Start connection attempt
        self.attempt_connection()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def init_offline_maps(self):
        """Initialize offline map loader"""
        # Create maps directory if it doesn't exist
        if not os.path.exists("offline_maps"):
            os.makedirs("offline_maps")

        # Initialize offline loader
        self.offline_loader = OfflineLoader(tile_path="offline_maps")
        
        # Download map region for offline use (adjust coordinates as needed)
        self.offline_loader.download_region(
            top_left_position=(17.4850, 78.3867),
            bottom_right_position=(17.2850, 78.5867),
            zoom_levels=[5, 6, 7, 8, 9, 10, 11, 12]
        )

    def create_frames(self):
        # Left Panel
        self.left_frame = ttk.Frame(self.root, padding="10")
        self.left_frame.grid(row=0, column=0, sticky="nsew")

        # Center Panel (Tabbed Interface)
        self.center_frame = ttk.Frame(self.root, padding="10")
        self.center_frame.grid(row=0, column=1, sticky="nsew")

        # Right Panel
        self.right_frame = ttk.Frame(self.root, padding="10")
        self.right_frame.grid(row=0, column=2, sticky="nsew")

        # Style configuration
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("Custom.TButton", padding=10, font=('Arial', 10))
        style.configure("TNotebook", background="#f0f0f0")
        style.configure("TNotebook.Tab", padding=[10, 5], font=("Arial", 10))

    def create_widgets(self):
        # Left Panel Widgets
        self.create_auth_widgets()
        
        # Center Panel (Tabbed Interface)
        self.create_tabbed_interface()
        
        # Right Panel Widgets
        self.create_status_widgets()

    def create_tabbed_interface(self):
        """Create tabbed interface for map and chat"""
        self.tab_control = ttk.Notebook(self.center_frame)
        
        # Map Tab
        self.map_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.map_tab, text="Map View")
        self.create_map_widget()
        
        # Chat Tab
        self.chat_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.chat_tab, text="Communication")
        self.create_chat_widget()
        
        self.tab_control.pack(expand=True, fill="both")

    def create_map_widget(self):
        """Create the map interface with offline support"""
        # Map Frame
        map_frame = ttk.Frame(self.map_tab, padding="10")
        map_frame.pack(fill="both", expand=True)

        # Initialize map widget with offline loader
        self.map_widget = TkinterMapView(
            map_frame, 
            width=600, 
            height=400, 
            corner_radius=0,
            use_database_only=True,  # Use only offline tiles
            max_zoom=15,
            database_path="offline_maps"
        )
        self.map_widget.pack(fill="both", expand=True, padx=5, pady=5)
        self.map_widget.set_position(17.3850, 78.4867)  # Default location
        self.map_widget.set_zoom(10)

        # Map controls
        controls_frame = ttk.Frame(map_frame)
        controls_frame.pack(fill="x", pady=5)

        ttk.Button(
            controls_frame,
            text="Reset View",
            command=self.reset_map_view,
            style="Custom.TButton"
        ).pack(side="left", padx=5)

        ttk.Button(
            controls_frame,
            text="Use Current Location",
            command=self.use_current_location,
            style="Custom.TButton"
        ).pack(side="left", padx=5)

    def create_chat_widget(self):
        """Create the chat interface"""
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(
            self.chat_tab,
            wrap=tk.WORD,
            font=("Arial", 10),
            height=20
        )
        self.chat_display.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Message input area
        input_frame = ttk.Frame(self.chat_tab)
        input_frame.pack(fill="x", padx=5, pady=5)
        
        self.message_input = ttk.Entry(input_frame, font=("Arial", 10))
        self.message_input.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        send_button = ttk.Button(
            input_frame,
            text="Send",
            command=self.send_message,
            style="Custom.TButton"
        )
        send_button.pack(side="right")

    def create_auth_widgets(self):
        # Authentication Frame
        auth_frame = ttk.LabelFrame(self.left_frame, text="Authentication", padding="10")
        auth_frame.pack(fill="x", pady=5)

        # Tank ID Entry
        ttk.Label(auth_frame, text="Enter Tank ID:").pack(fill="x", pady=2)
        self.entry_tank_id = ttk.Entry(auth_frame)
        self.entry_tank_id.pack(fill="x", pady=5)

        self.submit_tank_id = ttk.Button(
            auth_frame,
            text="Submit",
            command=self.send_tank_id,
            style="Custom.TButton"
        )
        self.submit_tank_id.pack(fill="x", pady=5)

        # Response widgets
        ttk.Label(auth_frame, text="Challenge Response:").pack(fill="x", pady=2)
        self.entry_response = ttk.Entry(auth_frame, state="disabled")
        self.entry_response.pack(fill="x", pady=5)

        self.submit_response = ttk.Button(
            auth_frame,
            text="Send Response",
            command=self.send_response,
            state="disabled",
            style="Custom.TButton"
        )
        self.submit_response.pack(fill="x", pady=5)

        # Location Entry
        ttk.Label(auth_frame, text="Location (lat,lon):").pack(fill="x", pady=2)
        self.entry_location = ttk.Entry(auth_frame, state="disabled")
        self.entry_location.pack(fill="x", pady=5)

        self.submit_location = ttk.Button(
            auth_frame,
            text="Send Location",
            command=self.send_location,
            state="disabled",
            style="Custom.TButton"
        )
        self.submit_location.pack(fill="x", pady=5)

    def create_status_widgets(self):
        # Status Frame
        status_frame = ttk.LabelFrame(self.right_frame, text="Status & Messages", padding="10")
        status_frame.pack(fill="both", expand=True)

        self.message_label = ttk.Label(
            status_frame,
            text="Waiting for connection...",
            wraplength=250
        )
        self.message_label.pack(fill="x", pady=5)

        # Add a progress bar for connection status
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(fill="x", pady=5)

    def _initialize_crypto(self):
        """Initialize cryptographic components with error handling."""
        try:
            # Get encryption keys
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
            
            # Get a random encryption sequence
            self.methods, self.sequence_hash = get_random_sequence_from_csv()

            logging.info(f"Cryptography initialized with sequence: {' -> '.join(self.methods)}")
            self.crypto_initialized = True
        except Exception as e:
            logging.error(f"Failed to initialize cryptography: {e}")
            self.crypto_initialized = False
            messagebox.showerror(
                "Initialization Error",
                "Failed to initialize cryptographic components. Some features may be limited."
            )

    def send_message(self):
        """Send encrypted message to commander"""
        if not self.connected or not self.tank_id:
            messagebox.showerror("Error", "Not connected to server")
            return

        message = self.message_input.get().strip()
        if message:
            try:
                logging.info(f"Preparing to send message: {message}")
                
                # Convert message to bytes
                message_bytes = message.encode('utf-8')
                
                # Get encryption sequence
                methods, sequence_hash = get_random_sequence_from_csv()
                logging.info(f"Using encryption sequence: {methods}, hash: {sequence_hash}")

                # Generate signature
                signature = generate_signature(message_bytes, self.private_key_rsa)
                logging.info("Generated digital signature")

                # Encrypt message
                ivs, encrypted_data, tags = encrypt_data(
                    message_bytes,
                    methods,
                    self.key_aes,
                    self.key_des,
                    self.key_tdes,
                    self.public_key_rsa,
                    self.public_key_ecc
                )
                logging.info("Message encrypted successfully")

                # Prepare payload
                payload = {
                    "type": "message",
                    "tank_id": self.tank_id,
                    "sequence_hash": sequence_hash,
                    "ivs": [base64.b64encode(iv).decode('utf-8') if iv else None for iv in ivs],
                    "data": [base64.b64encode(data).decode('utf-8') for data in encrypted_data],
                    "tags": [base64.b64encode(tag).decode('utf-8') if tag else None for tag in tags],
                    "signature": base64.b64encode(signature).decode('utf-8'),
                    "random_index": self.random_index
                }

                # Convert payload to JSON and encode
                payload_json = json.dumps(payload)
                self.client_socket.sendall(payload_json.encode('utf-8'))
                
                # Add message to chat display
                self.add_message(f"Tank {self.tank_id}", message)
                self.message_input.delete(0, tk.END)
                
                logging.info("Message sent successfully")
            except Exception as e:
                logging.error(f"Failed to send message: {str(e)}", exc_info=True)
                messagebox.showerror("Error", f"Failed to send message: {str(e)}")

    def send_location(self):
        """Send encrypted location data"""
        if not self.connected:
            messagebox.showerror("Connection Error", "Not connected to server")
            return

        location = self.entry_location.get()
        if location:
            try:
                logging.info(f"Preparing to send location: {location}")
                
                # Convert location to bytes
                location_bytes = location.encode('utf-8')
                
                # Get encryption sequence
                methods, sequence_hash = get_random_sequence_from_csv()
                logging.info(f"Using encryption sequence: {methods}, hash: {sequence_hash}")

                # Generate signature
                signature = generate_signature(location_bytes, self.private_key_rsa)
                logging.info("Generated digital signature")

                # Encrypt the location
                ivs, encrypted_data, tags = encrypt_data(
                    location_bytes,
                    methods,
                    self.key_aes,
                    self.key_des,
                    self.key_tdes,
                    self.public_key_rsa,
                    self.public_key_ecc
                )
                logging.info("Location encrypted successfully")

                # Store encryption info for verification
                self.last_encryption = {
                    "ivs": ivs,
                    "data": encrypted_data,
                    "tags": tags,
                    "signature": signature,
                    "original": location,
                    "sequence_hash": sequence_hash
                }

                # Prepare the payload
                payload = {
                    "type": "location",
                    "tank_id": self.tank_id,
                    "sequence_hash": sequence_hash,
                    "ivs": [base64.b64encode(iv).decode('utf-8') if iv else None for iv in ivs],
                    "data": [base64.b64encode(data).decode('utf-8') for data in encrypted_data],
                    "tags": [base64.b64encode(tag).decode('utf-8') if tag else None for tag in tags],
                    "signature": base64.b64encode(signature).decode('utf-8'),
                    "random_index": self.random_index
                }

                # Convert payload to JSON and encode
                payload_json = json.dumps(payload)
                self.client_socket.sendall(payload_json.encode('utf-8'))
                
                self.entry_location.config(state="disabled")
                self.submit_location.config(state="disabled")

                # Update map if valid coordinates
                try:
                    lat, lon = map(float, location.split(","))
                    self.map_widget.set_position(lat, lon)
                    self.map_widget.set_marker(lat, lon, text="Current Location")
                    self.message_label.config(text="Location sent successfully!")
                    
                    # Switch to map tab
                    self.tab_control.select(0)
                    
                    logging.info("Map updated with new location")
                except ValueError:
                    messagebox.showerror("Error", "Invalid location format. Use 'latitude,longitude'")

            except Exception as e:
                logging.error(f"Error sending location: {str(e)}", exc_info=True)
                self.message_label.config(text=f"Error sending location: {str(e)}")
                self.connected = False
                self.attempt_connection()
        else:
            messagebox.showwarning("Input Required", "Please enter your location.")

    def attempt_connection(self):
        """Attempt to connect to the server with retry mechanism"""
        if self.connection_retry_count >= self.MAX_RETRIES:
            self.message_label.config(text="Failed to connect to server. Please restart the application.")
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
            self.message_label.config(text="Connected to server successfully!")
            
            # Start message receiver thread
            self.message_receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.message_receiver_thread.start()
            
            self.receive_initial_message()
        except ConnectionRefusedError:
            self.connected = False
            self.connection_retry_count += 1
            self.message_label.config(text=f"Connection attempt {self.connection_retry_count}/{self.MAX_RETRIES}. Retrying...")
            self.root.after(2000, self.attempt_connection)
        except Exception as e:
            self.connected = False
            self.message_label.config(text=f"Connection error: {str(e)}")
            self.progress.stop()

    def receive_messages(self):
        """Handle incoming messages from server"""
        while self.running and self.connected:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                try:
                    # Decode and parse JSON data
                    message_data = json.loads(data.decode())
                    
                    if message_data.get("type") == "broadcast":
                        self.handle_broadcast_message(message_data)
                    else:
                        # Handle other message types
                        self.message_label.config(text=data.decode())
                except json.JSONDecodeError:
                    # Handle non-JSON messages (like authentication messages)
                    self.message_label.config(text=data.decode())
            except Exception as e:
                if self.running:  # Only log if not shutting down
                    logging.error(f"Error receiving message: {e}", exc_info=True)
                break

    def handle_broadcast_message(self, message_data):
        """Handle encrypted broadcast messages from commander"""
        try:
            # Get encryption sequence using hash
            sequence_hash = message_data.get("sequence_hash")
            methods = self.get_sequence_by_hash(sequence_hash)
            if not methods:
                logging.error("Invalid sequence hash received")
                return

            # Get keys using received index
            index = message_data.get("random_index")
            keys = get_keys_by_index(index)
            if not keys:
                logging.error("Invalid key index received")
                return

            key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc = keys

            # Decode encrypted data components
            ivs = [base64.b64decode(iv) if iv else None for iv in message_data.get("ivs", [])]
            encrypted_data = [base64.b64decode(data) for data in message_data.get("data", [])]
            tags = [base64.b64decode(tag) if tag else None for tag in message_data.get("tags", [])]
            signature = base64.b64decode(message_data.get("signature", ""))

            # Decrypt message
            decrypted_message = decrypt_data(
                ivs,
                encrypted_data,
                tags,
                methods,
                key_aes,
                key_des,
                key_tdes,
                private_key_rsa,
                private_key_ecc
            )

            # Verify signature
            if verify_signature(decrypted_message, signature, public_key_rsa):
                # Add message to chat
                self.root.after(0, lambda: self.add_message("Commander", decrypted_message))
            else:
                logging.warning("Invalid message signature")

        except Exception as e:
            logging.error(f"Error handling broadcast message: {e}", exc_info=True)

    def get_sequence_by_hash(self, sequence_hash):
        """Get encryption sequence using hash from sequences.csv"""
        try:
            with open('sequences.csv', 'r') as f:
                import csv
                reader = csv.DictReader(f)
                for row in reader:
                    if row['hash'] == sequence_hash:
                        return json.loads(row['sequence'])
            return None
        except Exception as e:
            logging.error(f"Error getting sequence by hash: {e}", exc_info=True)
            return None

    def receive_initial_message(self):
        try:
            message = self.client_socket.recv(1024).decode()
            self.message_label.config(text=message)
        except Exception as e:
            self.message_label.config(text=f"Error receiving message: {str(e)}")

    def send_tank_id(self):
        if not self.connected:
            messagebox.showerror("Connection Error", "Not connected to server. Please wait for connection.")
            return

        tank_id = self.entry_tank_id.get()
        if tank_id:
            try:
                self.tank_id = tank_id  # Store tank ID
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
        try:
            challenge_msg = self.client_socket.recv(1024).decode()
            self.message_label.config(text=challenge_msg)

            challenge_parts = challenge_msg.split(":")[-1].strip().split()
            challenge = int(challenge_parts[0])
            random_number = int(challenge_parts[1]) if len(challenge_parts) > 1 else None

            response = self.compute_response(challenge, random_number)

            self.entry_response.config(state="normal")
            self.entry_response.insert(0, response)
            self.submit_response.config(state="normal")
        except Exception as e:
            self.message_label.config(text=f"Error receiving challenge: {str(e)}")

    def compute_response(self, challenge, random_number):
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
        if not self.connected:
            messagebox.showerror("Connection Error", "Not connected to server. Please wait for connection.")
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
        try:
            auth_response = self.client_socket.recv(1024).decode()
            self.message_label.config(text=auth_response)

            if auth_response == "Authentication Successful":
                readiness_prompt = self.client_socket.recv(1024).decode()
                self.message_label.config(text=readiness_prompt)

                readiness_response = messagebox.askquestion("Readiness", "Are you ready?")
                if readiness_response == "yes":
                    self.client_socket.send("yes".encode())
                    self.receive_location_request()
                else:
                    self.client_socket.send("no".encode())
        except Exception as e:
            self.message_label.config(text=f"Authentication error: {str(e)}")

    def receive_location_request(self):
        try:
            location_request = self.client_socket.recv(1024).decode()
            self.message_label.config(text=location_request)
            self.entry_location.config(state="normal")
            self.submit_location.config(state="normal")
        except Exception as e:
            self.message_label.config(text=f"Error receiving location request: {str(e)}")

    def add_message(self, sender, message):
        """Add message to chat display"""
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {sender}: {message}\n"
        
        self.chat_display.insert(tk.END, formatted_message)
        self.chat_display.see(tk.END)
        
        # Store message in history
        self.chat_messages.append({
            'timestamp': timestamp,
            'sender': sender,
            'message': message
        })

    def reset_map_view(self):
        """Reset map to default view"""
        self.map_widget.set_position(17.3850, 78.4867)
        self.map_widget.set_zoom(10)

    def use_current_location(self):
        """Set current map center as location"""
        if self.entry_location["state"] == "normal":
            current_position = self.map_widget.get_position()
            location = f"{current_position[0]},{current_position[1]}"
            self.entry_location.delete(0, tk.END)
            self.entry_location.insert(0, location)

    def on_closing(self):
        """Handle window closing"""
        self.running = False
        if self.client_socket:
            self.client_socket.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = TankClientGUI(root)
    root.mainloop()
