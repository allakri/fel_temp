import socket
import logging
import tkinter as tk
from tkinter import Toplevel, messagebox, ttk
from typing import Optional, Dict
from tkintermapview import TkinterMapView
import time
import json  # Add this import

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
        logging.FileHandler('secure_comm.log'),
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

        # Create main frames
        self.create_frames()
        self.create_widgets()
        
        # Initialize cryptographic components
        self._initialize_crypto()

        # Popup Window
        self.popup_window = None

        # Start connection attempt
        self.attempt_connection()

    def create_frames(self):
        # Left Panel
        self.left_frame = ttk.Frame(self.root, padding="10")
        self.left_frame.grid(row=0, column=0, sticky="nsew")

        # Center Panel (Map)
        self.center_frame = ttk.Frame(self.root, padding="10")
        self.center_frame.grid(row=0, column=1, sticky="nsew")

        # Right Panel
        self.right_frame = ttk.Frame(self.root, padding="10")
        self.right_frame.grid(row=0, column=2, sticky="nsew")

        # Style configuration
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("Custom.TButton", padding=10, font=('Arial', 10))

    def create_widgets(self):
        # Left Panel Widgets
        self.create_auth_widgets()
        
        # Center Panel (Map)
        self.create_map_widget()
        
        # Right Panel Widgets
        self.create_status_widgets()

    def create_auth_widgets(self):
        # Authentication Frame
        auth_frame = ttk.LabelFrame(self.left_frame, text="Authentication", padding="10")
        auth_frame.pack(fill="x", pady=5)

        # Tank ID Entry
        ttk.Label(auth_frame, text="Enter Tank ID:").pack(fill="x", pady=2)
        self.entry_tank_id = ttk.Entry(auth_frame)
        self.entry_tank_id.pack(fill="x", pady=5)

        self.submit_tank_id = ttk.Button(auth_frame, text="Submit", command=self.send_tank_id)
        self.submit_tank_id.pack(fill="x", pady=5)

        # Response widgets
        ttk.Label(auth_frame, text="Challenge Response:").pack(fill="x", pady=2)
        self.entry_response = ttk.Entry(auth_frame, state="disabled")
        self.entry_response.pack(fill="x", pady=5)

        self.submit_response = ttk.Button(auth_frame, text="Send Response", 
                                        command=self.send_response, state="disabled")
        self.submit_response.pack(fill="x", pady=5)

        # Location Entry
        ttk.Label(auth_frame, text="Location (lat,lon):").pack(fill="x", pady=2)
        self.entry_location = ttk.Entry(auth_frame, state="disabled")
        self.entry_location.pack(fill="x", pady=5)

        self.submit_location = ttk.Button(auth_frame, text="Send Location", 
                                        command=self.send_location, state="disabled")
        self.submit_location.pack(fill="x", pady=5)

    def create_map_widget(self):
        # Map Frame
        map_frame = ttk.LabelFrame(self.center_frame, text="Map View", padding="10")
        map_frame.pack(fill="both", expand=True)

        self.map_widget = TkinterMapView(map_frame, width=600, height=400, corner_radius=0)
        self.map_widget.pack(fill="both", expand=True, padx=5, pady=5)
        self.map_widget.set_position(17.3850, 78.4867)  # Default location
        self.map_widget.set_zoom(10)

    def create_status_widgets(self):
        # Status Frame
        status_frame = ttk.LabelFrame(self.right_frame, text="Status & Messages", padding="10")
        status_frame.pack(fill="both", expand=True)

        self.message_label = ttk.Label(status_frame, text="Waiting for connection...", wraplength=250)
        self.message_label.pack(fill="x", pady=5)

        # Add a progress bar for connection status
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(fill="x", pady=5)

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
            self.receive_initial_message()
        except ConnectionRefusedError:
            self.connected = False
            self.connection_retry_count += 1
            self.message_label.config(text=f"Connection attempt {self.connection_retry_count}/{self.MAX_RETRIES}. Retrying...")
            self.root.after(2000, self.attempt_connection)  # Retry after 2 seconds
        except Exception as e:
            self.connected = False
            self.message_label.config(text=f"Connection error: {str(e)}")
            self.progress.stop()

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

    def send_location(self):
        if not self.connected:
            messagebox.showerror("Connection Error", "Not connected to server. Please wait for connection.")
            return

        location = self.entry_location.get()
        if location:
            try:
                # Encrypt the location
                signature = generate_signature(location, self.private_key_rsa)
                ivs, encrypted_data, tags = encrypt_data(
                    location,
                    self.methods,
                    self.key_aes,
                    self.key_des,
                    self.key_tdes,
                    self.public_key_rsa,
                    self.public_key_ecc
                )

                # Store encryption info
                self.last_encryption = {
                    "ivs": ivs,
                    "data": encrypted_data,
                    "tags": tags,
                    "signature": signature,
                    "original": location
                }

                # Prepare the payload
                payload = {
                    "ivs": ivs,
                    "data": encrypted_data,
                    "tags": tags,
                    "signature": signature,
                    "random_index": self.random_index
                }

                # Send the encrypted location
                self.client_socket.sendall(json.dumps(payload).encode())
                self.entry_location.config(state="disabled")
                self.submit_location.config(state="disabled")

                # Update map if valid coordinates
                try:
                    lat, lon = map(float, location.split(","))
                    self.map_widget.set_position(lat, lon)
                    self.map_widget.set_marker(lat, lon, text="Current Location")
                    self.message_label.config(text="Location sent successfully!")
                except ValueError:
                    messagebox.showerror("Error", "Invalid location format. Use 'latitude,longitude'")

            except Exception as e:
                self.message_label.config(text=f"Error sending location: {str(e)}")
                self.connected = False
                self.attempt_connection()
        else:
            messagebox.showwarning("Input Required", "Please enter your location.")

if __name__ == "__main__":
    root = tk.Tk()
    app = TankClientGUI(root)
    root.mainloop()