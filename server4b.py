import sys
import socket
import random
import logging
import threading
import subprocess
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from typing import Optional, Dict
from tkintermapview import TkinterMapView
import time
import json
import csv
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
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)

LOCATIONS_CSV = 'tank_locations.csv'

class CommanderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Commander Control Center")
        self.root.geometry("1400x800")
        
        # Initialize variables
        self.server_socket = None
        self.connected_tanks = {}
        self.tank_markers = {}
        self.tank_paths = {}
        self.server_running = False
        self.selected_tank = None
        self.show_paths = False
        self.client_threads = {}
        self.client_locks = {}

        # Setup styles
        self.setup_styles()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.home_tab = ttk.Frame(self.notebook)
        self.user_management_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.home_tab, text='Home')
        self.notebook.add(self.user_management_tab, text='User Management')
        
        # Create layouts for each tab
        self.create_home_tab()
        self.create_user_management_tab()
        
        # Initialize crypto
        self._initialize_crypto()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """Handle window closing event"""
        if self.server_running:
            self.stop_server()
        self.root.destroy()

    def setup_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", font=("Arial", 12))
        style.configure("TButton", padding=5)
        style.configure("Tank.TButton", padding=10)
        style.configure("Header.TLabel", font=("Arial", 16, "bold"))
        style.configure("Online.TLabel", foreground="green")
        style.configure("Offline.TLabel", foreground="red")

    def create_home_tab(self):
        # Configure grid weights for home tab
        self.home_tab.grid_rowconfigure(0, weight=1)
        self.home_tab.grid_columnconfigure(1, weight=3)
        self.home_tab.grid_columnconfigure(2, weight=1)

        # Left Panel - Tank List
        left_panel = ttk.Frame(self.home_tab, padding=10)
        left_panel.grid(row=0, column=0, sticky="nsew")
        
        # Tank List
        tank_frame = ttk.LabelFrame(left_panel, text="Connected Tanks", padding=10)
        tank_frame.pack(fill="both", expand=True)

        self.tank_listbox = tk.Listbox(tank_frame, font=("Arial", 10))
        self.tank_listbox.pack(fill="both", expand=True)
        self.tank_listbox.bind('<<ListboxSelect>>', self.on_tank_selected)

        # Control Buttons
        control_frame = ttk.Frame(tank_frame, padding=5)
        control_frame.pack(fill="x", pady=5)

        ttk.Button(
            control_frame,
            text="Show Path",
            command=self.toggle_path_visibility
        ).pack(side="left", padx=2)

        ttk.Button(
            control_frame,
            text="Clear Path",
            command=self.clear_selected_path
        ).pack(side="left", padx=2)

        # Center Panel - Map
        center_panel = ttk.Frame(self.home_tab, padding=10)
        center_panel.grid(row=0, column=1, sticky="nsew")
        
        map_frame = ttk.LabelFrame(center_panel, text="Tactical Map", padding=10)
        map_frame.pack(fill="both", expand=True)

        self.map_widget = TkinterMapView(map_frame, width=800, height=600)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(17.385044, 78.486671)
        self.map_widget.set_zoom(10)

        # Right Panel - Controls and Logs
        right_panel = ttk.Frame(self.home_tab, padding=10)
        right_panel.grid(row=0, column=2, sticky="nsew")
        
        # Server Controls
        control_frame = ttk.LabelFrame(right_panel, text="Server Controls", padding=10)
        control_frame.pack(fill="x")

        self.server_status = ttk.Label(
            control_frame,
            text="Server Status: Stopped",
            font=("Arial", 10)
        )
        self.server_status.pack(fill="x", pady=5)

        self.start_button = ttk.Button(
            control_frame,
            text="Start Server",
            command=self.start_server
        )
        self.start_button.pack(fill="x", pady=5)

        # Log Section
        log_frame = ttk.LabelFrame(right_panel, text="Server Logs", padding=10)
        log_frame.pack(fill="both", expand=True)

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.log_area.pack(fill="both", expand=True)

    def create_user_management_tab(self):
        # Tank Management Section
        self.create_tank_management_section()

    def create_tank_management_section(self):
        """Create the tank management section"""
        # Header
        ttk.Label(self.user_management_tab, 
                 text="Tank Management", 
                 style="Header.TLabel").pack(fill="x", pady=(10, 20))

        # Main container
        container = ttk.Frame(self.user_management_tab)
        container.pack(fill="both", expand=True, padx=20)

        # Available Tanks
        tank_frame = ttk.LabelFrame(container, text="Available Tanks", padding=5)
        tank_frame.pack(fill="x", expand=True, pady=5)

        self.available_tanks_list = tk.Listbox(tank_frame, 
                                           height=8,
                                           selectmode=tk.MULTIPLE,
                                           font=("Arial", 10))
        self.available_tanks_list.pack(fill="both", expand=True, pady=5)

        # Populate the listbox with 12 tanks
        for i in range(1, 13):
            self.available_tanks_list.insert(tk.END, f"Tk {i}")

        # Launch Clients Button
        ttk.Button(
            tank_frame,
            text="Launch Selected Clients",
            style="Tank.TButton",
            command=self.launch_clients
        ).pack(fill="x", pady=5)

        # Status Frames Container
        status_container = ttk.Frame(container)
        status_container.pack(fill="x", expand=True)
        
        # Online Tanks
        online_frame = ttk.LabelFrame(status_container, text="Online Tanks", padding=5)
        online_frame.pack(side="left", fill="both", expand=True, padx=5)

        self.online_tanks_list = tk.Listbox(online_frame,
                                          height=6,
                                          selectmode=tk.SINGLE,
                                          font=("Arial", 10),
                                          bg="#d4edda")
        self.online_tanks_list.pack(fill="both", expand=True, pady=5)

        # Offline Tanks
        offline_frame = ttk.LabelFrame(status_container, text="Offline Tanks", padding=5)
        offline_frame.pack(side="left", fill="both", expand=True, padx=5)

        self.offline_tanks_list = tk.Listbox(offline_frame,
                                           height=6,
                                           selectmode=tk.SINGLE,
                                           font=("Arial", 10),
                                           bg="#f8d7da")
        self.offline_tanks_list.pack(fill="both", expand=True, pady=5)

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
            self.log(f"Failed to initialize cryptography: {str(e)}", "ERROR")
            self.crypto_initialized = False

    def start_server(self):
        """Start the server"""
        if not self.server_running:
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('localhost', 12345))
                self.server_socket.listen(5)
                self.server_running = True
                
                # Update UI
                self.server_status.config(text="Server Status: Running")
                self.start_button.config(text="Stop Server", command=self.stop_server)
                
                # Start accepting connections in a separate thread
                threading.Thread(target=self.accept_connections, daemon=True).start()
                
                self.log("Server started successfully")
            except Exception as e:
                self.log(f"Failed to start server: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Failed to start server: {str(e)}")

    def stop_server(self):
        """Stop the server"""
        if self.server_running:
            self.server_running = False
            
            # Close all client connections
            for tank_id in list(self.connected_tanks.keys()):
                self.disconnect_tank(tank_id)
            
            # Close server socket
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
                self.server_socket = None
            
            # Update UI
            self.server_status.config(text="Server Status: Stopped")
            self.start_button.config(text="Start Server", command=self.start_server)
            self.log("Server stopped")

    def accept_connections(self):
        """Accept incoming connections"""
        while self.server_running:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(60)  # Set timeout to 60 seconds
                
                self.log(f"New connection from {address}")
                
                # Start a new thread to handle the client
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                if self.server_running:
                    self.log(f"Error accepting connection: {str(e)}", "ERROR")

    def handle_client(self, client_socket, address):
        """Handle client connection"""
        tank_id = None
        try:
            # Receive tank ID
            tank_id = client_socket.recv(1024).decode().strip()
            if not tank_id:
                raise ValueError("Empty tank ID received")
            
            self.log(f"Tank {tank_id} connected")
            
            # Store client connection
            self.connected_tanks[tank_id] = client_socket
            self.client_locks[tank_id] = threading.Lock()
            
            # Update UI
            self.root.after(0, self.update_tank_list, tank_id, True)
            
            # Authenticate tank
            if not self.authenticate_tank(tank_id, client_socket):
                raise ValueError("Authentication failed")
            
            self.log(f"Tank {tank_id} authenticated")
            
            # Main communication loop
            while self.server_running:
                # Send location request
                with self.client_locks[tank_id]:
                    client_socket.send("Give me your location".encode())
                
                # Wait for response
                response = client_socket.recv(4096).decode()
                if not response:
                    raise ConnectionError("Empty response received")
                
                # Process location update
                self.process_location_update(tank_id, response)
                
                # Wait before next request
                time.sleep(1)
                
        except Exception as e:
            if self.server_running:
                self.log(f"Error handling client: {str(e)}", "ERROR")
        
        finally:
            if tank_id:
                self.disconnect_tank(tank_id)

    def authenticate_tank(self, tank_id, client_socket):
        """Authenticate tank connection"""
        try:
            # Send challenge
            challenge_type = random.randint(0, 9)
            challenge_num = random.randint(1, 100)
            challenge = f"Challenge: {challenge_type} {challenge_num}"
            client_socket.send(challenge.encode())
            
            # Wait for response
            response = client_socket.recv(1024).decode()
            if not response:
                return False
            
            # Verify response
            expected_response = self.calculate_expected_response(challenge_type, challenge_num)
            if response.strip() != str(expected_response).strip():
                return False
            
            # Send confirmation
            client_socket.send("Authentication Successful".encode())
            return True
            
        except Exception as e:
            self.log(f"Authentication error for {tank_id}: {str(e)}", "ERROR")
            return False

    def calculate_expected_response(self, challenge_type, num):
        """Calculate expected response for challenge"""
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

    def disconnect_tank(self, tank_id):
        """Disconnect a tank client"""
        try:
            # Close socket
            if tank_id in self.connected_tanks:
                try:
                    self.connected_tanks[tank_id].close()
                except:
                    pass
                del self.connected_tanks[tank_id]
            
            # Remove locks
            if tank_id in self.client_locks:
                del self.client_locks[tank_id]
            
            # Update UI
            self.root.after(0, self.update_tank_list, tank_id, False)
            self.log(f"Tank {tank_id} disconnected")
            
        except Exception as e:
            self.log(f"Error disconnecting {tank_id}: {str(e)}", "ERROR")

    def update_tank_list(self, tank_id, connected):
        """Update tank list in UI"""
        try:
            if connected:
                self.tank_listbox.insert(tk.END, tank_id)
                self.move_tank_to_list(tank_id, "online")
            else:
                # Remove from tank listbox
                for i in range(self.tank_listbox.size()):
                    if self.tank_listbox.get(i) == tank_id:
                        self.tank_listbox.delete(i)
                        break
                self.move_tank_to_list(tank_id, "offline")
        except Exception as e:
            self.log(f"Error updating tank list: {str(e)}", "ERROR")

    def process_location_update(self, tank_id, data):
        """Process location update from tank"""
        try:
            # Parse JSON data
            payload = json.loads(data)
            
            # Decrypt location
            decrypted_location = decrypt_data(
                payload["data"],
                payload["ivs"],
                payload["tags"],
                find_sequence_by_hash(payload["sequence_hash"]),
                *get_keys_by_index(payload["random_index"])
            )
            
            # Verify signature
            if not verify_signature(decrypted_location, payload["signature"], self.public_key_rsa):
                raise ValueError("Invalid signature")
            
            # Update map
            lat, lon = map(float, decrypted_location.split(","))
            self.update_tank_location(tank_id, lat, lon)
            
        except Exception as e:
            self.log(f"Error processing location update from {tank_id}: {str(e)}", "ERROR")

    def update_tank_location(self, tank_id, lat, lon):
        """Update tank location on map"""
        try:
            # Update or create marker
            if tank_id in self.tank_markers:
                self.tank_markers[tank_id].set_position(lat, lon)
            else:
                marker = self.map_widget.set_marker(lat, lon, text=tank_id)
                self.tank_markers[tank_id] = marker
            
            # Update path
            if tank_id not in self.tank_paths:
                self.tank_paths[tank_id] = []
            self.tank_paths[tank_id].append((lat, lon))
            
            # Draw path if enabled
            if self.show_paths and tank_id == self.selected_tank:
                self.draw_tank_path(tank_id)
            
        except Exception as e:
            self.log(f"Error updating tank location: {str(e)}", "ERROR")

    def draw_tank_path(self, tank_id):
        """Draw tank path on map"""
        try:
            # Clear existing path
            self.map_widget.delete_all_path()
            
            # Draw new path if tank has positions
            if tank_id in self.tank_paths and len(self.tank_paths[tank_id]) > 1:
                self.map_widget.set_path(self.tank_paths[tank_id])
                
        except Exception as e:
            self.log(f"Error drawing tank path: {str(e)}", "ERROR")

    def toggle_path_visibility(self):
        """Toggle path visibility"""
        self.show_paths = not self.show_paths
        if self.selected_tank:
            if self.show_paths:
                self.draw_tank_path(self.selected_tank)
            else:
                self.map_widget.delete_all_path()

    def clear_selected_path(self):
        """Clear selected tank's path"""
        if self.selected_tank:
            if self.selected_tank in self.tank_paths:
                self.tank_paths[self.selected_tank] = []
            self.map_widget.delete_all_path()

    def on_tank_selected(self, event):
        """Handle tank selection"""
        selection = self.tank_listbox.curselection()
        if selection:
            self.selected_tank = self.tank_listbox.get(selection[0])
            if self.show_paths:
                self.draw_tank_path(self.selected_tank)

    def launch_clients(self):
        """Launch client GUIs for selected tanks"""
        selected_indices = self.available_tanks_list.curselection()
        selected_tanks = [self.available_tanks_list.get(i) for i in selected_indices]

        if not selected_tanks:
            messagebox.showwarning("No Tanks Selected", "Please select at least one tank to launch clients.")
            return

        for tank_id in selected_tanks:
            self.launch_client_gui(tank_id)

    def launch_client_gui(self, tank_id):
        """Launch a client GUI for the given tank"""
        try:
            # Use sys.executable to ensure the correct Python interpreter is used
            subprocess.Popen([sys.executable, "client_auth_gui.py", tank_id])
            self.log(f"Launched client GUI for {tank_id}")
            
            # Move tank to offline list
            self.move_tank_to_list(tank_id, "offline")
            
        except Exception as e:
            self.log(f"Failed to launch client GUI for {tank_id}: {e}", "ERROR")

    def move_tank_to_list(self, tank_id, status):
        """Move tank between available, online, and offline lists"""
        # Remove from all lists first
        lists = {
            "available": self.available_tanks_list,
            "online": self.online_tanks_list,
            "offline": self.offline_tanks_list
        }
        
        for lst in lists.values():
            for i in range(lst.size()):
                if tank_id in lst.get(i):
                    lst.delete(i)
                    break
        
        # Add to appropriate list
        if status == "online":
            self.online_tanks_list.insert(tk.END, tank_id)
        elif status == "offline":
            self.offline_tanks_list.insert(tk.END, tank_id)
        else:  # available
            self.available_tanks_list.insert(tk.END, tank_id)

    def log(self, message, level="INFO"):
        """Add message to log area with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        # Add to GUI log
        self.log_area.insert(tk.END, log_entry)
        self.log_area.see(tk.END)
        
        # Add to file log
        logging.log(
            getattr(logging, level),
            message
        )

if __name__ == "__main__":
    root = tk.Tk()
    app = CommanderGUI(root)
    root.mainloop()