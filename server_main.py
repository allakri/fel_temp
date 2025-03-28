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
import os
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

class CommanderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Commander Control Center")
        self.root.geometry("1400x800")
        
        # Initialize variables
        self.server_socket = None
        self.connected_tanks = {}  # {tank_id: connection}
        self.tank_markers = {}
        self.tank_paths = {}
        self.server_running = False
        self.selected_tank = None
        self.show_paths = False
        self.message_processing = False
        
        # Ensure history directory exists
        self.history_dir = "tank_history"
        os.makedirs(self.history_dir, exist_ok=True)
        
        # Initialize crypto
        self._initialize_crypto()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.map_tab = ttk.Frame(self.notebook)
        self.chat_tab = ttk.Frame(self.notebook)
        self.user_management_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.map_tab, text='Map View')
        self.notebook.add(self.chat_tab, text='Chat')
        self.notebook.add(self.user_management_tab, text='User Management')
        
        # Create layouts for each tab
        self.create_map_tab()
        self.create_chat_tab()
        self.create_user_management_tab()
    
    def setup_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", font=("Arial", 12))
        style.configure("TButton", padding=5)
        style.configure("Tank.TButton", padding=10)
        style.configure("Header.TLabel", font=("Arial", 16, "bold"))
        style.configure("Online.TLabel", foreground="green")
        style.configure("Offline.TLabel", foreground="red")

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

    def create_map_tab(self):
        # Configure grid weights for home tab
        self.map_tab.grid_rowconfigure(0, weight=1)
        self.map_tab.grid_columnconfigure(1, weight=3)
        self.map_tab.grid_columnconfigure(2, weight=1)

        # Left Panel - Tank List
        left_panel = ttk.Frame(self.map_tab, padding=10)
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
        center_panel = ttk.Frame(self.map_tab, padding=10)
        center_panel.grid(row=0, column=1, sticky="nsew")
        
        map_frame = ttk.LabelFrame(center_panel, text="Tactical Map", padding=10)
        map_frame.pack(fill="both", expand=True)

        self.map_widget = TkinterMapView(map_frame, width=800, height=600)
        self.map_widget.pack(fill="both", expand=True)
        self.map_widget.set_position(17.385044, 78.486671)
        self.map_widget.set_zoom(10)

        # Right Panel - Controls and Logs
        right_panel = ttk.Frame(self.map_tab, padding=10)
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

    def create_chat_tab(self):
        # Chat container
        chat_container = ttk.Frame(self.chat_tab)
        chat_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Tank selection for chat
        select_frame = ttk.Frame(chat_container)
        select_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(select_frame, text="Select Tank:").pack(side="left", padx=(0, 10))
        self.chat_tank_var = tk.StringVar()
        self.chat_tank_combo = ttk.Combobox(
            select_frame,
            textvariable=self.chat_tank_var,
            state="readonly"
        )
        self.chat_tank_combo.pack(side="left", fill="x", expand=True)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(
            chat_container,
            wrap=tk.WORD,
            font=("Consolas", 10),
            height=20
        )
        self.chat_display.pack(fill="both", expand=True, pady=(0, 10))

        # Message input area
        input_frame = ttk.Frame(chat_container)
        input_frame.pack(fill="x")

        self.message_input = ttk.Entry(input_frame)
        self.message_input.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Button(
            input_frame,
            text="Send",
            command=self.send_chat_message
        ).pack(side="right")

    def create_user_management_tab(self):
        # Tank Management Section
        self.create_tank_management_section()

    def create_tank_management_section(self):
        """Create the tank management section"""
        # Header
        ttk.Label(
            self.user_management_tab,
            text="Tank Management",
            style="Header.TLabel"
        ).pack(fill="x", pady=(10, 20))

        # Main container
        container = ttk.Frame(self.user_management_tab)
        container.pack(fill="both", expand=True, padx=20)

        # Available Tanks
        tank_frame = ttk.LabelFrame(container, text="Available Tanks", padding=5)
        tank_frame.pack(fill="x", expand=True, pady=5)

        self.available_tanks_list = tk.Listbox(
            tank_frame,
            height=8,
            selectmode=tk.MULTIPLE,
            font=("Arial", 10)
        )
        self.available_tanks_list.pack(fill="both", expand=True, pady=5)

        # Populate the listbox with tanks
        for i in range(1, 13):
            self.available_tanks_list.insert(tk.END, f"Tk{i}")

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

        self.online_tanks_list = tk.Listbox(
            online_frame,
            height=6,
            selectmode=tk.SINGLE,
            font=("Arial", 10),
            bg="#d4edda"
        )
        self.online_tanks_list.pack(fill="both", expand=True, pady=5)

        # Offline Tanks
        offline_frame = ttk.LabelFrame(status_container, text="Offline Tanks", padding=5)
        offline_frame.pack(side="left", fill="both", expand=True, padx=5)

        self.offline_tanks_list = tk.Listbox(
            offline_frame,
            height=6,
            selectmode=tk.SINGLE,
            font=("Arial", 10),
            bg="#f8d7da"
        )
        self.offline_tanks_list.pack(fill="both", expand=True, pady=5)

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
            self.log(f"Failed to launch client GUI for {tank_id}: {e}", level="ERROR")

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
    
    def on_tank_selected(self, event):
        selection = self.tank_listbox.curselection()
        if selection:
            self.selected_tank = self.tank_listbox.get(selection[0])
            self.center_on_tank(self.selected_tank)
            if self.show_paths:
                self.show_tank_path(self.selected_tank)

    # def toggle_path_visibility(self):
    #     self.show_paths = not self.show_paths
    #     if self.selected_tank:
    #         if self.show_paths:
    #             self.show_tank_path(self.selected_tank)
    #         else:
    #             self.clear_path(self.selected_tank)
    def toggle_path_visibility(self):
        """Toggle path visibility for the selected tank"""
        self.show_paths = not self.show_paths
        if self.selected_tank:
            if self.show_paths:
                if self.selected_tank in self.tank_paths and len(self.tank_paths[self.selected_tank]) >= 2:
                    # Draw the path if it has at least two points
                    self.map_widget.set_path(self.tank_paths[self.selected_tank])
                else:
                    self.log(f"No valid path data for {self.selected_tank}", "WARNING")
            else:
                # Clear all paths from the map
                self.map_widget.delete_all_path()
    
    
    def show_tank_path(self, tank_id):
        """Show historical path for selected tank"""
        try:
            # Clear existing path
            if tank_id in self.tank_paths:
                self.tank_paths[tank_id].delete()
            
            history_file = os.path.join(self.history_dir, f"hist_{tank_id}.csv")
            if not os.path.exists(history_file):
                self.log(f"No history file found for {tank_id}")
                return
            
            # Read locations
            locations = []
            with open(history_file, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    locations.append((float(row['latitude']), float(row['longitude'])))
            
            if locations:
                # Draw path on map
                self.tank_paths[tank_id] = self.map_widget.set_path(locations)
                
                # Center map on latest position
                self.map_widget.set_position(locations[-1][0], locations[-1][1])
                self.map_widget.set_zoom(12)
                
                self.log(f"Showing path for {tank_id} with {len(locations)} points")
            
        except Exception as e:
            self.log(f"Error showing path for {tank_id}: {e}", "ERROR")

    def clear_path(self, tank_id):
        if tank_id in self.tank_paths:
            self.tank_paths[tank_id].delete()
            del self.tank_paths[tank_id]

    def clear_selected_path(self):
        if self.selected_tank:
            self.clear_path(self.selected_tank)

    def center_on_tank(self, tank_id):
        if tank_id in self.tank_markers:
            marker = self.tank_markers[tank_id]
            self.map_widget.set_position(marker.position[0], marker.position[1])
            self.map_widget.set_zoom(15)

    def store_tank_location(self, tank_id: str, lat: float, lon: float):
        """Store tank location in history file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_file = os.path.join(self.history_dir, f"hist_{tank_id}.csv")
        
        # Create file with headers if it doesn't exist
        if not os.path.exists(history_file):
            with open(history_file, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['timestamp', 'latitude', 'longitude'])
        
        # Append location
        with open(history_file, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, lat, lon])

    def update_tank_status(self, tank_id: str, online: bool):
        """Update tank online/offline status"""
        try:
            if online:
                # Move from offline to online list
                for i in range(self.offline_tanks_list.size()):
                    if self.offline_tanks_list.get(i) == tank_id:
                        self.offline_tanks_list.delete(i)
                        break
                self.online_tanks_list.insert(tk.END, tank_id)
            else:
                # Move from online to offline list
                for i in range(self.online_tanks_list.size()):
                    if self.online_tanks_list.get(i) == tank_id:
                        self.online_tanks_list.delete(i)
                        break
                self.offline_tanks_list.insert(tk.END, tank_id)
        except Exception as e:
            self.log(f"Error updating tank status: {e}", "ERROR")

    # def update_tank_marker(self, tank_id: str, lat: float, lon: float):
    #     """Update tank marker on map"""
    #     try:
    #         # Remove old marker
    #         if tank_id in self.tank_markers:
    #             self.tank_markers[tank_id].delete()
            
    #         # Create new marker
    #         marker = self.map_widget.set_marker(
    #             lat, lon,
    #             text=f"{tank_id}",
    #             command=lambda: self.show_tank_info(tank_id)
    #         )
    #         self.tank_markers[tank_id] = marker
            
    #         # Store location in history
    #         self.store_tank_location(tank_id, lat, lon)
            
    #         # Update path if showing
    #         if self.show_paths and self.selected_tank == tank_id:
    #             self.show_tank_path(tank_id)
                
    #     except Exception as e:
    #         self.log(f"Error updating tank marker: {e}", "ERROR")

    def update_tank_marker(self, tank_id, lat, lon):
        """Update tank marker on map"""
        try:
            # Remove old marker
            if tank_id in self.tank_markers:
                self.tank_markers[tank_id].delete()
            
            # Create new marker
            marker = self.map_widget.set_marker(
                lat, lon,
                text=f"{tank_id}",
                command=lambda: self.show_tank_info(tank_id)
            )
            self.tank_markers[tank_id] = marker
            
            # Store location in history
            self.store_tank_location(tank_id, lat, lon)
            
            # Update path
            if tank_id not in self.tank_paths:
                self.tank_paths[tank_id] = []
            self.tank_paths[tank_id].append((lat, lon))
            
            # Draw path if visibility is enabled
            if self.show_paths and self.selected_tank == tank_id and len(self.tank_paths[tank_id]) >= 2:
                self.map_widget.set_path(self.tank_paths[tank_id])
                
        except Exception as e:
            self.log(f"Error updating tank marker: {e}", "ERROR")

    def show_tank_info(self, tank_id):
        history_file = os.path.join(self.history_dir, f"hist_{tank_id}.csv")
        if os.path.exists(history_file):
            with open(history_file, 'r') as file:
                reader = csv.DictReader(file)
                rows = list(reader)
                if rows:
                    latest = rows[-1]
                    info = f"Tank: {tank_id}\n"
                    info += f"Last Update: {latest['timestamp']}\n"
                    info += f"Position: {latest['latitude']}, {latest['longitude']}"
                    messagebox.showinfo("Tank Information", info)


    def start_server(self):
        """Start the server"""
        if not self.server_running:
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.bind(('localhost', 5000))
                self.server_socket.listen(5)
                self.server_running = True
                
                self.server_status.config(text="Server Status: Running")
                self.start_button.config(text="Stop Server")
                self.log("Server started successfully")
                # self.log("Server started on localhost:5000")
                
                # Start accepting connections in a separate thread
                threading.Thread(target=self.accept_connections, daemon=True).start()
                
            except Exception as e:
                self.log(f"Failed to start server: {e}", "ERROR")
        else:
            self.stop_server()

    def stop_server(self):
        """Stop the server"""
        if self.server_running:
            try:
                self.server_running = False
                if self.server_socket:
                    self.server_socket.close()
                
                # Close all tank connections
                for tank_id, conn in self.connected_tanks.items():
                    try:
                        conn.close()
                    except:
                        pass
                
                self.connected_tanks.clear()
                self.tank_listbox.delete(0, tk.END)
                self.map_widget.delete_all_marker()
                
                self.server_status.config(text="Server Status: Stopped")
                self.start_button.config(text="Start Server")
                self.log("Server stopped")
                
            except Exception as e:
                self.log(f"Error stopping server: {e}", "ERROR")

    def accept_connections(self):
        """Accept incoming connections"""
        while self.server_running:
            try:
                conn, addr = self.server_socket.accept()
                self.log(f"New connection from {addr}")
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except:
                if self.server_running:
                    self.log("Error accepting connection", "ERROR")

    def handle_client(self, conn, addr):
        """Handle client connection"""
        try:
            tank_id = conn.recv(1024).decode().strip()
            self.log(f"Tank {tank_id} connected")

            # Check if the tank is already authenticated
            if tank_id in self.connected_tanks:
                self.log(f"Tank {tank_id} is already authenticated")
                self.handle_tank_communication(conn, tank_id)
                return
            
            # Add to tank list and update UI
            self.root.after(0, lambda: self.tank_listbox.insert(tk.END, tank_id))

            self.root.after(0, lambda: self.update_chat_tank_list(tank_id, True))
            self.connected_tanks[tank_id] = conn
            
            # Generate and send challenge
            challenge_msg, expected_answer = self.generate_challenge()
            conn.send(f"Challenge: {challenge_msg}".encode())
            
            # Handle authentication
            response = conn.recv(1024).decode().strip()
            
            if response == expected_answer:
                conn.send("Authentication Successful".encode())
                self.log(f"Tank {tank_id} authenticated")
                self.handle_tank_communication(conn, tank_id)
            else:
                conn.send("Authentication Failed".encode())
                self.log(f"Tank {tank_id} authentication failed")
            
        except Exception as e:
            self.log(f"Error handling client: {e}", "ERROR")
        finally:
            if tank_id in self.connected_tanks:
                del self.connected_tanks[tank_id]
            conn.close()
            # Remove from tank list and update UI
            self.root.after(0, lambda: self.remove_tank(tank_id))
            self.root.after(0, lambda: self.update_chat_tank_list(tank_id, False))

    def remove_tank(self, tank_id):
        for i in range(self.tank_listbox.size()):
            if self.tank_listbox.get(i) == tank_id:
                self.tank_listbox.delete(i)
                break
        if tank_id in self.tank_markers:
            self.tank_markers[tank_id].delete()
            del self.tank_markers[tank_id]
        if tank_id in self.tank_paths:
            self.tank_paths[tank_id].delete()
            del self.tank_paths[tank_id]

    # def generate_challenge(self):
    #     """Generate authentication challenge"""
    #     num = random.randint(1000, 9999)
    #     return str(num), str(num + 1)

    def generate_challenge(self):
        challenge_type = random.randint(0, 9)
        if challenge_type == 0:
            return "0", "OK"
        num = random.randint(2, 20)
        return f"{challenge_type} {num}", self.calculate_expected_answer(challenge_type, num)

    def calculate_expected_answer(self, challenge_type, num):
        if challenge_type == 1:
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

    def handle_tank_communication(self, conn, tank_id):
        """Handle communication with tank"""
        try:
            # Set a longer timeout for receiving data
            conn.settimeout(30)  # Increase timeout to 20 seconds

            # Update tank status to online
            self.root.after(0, lambda: self.update_tank_status(tank_id, True))
            
            conn.send("Are you ready?".encode())
            
            readiness = conn.recv(1024).decode().strip()
            self.log(f"Received readiness response: {readiness}")
            print(readiness)
            
            if readiness.lower() in ["yes", "ready", "ok"]:
                while True:
                    conn.send("Give me your location".encode())
                    
                    data = ""
                    while True:
                        chunk = conn.recv(1024).decode()
                        if not chunk:
                            raise ConnectionError("No data received")
                        
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
                                    f"From {tank_id}: {decrypted_message[:50]}..."
                                ))
                                self.root.after(0, lambda: self.add_chat_message(
                                    tank_id,
                                    decrypted_message
                                ))
                        else:
                            # Handle location update
                            location = self.decrypt_location(payload, tank_id)
                            if location:
                                lat, lon = map(float, location.split(","))
                                self.root.after(0, lambda: self.update_tank_marker(tank_id, lat, lon))
                                self.log(f"Location received from Tank {tank_id}: {lat}, {lon}")
                                # Send "Received" status back to the client
                                conn.send("Location received successfully".encode())
                    
                    except json.JSONDecodeError:
                        self.log(f"Invalid JSON from Tank {tank_id}", "ERROR")
                    except Exception as e:
                        self.log(f"Error processing data from Tank {tank_id}: {e}", "ERROR")
                        
        except Exception as e:
            self.log(f"Communication error with Tank {tank_id}: {e}", "ERROR")
        finally:
            # Update tank status to offline
            self.root.after(0, lambda: self.update_tank_status(tank_id, False))

    def decrypt_location(self, payload, tank_id):
        """Decrypt location data from tank"""
        try:
            index = payload["random_index"]
            hash_value = payload["sequence_hash"]
            methods = find_sequence_by_hash(hash_value)

            if not methods:
                self.log(f"Invalid sequence hash from Tank {tank_id}", "ERROR")
                return None

            keys = get_keys_by_index(index)
            if not keys or len(keys) != 7:
                self.log(f"Invalid keys for Tank {tank_id}", "ERROR")
                return None

            key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc = keys

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

            is_valid = verify_signature(
                decrypted_location,
                payload["signature"],
                public_key_rsa
            )

            if not is_valid:
                self.log(f"Invalid signature from Tank {tank_id}", "ERROR")
                return None

            return decrypted_location

        except Exception as e:
            self.log(f"Decryption error from Tank {tank_id}: {e}", "ERROR")
            return None

    def update_tank_marker(self, tank_id, lat, lon):
        """Update tank marker on map"""
        if tank_id in self.tank_markers:
            self.map_widget.delete(self.tank_markers[tank_id])
        
        marker = self.map_widget.set_marker(lat, lon, text=tank_id)
        self.tank_markers[tank_id] = marker
        
        # Update path if enabled
        if self.show_paths:
            if tank_id not in self.tank_paths:
                self.tank_paths[tank_id] = []
            self.tank_paths[tank_id].append((lat, lon))
            
            # Draw path
            if len(self.tank_paths[tank_id]) > 1:
                self.map_widget.set_path(self.tank_paths[tank_id])

    def send_chat_message(self):
        """Send encrypted chat message to selected tank"""
        selected_tank = self.chat_tank_var.get()
        if not selected_tank or selected_tank not in self.connected_tanks:
            messagebox.showerror("Error", "Please select a connected tank")
            return

        message = self.message_input.get().strip()
        if not message:
            return

        try:
            # Get new encryption sequence for this message
            methods, sequence_hash = get_random_sequence_from_csv()

            # Encrypt message
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
                "sender": "Commander"
            }

            # Send encrypted message
            conn = self.connected_tanks[selected_tank]
            conn.sendall(f"{json.dumps(payload)}\n".encode())

            # Add message to chat display
            self.add_chat_message("You", message)

            # Clear input field
            self.message_input.delete(0, tk.END)

        except Exception as e:
            self.log(f"Error sending message: {e}", "ERROR")

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

    def show_notification(self, title, message):
        """Show popup notification"""
        messagebox.showinfo(title, message)

    def add_chat_message(self, sender, message):
        """Add message to chat display"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
        self.chat_display.see(tk.END)

    def update_chat_tank_list(self, tank_id, connected):
        """Update the chat tank selection dropdown"""
        tanks = list(self.connected_tanks.keys())
        self.chat_tank_combo['values'] = tanks
        if not tanks:
            self.chat_tank_combo.set('')
        elif self.chat_tank_var.get() not in tanks:
            self.chat_tank_combo.set(tanks[0])

    def update_tank_status(self, tank_id, online):
        """Update tank status in lists"""
        if online:
            self.offline_tanks_list.delete(0, tk.END)
            self.online_tanks_list.insert(tk.END, tank_id)
        else:
            self.online_tanks_list.delete(0, tk.END)
            self.offline_tanks_list.insert(tk.END, tank_id)

    def remove_tank(self, tank_id):
        """Remove tank from lists and map"""
        try:
            idx = 0
            while idx < self.tank_listbox.size():
                if self.tank_listbox.get(idx) == tank_id:
                    self.tank_listbox.delete(idx)
                    break
                idx += 1
            
            if tank_id in self.tank_markers:
                self.map_widget.delete(self.tank_markers[tank_id])
                del self.tank_markers[tank_id]
            
            if tank_id in self.tank_paths:
                del self.tank_paths[tank_id]
            
        except Exception as e:
            self.log(f"Error removing tank {tank_id}: {e}", "ERROR")

    def on_tank_selected(self, event):
        """Handle tank selection"""
        selection = self.tank_listbox.curselection()
        if selection:
            self.selected_tank = self.tank_listbox.get(selection[0])
        else:
            self.selected_tank = None

    def toggle_path_visibility(self):
        """Toggle path visibility for selected tank"""
        self.show_paths = not self.show_paths
        if self.show_paths and self.selected_tank:
            if self.selected_tank in self.tank_paths:
                self.map_widget.set_path(self.tank_paths[self.selected_tank])
        else:
            self.map_widget.delete_all_path()

    def clear_selected_path(self):
        """Clear path for selected tank"""
        if self.selected_tank and self.selected_tank in self.tank_paths:
            self.tank_paths[self.selected_tank] = []
            self.map_widget.delete_all_path()

    # def launch_clients(self):
    #     """Launch selected tank clients"""
    #     selected_indices = self.available_tanks_list.curselection()
    #     for idx in selected_indices:
    #         tank_id = self.available_tanks_list.get(idx)
    #         try:
    #             subprocess.Popen([sys.executable, "client4b.py", tank_id])
    #             self.log(f"Launched client for {tank_id}")
    #         except Exception as e:
    #             self.log(f"Error launching client for {tank_id}: {e}", "ERROR")


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
            self.log(f"Failed to launch client GUI for {tank_id}: {e}", level="ERROR")

    def move_tank_to_list(self, tank_id, status):
        """Move tank between available, online, and offline lists"""
        # Remove from all lists first
        lists = {
            "available": self.available_tanks_list,
            "online": self.online_tanks_list,
            "offline": self.offline_tanks_list
        }

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
    app = CommanderGUI(root)
    root.mainloop()
