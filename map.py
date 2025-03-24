import tkinter as tk
from tkintermapview import TkinterMapView

class MapGUI:
    def __init__(self, parent):
        self.parent = parent
        self.setup_map()

    def setup_map(self):
        """Setup the map widget and controls."""
        # Create map widget
        self.map_widget = TkinterMapView(self.parent, width=400, height=400, corner_radius=0)
        self.map_widget.pack(fill="both", expand=True)

        # Set default position (example coordinates)
        self.map_widget.set_position(51.5074, -0.1278)  # London coordinates as default
        self.map_widget.set_zoom(10)

        # Control panel
        control_frame = tk.Frame(self.parent, bg="#ffffff")
        control_frame.pack(fill="x", padx=5, pady=5)

        # Zoom controls
        zoom_frame = tk.Frame(control_frame, bg="#ffffff")
        zoom_frame.pack(side="left", padx=5)

        zoom_in_btn = tk.Button(zoom_frame, text="+", command=lambda: self.map_widget.set_zoom(self.map_widget.zoom + 1))
        zoom_in_btn.pack(side="left", padx=2)

        zoom_out_btn = tk.Button(zoom_frame, text="-", command=lambda: self.map_widget.set_zoom(self.map_widget.zoom - 1))
        zoom_out_btn.pack(side="left", padx=2)

    def add_marker(self, lat, lon, text=""):
        """Add a marker to the map."""
        return self.map_widget.set_marker(lat, lon, text=text)

    def remove_marker(self, marker):
        """Remove a marker from the map."""
        marker.delete()

    def set_position(self, lat, lon, zoom=None):
        """Set the map position and optionally zoom level."""
        self.map_widget.set_position(lat, lon)
        if zoom is not None:
            self.map_widget.set_zoom(zoom)

    def clear_markers(self):
        """Clear all markers from the map."""
        self.map_widget.delete_all_marker()


def main():
    root = tk.Tk()
    root.title("Map GUI Example")
    root.geometry("800x600")

    # Create a frame for the map
    map_frame = tk.Frame(root, bg="#ffffff", bd=1, relief="solid")
    map_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Initialize the MapGUI
    map_gui = MapGUI(map_frame)

    # Example usage: Add a marker
    map_gui.add_marker(51.5074, -0.1278, "London")

    root.mainloop()

if __name__ == "__main__":
    main()