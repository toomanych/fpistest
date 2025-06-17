"""
Variable Monitor Dialog
Allows users to add custom OPC-UA variables for monitoring in the main GUI.
Variables are displayed in the System Status section of each server.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Optional, Callable
import logging

logger = logging.getLogger(__name__)


class ServerConnection:
    """Server connection information (imported from main module)"""
    def __init__(self, name: str, url: str, client=None, connected: bool = False, controller_id: Optional[int] = None):
        self.name = name
        self.url = url
        self.client = client
        self.connected = connected
        self.controller_id = controller_id


class MonitorVariable:
    """Represents a custom variable to monitor"""
    def __init__(self, server_name: str, browse_path: List[str], label: str):
        self.server_name = server_name
        self.browse_path = browse_path  # ['1:abc', '1:qwe', ...]
        self.label = label
        self.current_value = "N/A"
        self.last_error = None

    def get_browse_path_string(self) -> str:
        """Get browse path as comma-separated string for display"""
        return ", ".join(self.browse_path)

    def __repr__(self):
        return "MonitorVariable(server={}, label={}, path={})".format(
            self.server_name, self.label, self.get_browse_path_string())


class VariableMonitorDialog:
    """
    Dialog for adding custom OPC-UA variables to monitor.
    Variables will appear in the System Status section of the main GUI.
    """
    
    def __init__(self, parent, servers: Dict[str, ServerConnection], 
                 add_variable_callback: Callable[[MonitorVariable], None]):
        """
        Initialize the variable monitor dialog.
        
        Args:
            parent: Parent tkinter widget
            servers: Dictionary of available server connections
            add_variable_callback: Callback function to add new variable to main GUI
        """
        self.parent = parent
        self.servers = servers
        self.add_variable_callback = add_variable_callback
        self.dialog = None
        
        # UI variables
        self.server_var = None
        self.label_var = None
        self.browse_path_var = None
        self.preview_text = None

    def show(self):
        """Show the variable monitor dialog"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Add OPC-UA Variable to Monitor")
        self.dialog.geometry("600x450")
        self.dialog.grab_set()
        self.dialog.resizable(True, True)
        
        self.create_dialog_widgets()
        self.update_server_options()
        
        # Center the dialog
        self.dialog.transient(self.parent)
        self.dialog.grab_set()

    def create_dialog_widgets(self):
        """Create dialog widgets"""
        
        # Main frame with padding
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Add Custom OPC-UA Variable to Monitor", 
                               font=('TkDefaultFont', 12, 'bold'))
        title_label.pack(pady=(0, 15))
        
        # Server selection frame
        server_frame = ttk.LabelFrame(main_frame, text="Server Selection", padding="10")
        server_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(server_frame, text="Server:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.server_var = tk.StringVar()
        self.server_combo = ttk.Combobox(server_frame, textvariable=self.server_var, 
                                        state="readonly", width=20)
        self.server_combo.grid(row=0, column=1, sticky="w")
        
        # Variable configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Variable Configuration", padding="10")
        config_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Label name
        ttk.Label(config_frame, text="Display Label:").grid(row=0, column=0, sticky="nw", padx=(0, 10), pady=(0, 10))
        self.label_var = tk.StringVar()
        label_entry = ttk.Entry(config_frame, textvariable=self.label_var, width=30)
        label_entry.grid(row=0, column=1, sticky="ew", pady=(0, 10))
        
        # Browse path
        ttk.Label(config_frame, text="Browse Path:").grid(row=1, column=0, sticky="nw", padx=(0, 10), pady=(0, 5))
        path_info_frame = ttk.Frame(config_frame)
        path_info_frame.grid(row=1, column=1, sticky="ew", pady=(0, 5))
        
        self.browse_path_var = tk.StringVar()
        path_entry = ttk.Entry(path_info_frame, textvariable=self.browse_path_var, width=40)
        path_entry.pack(fill="x")
        
        # Browse path help
        help_text = "Enter browse path as comma-separated strings, e.g.: 1:Objects, 1:MyFolder, 1:MyVariable"
        help_label = ttk.Label(path_info_frame, text=help_text, font=('TkDefaultFont', 8), 
                              foreground="gray", wraplength=400)
        help_label.pack(anchor="w", pady=(2, 0))
        
        # Configure grid weights
        config_frame.columnconfigure(1, weight=1)
        
        # Preview frame
        preview_frame = ttk.LabelFrame(main_frame, text="Preview", padding="10")
        preview_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Preview text
        self.preview_text = tk.Text(preview_frame, height=6, width=60, font=('TkDefaultFont', 9),
                                   state="disabled", wrap="word")
        preview_scroll = ttk.Scrollbar(preview_frame, orient="vertical", command=self.preview_text.yview)
        self.preview_text.configure(yscrollcommand=preview_scroll.set)
        
        self.preview_text.pack(side="left", fill="both", expand=True)
        preview_scroll.pack(side="right", fill="y")
        
        # Update preview when fields change
        self.server_var.trace('w', self.update_preview)
        self.label_var.trace('w', self.update_preview)
        self.browse_path_var.trace('w', self.update_preview)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        
        # Validate button
        ttk.Button(button_frame, text="Validate Path", 
                  command=self.validate_browse_path).pack(side="left", padx=(0, 10))
        
        # Spacer
        ttk.Frame(button_frame).pack(side="left", expand=True)
        
        # OK and Cancel buttons
        ttk.Button(button_frame, text="OK", 
                  command=self.on_ok).pack(side="right", padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", 
                  command=self.on_cancel).pack(side="right")

    def update_server_options(self):
        """Update available server options"""
        connected_servers = []
        
        # Include all servers (connected and disconnected) for monitoring setup
        for server_name in self.servers.keys():
            connected_servers.append(server_name)
            
        if not connected_servers:
            messagebox.showerror("No Servers", "No servers are configured.")
            self.close_dialog()
            return
            
        # Update combobox
        self.server_combo.config(values=connected_servers)
        if connected_servers:
            self.server_combo.current(0)

    def update_preview(self, *args):
        """Update the preview text based on current selections"""
        server = self.server_var.get()
        label = self.label_var.get()
        browse_path_str = self.browse_path_var.get()
        
        # Parse browse path
        try:
            browse_path = self.parse_browse_path(browse_path_str)
            path_valid = len(browse_path) > 0
        except Exception as e:
            browse_path = []
            path_valid = False
        
        # Generate preview
        preview_lines = []
        preview_lines.append("Variable Configuration Preview:")
        preview_lines.append("=" * 40)
        preview_lines.append("")
        
        if server:
            server_status = "Connected" if (server in self.servers and self.servers[server].connected) else "Disconnected"
            preview_lines.append("Server: {} ({})".format(server, server_status))
        else:
            preview_lines.append("Server: <Not selected>")
        
        if label:
            preview_lines.append("Display Label: {}".format(label))
        else:
            preview_lines.append("Display Label: <Not specified>")
        
        if browse_path_str:
            preview_lines.append("Browse Path Input: {}".format(browse_path_str))
            if path_valid:
                preview_lines.append("Parsed Path: {}".format(browse_path))
                preview_lines.append("Path Elements: {} items".format(len(browse_path)))
            else:
                preview_lines.append("Parsed Path: <Invalid format>")
        else:
            preview_lines.append("Browse Path: <Not specified>")
        
        preview_lines.append("")
        
        # Validation status
        if server and label and path_valid:
            preview_lines.append("Status: ✓ Ready to add variable")
            preview_lines.append("")
            preview_lines.append("This variable will appear in the '{}' server status section".format(server))
            preview_lines.append("as: {} = <current value>".format(label))
        else:
            missing = []
            if not server: missing.append("server")
            if not label: missing.append("display label")
            if not path_valid: missing.append("valid browse path")
            preview_lines.append("Status: ✗ Missing: {}".format(", ".join(missing)))
        
        # Update preview text
        self.preview_text.config(state="normal")
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, "\n".join(preview_lines))
        self.preview_text.config(state="disabled")

    def parse_browse_path(self, browse_path_str: str) -> List[str]:
        """Parse browse path string into list of strings"""
        if not browse_path_str.strip():
            return []
        
        # Split by comma and clean up
        elements = [elem.strip() for elem in browse_path_str.split(',')]
        
        # Remove empty elements
        elements = [elem for elem in elements if elem]
        
        # Validate format (each element should contain a colon for namespace)
        for elem in elements:
            if ':' not in elem:
                raise ValueError("Browse path elements should be in format 'namespace:name', got: {}".format(elem))
        
        return elements

    def validate_browse_path(self):
        """Validate the browse path by attempting to read from the server"""
        server = self.server_var.get()
        browse_path_str = self.browse_path_var.get()
        
        if not server:
            messagebox.showwarning("Validation Error", "Please select a server first.")
            return
        
        if not browse_path_str.strip():
            messagebox.showwarning("Validation Error", "Please enter a browse path.")
            return
        
        # Check if server is connected
        if server not in self.servers or not self.servers[server].connected:
            messagebox.showwarning("Validation Error", 
                                 "Server '{}' is not connected. Cannot validate browse path.".format(server))
            return
        
        try:
            # Parse browse path
            browse_path = self.parse_browse_path(browse_path_str)
            
            # Attempt to read from server
            client = self.servers[server].client
            objects = client.get_objects_node()
            
            # Navigate to the node
            current_node = objects
            for element in browse_path:
                current_node = current_node.get_child([element])
            
            # Try to read the value
            value = current_node.get_value()
            
            messagebox.showinfo("Validation Success", 
                              "✓ Browse path is valid!\n\nCurrent value: {}".format(value))
            
        except Exception as e:
            messagebox.showerror("Validation Failed", 
                               "✗ Failed to read from browse path:\n\n{}".format(str(e)))

    def on_ok(self):
        """Handle OK button click"""
        server = self.server_var.get()
        label = self.label_var.get().strip()
        browse_path_str = self.browse_path_var.get().strip()
        
        # Validate inputs
        if not server:
            messagebox.showerror("Input Error", "Please select a server.")
            return
        
        if not label:
            messagebox.showerror("Input Error", "Please enter a display label.")
            return
        
        if not browse_path_str:
            messagebox.showerror("Input Error", "Please enter a browse path.")
            return
        
        try:
            # Parse browse path
            browse_path = self.parse_browse_path(browse_path_str)
            
            if len(browse_path) == 0:
                messagebox.showerror("Input Error", "Browse path cannot be empty.")
                return
            
            # Create monitor variable
            monitor_var = MonitorVariable(server, browse_path, label)
            
            # Add to main GUI via callback
            self.add_variable_callback(monitor_var)
            
            # Show success message
            messagebox.showinfo("Variable Added", 
                              "Variable '{}' has been added to {} monitoring.".format(label, server))
            
            # Close dialog
            self.close_dialog()
            
        except Exception as e:
            messagebox.showerror("Input Error", 
                               "Invalid browse path format:\n\n{}".format(str(e)))

    def on_cancel(self):
        """Handle Cancel button click"""
        self.close_dialog()

    def close_dialog(self):
        """Close the dialog"""
        if self.dialog:
            self.dialog.destroy()


def create_variable_monitor_dialog(parent, servers: Dict[str, ServerConnection], 
                                 add_variable_callback: Callable[[MonitorVariable], None]):
    """
    Factory function to create and show the variable monitor dialog.
    
    Args:
        parent: Parent tkinter widget
        servers: Dictionary of server connections
        add_variable_callback: Callback function to add new variable to main GUI
        
    Example usage in main_gui.py:
        def add_custom_variable(monitor_var: MonitorVariable):
            # Add to monitoring list
            self.custom_variables.append(monitor_var)
            
        dialog = create_variable_monitor_dialog(self.root, self.servers, add_custom_variable)
        dialog.show()
    """
    dialog = VariableMonitorDialog(parent, servers, add_variable_callback)
    dialog.show()
    return dialog


# Example integration for main_gui.py:
#
# 1. Import the dialog:
#    from variable_monitor_dialog import create_variable_monitor_dialog, MonitorVariable
#
# 2. Add custom variables list to main GUI class:
#    self.custom_variables = []  # List[MonitorVariable]
#
# 3. Add callback method to main GUI class:
#    def add_custom_variable(self, monitor_var: MonitorVariable):
#        self.custom_variables.append(monitor_var)
#        logger.info("Added custom variable: {}".format(monitor_var))
#
# 4. Add button next to HIOC Configuration:
#    ttk.Button(frame, text="Add Variable Monitor", 
#              command=lambda: create_variable_monitor_dialog(
#                  self.root, self.servers, self.add_custom_variable)).pack(...)
#
# 5. Update status monitoring to include custom variables:
#    def update_status_display(self):
#        # ... existing status updates ...
#        
#        # Update custom variables
#        for monitor_var in self.custom_variables:
#            if monitor_var.server_name in self.servers and self.servers[monitor_var.server_name].connected:
#                try:
#                    client = self.servers[monitor_var.server_name].client
#                    objects = client.get_objects_node()
#                    node = objects
#                    for element in monitor_var.browse_path:
#                        node = node.get_child([element])
#                    value = node.get_value()
#                    monitor_var.current_value = str(value)
#                    monitor_var.last_error = None
#                except Exception as e:
#                    monitor_var.current_value = "Error"
#                    monitor_var.last_error = str(e)
#            else:
#                monitor_var.current_value = "N/A"
#        
#        # Display custom variables in server status sections
#        for server_name, server_info in self.servers.items():
#            server_custom_vars = [v for v in self.custom_variables if v.server_name == server_name]
#            for monitor_var in server_custom_vars:
#                # Add to server status display: monitor_var.label = monitor_var.current_value
