"""
Main GUI Application
ITER OPC-UA Control System with HIOC/HIOCwSUP, COS/PSOS, and IOP support
UPDATED: Added minimal variable monitoring integration
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from typing import Dict, Optional, List
from opcua import Client
import logging

# Import our modules
from cos_operator import COSOperator, COSCommand, COSState, PSOSState, SystemState
from hioc_module import HIOCDialog, ServerConnection

# NEW: Import variable monitoring functionality
from variable_monitor_dialog import create_variable_monitor_dialog, MonitorVariable

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Reduce OPC-UA library logging
logging.getLogger('opcua').setLevel(logging.WARNING)


class MainGUI:
    """
    Main GUI application for ITER OPC-UA control systems.
    Handles CG1, CG2, and FPIS servers with COS/PSOS/IOP monitoring and HIOC operations.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("ITER OPC-UA Control System - COS/PSOS/IOP/HIOC")
        self.root.geometry("1280x600")  # CHANGED: Updated window size
        
        # Server configurations with ServerConnection objects
        self.servers = {
            'CG1': ServerConnection(
                name='CG1',
                url='opc.tcp://4602tv-cpu-4201.codac.iter.org:4840',
                controller_id=1464099
            ),
            'CG2': ServerConnection(
                name='CG2', 
                url='opc.tcp://4602tv-cpu-4202.codac.iter.org:4840',
                controller_id=1464098
            ),
            'FPIS': ServerConnection(
                name='FPIS',
                url='opc.tcp://4602tv-SRV-5101.codac.iter.org:4840'
            )
        }
        
        # NEW: Custom variables for monitoring
        self.custom_variables = []  # List[MonitorVariable]
        
        # COS operator for CG1/CG2
        self.cos_operator = COSOperator()
        self.setup_cos_operator()
        
        # IOP command values for FPIS
        self.iop_commands = {
            0: 'In-Pulse',
            3: 'Out-of-Pulse'
        }
        
        # IOP state colors
        self.iop_state_colors = {
            0: '#4ECDC4',  # Light Teal
            3: '#FF6B6B'   # Light Red
        }
        
        # Monitoring
        self.monitoring = True
        self.monitor_thread = None
        
        # UI elements
        self.connection_labels = {}
        self.connection_buttons = {}
        self.server_status_frames = {}
        self.status_labels = {}
        
        self.create_widgets()
        self.update_connection_status()
        self.start_monitoring()

    def setup_cos_operator(self):
        """Setup COS operator with server configurations"""
        for server_name, server_info in self.servers.items():
            if server_name in ['CG1', 'CG2']:
                self.cos_operator.add_server(server_name, server_info.url)

    def create_widgets(self):
        """Create main GUI widgets"""
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure main grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(2, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Server connection frame
        self.create_connection_frame(main_frame)
        
        # Command frames
        self.create_command_frames(main_frame)
        
        # Status monitoring frame
        self.create_status_frame(main_frame)

    def create_connection_frame(self, parent):
        """Create server connection frame"""
        conn_frame = ttk.LabelFrame(parent, text="Server Connections", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        for i, (server_name, server_info) in enumerate(self.servers.items()):
            # Server name
            ttk.Label(conn_frame, text="{}:".format(server_name), 
                     font=('TkDefaultFont', 10, 'bold')).grid(
                row=i, column=0, sticky=tk.W, padx=(0, 10))
            
            # Connection status
            self.connection_labels[server_name] = ttk.Label(
                conn_frame, text="Disconnected", foreground="red", width=12)
            self.connection_labels[server_name].grid(
                row=i, column=1, sticky=tk.W, padx=(0, 10))
            
            # Connect/Disconnect button
            self.connection_buttons[server_name] = ttk.Button(
                conn_frame, text="Connect", width=12,
                command=lambda s=server_name: self.toggle_connection(s))
            self.connection_buttons[server_name].grid(row=i, column=2, padx=5)
            
            # URL entry
            url_var = tk.StringVar(value=server_info.url)
            url_entry = ttk.Entry(conn_frame, textvariable=url_var, width=40)
            url_entry.grid(row=i, column=3, padx=(10, 0))
            url_entry.bind('<FocusOut>', 
                          lambda e, s=server_name, v=url_var: self.update_server_url(s, v.get()))

    def create_command_frames(self, parent):
        """Create command control frames"""
        # COS Commands frame
        cos_frame = ttk.LabelFrame(parent, text="COS Commands", padding="10")
        cos_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N), pady=(0, 10))
        
        # COS command buttons
        commands = [
            (COSCommand.GOTO_READY, 0, 0),
            (COSCommand.GOTO_LOCAL, 0, 1),
            (COSCommand.GO_NOT_READY, 0, 2),
            (COSCommand.INITIALISE, 1, 0),
            (COSCommand.ABORT, 1, 1),
            (COSCommand.EXECUTE, 1, 2),
            (COSCommand.POST_CHECK, 2, 0)
        ]
        
        for command, row, col in commands:
            btn = ttk.Button(
                cos_frame, 
                text="{}\n({})".format(command.description, command.int_value),
                command=lambda cmd=command: self.send_cos_command_dialog(cmd),
                width=15
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # IOP Commands frame (FPIS only)
        iop_frame = ttk.LabelFrame(parent, text="IOP Commands (FPIS Only)", padding="10")
        iop_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N), pady=(0, 10), padx=(10, 0))
        
        for i, (value, description) in enumerate(self.iop_commands.items()):
            btn = ttk.Button(
                iop_frame,
                text="{}\n({})".format(description, value),
                command=lambda v=value: self.send_iop_command(v),
                width=15
            )
            btn.grid(row=0, column=i, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # HIOC Commands frame - UPDATED: Added variable monitor button
        hioc_frame = ttk.LabelFrame(parent, text="HIOC Configuration", padding="10")
        hioc_frame.grid(row=1, column=2, sticky=(tk.W, tk.E, tk.N), pady=(0, 10), padx=(10, 0))
        
        ttk.Button(
            hioc_frame,
            text="Open HIOC\nConfiguration",
            command=self.open_hioc_dialog,
            width=15
        ).grid(row=0, column=0, padx=5, pady=5)
        
        # NEW: Add Variable Monitor button
        ttk.Button(
            hioc_frame,
            text="Add Variable\nMonitor",
            command=self.open_variable_monitor_dialog,
            width=15
        ).grid(row=0, column=1, padx=5, pady=5)

    def create_status_frame(self, parent):
        """Create status monitoring frame"""
        status_main_frame = ttk.LabelFrame(parent, text="System Status", padding="10")
        status_main_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure status frame grid
        status_main_frame.columnconfigure(0, weight=1)
        status_main_frame.columnconfigure(1, weight=1)
        status_main_frame.columnconfigure(2, weight=1)
        
        # Create individual server status frames
        for i, server_name in enumerate(['CG1', 'CG2', 'FPIS']):
            self.create_server_status_frame(status_main_frame, server_name, i)

    def create_server_status_frame(self, parent, server_name: str, column: int):
        """Create status frame for individual server"""
        server_frame = ttk.LabelFrame(parent, text="{} Status".format(server_name), padding="10")
        server_frame.grid(row=0, column=column, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        server_frame.config(width=340)  # NEW: Set fixed width for each server pane
        
        self.server_status_frames[server_name] = server_frame
        self.status_labels[server_name] = {}
        
        # Configure server frame grid
        server_frame.columnconfigure(1, weight=1)
        
        row = 0
        
        # COS State (or PSOS State for FPIS)
        if server_name == 'FPIS':
            ttk.Label(server_frame, text="PSOS State:", font=('TkDefaultFont', 9, 'bold')).grid(
                row=row, column=0, sticky=tk.W, pady=2)
        else:
            ttk.Label(server_frame, text="COS State:", font=('TkDefaultFont', 9, 'bold')).grid(
                row=row, column=0, sticky=tk.W, pady=2)
        
        self.status_labels[server_name]['COS'] = ttk.Label(
            server_frame, text="N/A", relief="sunken", width=25, anchor="center")
        self.status_labels[server_name]['COS'].grid(
            row=row, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
        row += 1
        
        # PSOS State (not for FPIS)
        if server_name != 'FPIS':
            ttk.Label(server_frame, text="PSOS State:", font=('TkDefaultFont', 9, 'bold')).grid(
                row=row, column=0, sticky=tk.W, pady=2)
            self.status_labels[server_name]['PSOS'] = ttk.Label(
                server_frame, text="N/A", relief="sunken", width=25, anchor="center")
            self.status_labels[server_name]['PSOS'].grid(
                row=row, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
            row += 1
        
        # NEW: Custom variables will be added here (below PSOS, before IOP)
        # Store the current row for later use
        self.status_labels[server_name]['_custom_row_start'] = row
        
        # IOP Status
        ttk.Label(server_frame, text="IOP Status:", font=('TkDefaultFont', 9, 'bold')).grid(
            row=row, column=0, sticky=tk.W, pady=2)
        self.status_labels[server_name]['IOP'] = ttk.Label(
            server_frame, text="N/A", relief="sunken", width=25, anchor="center")
        self.status_labels[server_name]['IOP'].grid(
            row=row, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
        row += 1
        
        # PCS WD Threshold (only for CG1/CG2)
        if server_name in ['CG1', 'CG2']:
            ttk.Label(server_frame, text="PCS WD Threshold:", font=('TkDefaultFont', 9, 'bold')).grid(
                row=row, column=0, sticky=tk.W, pady=2)
            self.status_labels[server_name]['PCS_WD'] = ttk.Label(
                server_frame, text="N/A", relief="sunken", width=25, anchor="center")
            self.status_labels[server_name]['PCS_WD'].grid(
                row=row, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)

    # NEW: Method to add custom variables
    def add_custom_variable(self, monitor_var: MonitorVariable):
        """Add a custom variable to monitoring"""
        self.custom_variables.append(monitor_var)
        logger.info("Added custom variable '{}' for server '{}' at path: {}".format(
            monitor_var.label, monitor_var.server_name, monitor_var.get_browse_path_string()))
        
        # Update the display for this server
        self.update_custom_variables_display(monitor_var.server_name)

    # NEW: Method to open variable monitor dialog
    def open_variable_monitor_dialog(self):
        """Open the variable monitor dialog"""
        try:
            create_variable_monitor_dialog(self.root, self.servers, self.add_custom_variable)
        except Exception as e:
            messagebox.showerror("Dialog Error", "Failed to open variable monitor dialog:\n{}".format(e))
            logger.error("Failed to open variable monitor dialog: {}".format(e))

    # NEW: Update custom variables display
    def update_custom_variables_display(self, server_name: str):
        """Update display of custom variables for a specific server - insert between PSOS and IOP"""
        if server_name not in self.status_labels:
            return
        
        server_frame = self.server_status_frames[server_name]
        
        # Remove existing custom variable labels
        for widget_name in list(self.status_labels[server_name].keys()):
            if widget_name.startswith('custom_'):
                widget = self.status_labels[server_name][widget_name]
                widget.destroy()
                del self.status_labels[server_name][widget_name]
        
        # Get custom variables for this server
        server_custom_vars = [v for v in self.custom_variables if v.server_name == server_name]
        
        # Get the starting row for custom variables (after PSOS, before IOP)
        custom_row_start = self.status_labels[server_name]['_custom_row_start']
        
        if server_custom_vars:
            # Calculate total rows needed for custom variables
            num_custom_vars = len(server_custom_vars)
            
            # First, move IOP and PCS_WD widgets down to make space
            # Find and move IOP label and value
            iop_row = custom_row_start  # IOP was originally at custom_row_start
            new_iop_row = custom_row_start + num_custom_vars
            
            # Move IOP label
            for widget in server_frame.grid_slaves(row=iop_row, column=0):
                if isinstance(widget, ttk.Label) and "IOP" in widget.cget("text"):
                    widget.grid(row=new_iop_row, column=0, sticky=tk.W, pady=2)
                    break
            
            # Move IOP value
            if 'IOP' in self.status_labels[server_name]:
                self.status_labels[server_name]['IOP'].grid(
                    row=new_iop_row, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
            
            # Move PCS_WD widgets if they exist (only for CG1/CG2)
            if server_name in ['CG1', 'CG2'] and 'PCS_WD' in self.status_labels[server_name]:
                pcs_wd_row = iop_row + 1  # PCS_WD was originally after IOP
                new_pcs_wd_row = new_iop_row + 1
                
                # Move PCS_WD label
                for widget in server_frame.grid_slaves(row=pcs_wd_row, column=0):
                    if isinstance(widget, ttk.Label) and "PCS WD" in widget.cget("text"):
                        widget.grid(row=new_pcs_wd_row, column=0, sticky=tk.W, pady=2)
                        break
                
                # Move PCS_WD value
                self.status_labels[server_name]['PCS_WD'].grid(
                    row=new_pcs_wd_row, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
            
            # Now add custom variables in the cleared space
            for i, monitor_var in enumerate(server_custom_vars):
                row = custom_row_start + i
                
                # Create label
                var_label = ttk.Label(server_frame, text="{}:".format(monitor_var.label), 
                                     font=('TkDefaultFont', 9, 'bold'))
                var_label.grid(row=row, column=0, sticky=tk.W, pady=2)
                
                # Create value label with appropriate color
                if monitor_var.current_value == "Error":
                    value_color = "red"
                elif monitor_var.current_value == "N/A":
                    value_color = "gray"
                else:
                    value_color = "black"
                
                var_value = ttk.Label(server_frame, text=monitor_var.current_value, 
                                     relief="sunken", width=25, anchor="center", foreground=value_color)
                var_value.grid(row=row, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
                
                # Store references
                self.status_labels[server_name]['custom_{}_label'.format(i)] = var_label
                self.status_labels[server_name]['custom_{}_value'.format(i)] = var_value
                
                # Store reference in monitor variable for updates
                monitor_var._gui_label = var_value
        
        else:
            # No custom variables - make sure IOP and PCS_WD are in their original positions
            # Move IOP back to original position if it was moved
            if 'IOP' in self.status_labels[server_name]:
                # Find IOP label and move back
                for widget in server_frame.grid_slaves():
                    if isinstance(widget, ttk.Label) and "IOP" in widget.cget("text"):
                        widget.grid(row=custom_row_start, column=0, sticky=tk.W, pady=2)
                        break
                
                # Move IOP value back
                self.status_labels[server_name]['IOP'].grid(
                    row=custom_row_start, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
            
            # Move PCS_WD back if it exists
            if server_name in ['CG1', 'CG2'] and 'PCS_WD' in self.status_labels[server_name]:
                for widget in server_frame.grid_slaves():
                    if isinstance(widget, ttk.Label) and "PCS WD" in widget.cget("text"):
                        widget.grid(row=custom_row_start + 1, column=0, sticky=tk.W, pady=2)
                        break
                
                self.status_labels[server_name]['PCS_WD'].grid(
                    row=custom_row_start + 1, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)

    # NEW: Update custom variables in background monitoring
    def update_custom_variables(self):
        """Update custom variables from background thread"""
        for monitor_var in self.custom_variables:
            server_name = monitor_var.server_name
            
            if server_name in self.servers and self.servers[server_name].connected:
                try:
                    client = self.servers[server_name].client
                    objects = client.get_objects_node()
                    
                    # Navigate through the browse path
                    current_node = objects
                    for element in monitor_var.browse_path:
                        current_node = current_node.get_child([element])
                    
                    # Read the value
                    value = current_node.get_value()
                    monitor_var.current_value = str(value)
                    monitor_var.last_error = None
                    
                    # Update GUI label if it exists
                    if hasattr(monitor_var, '_gui_label') and monitor_var._gui_label:
                        def update_label(v=str(value), l=monitor_var._gui_label):
                            l.config(text=v, foreground="black")
                        self.root.after(0, update_label)
                    
                except Exception as e:
                    monitor_var.current_value = "Error"
                    monitor_var.last_error = str(e)
                    
                    # Update GUI label if it exists
                    if hasattr(monitor_var, '_gui_label') and monitor_var._gui_label:
                        def update_error_label(l=monitor_var._gui_label):
                            l.config(text="Error", foreground="red")
                        self.root.after(0, update_error_label)
                    
                    logger.debug("Failed to read custom variable '{}' for {}: {}".format(
                        monitor_var.label, server_name, e))
            else:
                monitor_var.current_value = "N/A"
                monitor_var.last_error = "Server not connected"
                
                # Update GUI label if it exists
                if hasattr(monitor_var, '_gui_label') and monitor_var._gui_label:
                    def update_na_label(l=monitor_var._gui_label):
                        l.config(text="N/A", foreground="gray")
                    self.root.after(0, update_na_label)

    def update_server_url(self, server_name: str, url: str):
        """Update server URL"""
        self.servers[server_name].url = url
        if server_name in ['CG1', 'CG2']:
            self.cos_operator.update_server_url(server_name, url)

    def toggle_connection(self, server_name: str):
        """Toggle server connection"""
        server_info = self.servers[server_name]
        
        if server_info.connected:
            self.disconnect_server(server_name)
        else:
            self.connect_server(server_name)
        
        self.update_connection_status()

    def connect_server(self, server_name: str):
        """Connect to server"""
        server_info = self.servers[server_name]
        
        try:
            if server_info.client is None:
                server_info.client = Client(server_info.url)
            
            server_info.client.connect()
            server_info.connected = True
            
            # Also connect via COS operator for CG1/CG2
            if server_name in ['CG1', 'CG2']:
                self.cos_operator.connect_server(server_name)
            
            logger.info("Connected to {}".format(server_name))
            
        except Exception as e:
            logger.error("Failed to connect to {}: {}".format(server_name, e))
            server_info.connected = False
            messagebox.showerror("Connection Error", "Failed to connect to {}:\n{}".format(server_name, e))

    def disconnect_server(self, server_name: str):
        """Disconnect from server"""
        server_info = self.servers[server_name]
        
        try:
            if server_info.client and server_info.connected:
                server_info.client.disconnect()
            
            server_info.connected = False
            
            # Also disconnect via COS operator for CG1/CG2  
            if server_name in ['CG1', 'CG2']:
                self.cos_operator.disconnect_server(server_name)
            
            logger.info("Disconnected from {}".format(server_name))
            
        except Exception as e:
            logger.error("Error disconnecting from {}: {}".format(server_name, e))
            server_info.connected = False

    def update_connection_status(self):
        """Update connection status display"""
        for server_name, server_info in self.servers.items():
            if server_info.connected:
                self.connection_labels[server_name].config(text="Connected", foreground="green")
                self.connection_buttons[server_name].config(text="Disconnect")
            else:
                self.connection_labels[server_name].config(text="Disconnected", foreground="red")
                self.connection_buttons[server_name].config(text="Connect")

    def send_cos_command_dialog(self, command: COSCommand):
        """Show dialog to select servers for COS command"""
        # Create selection dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Send COS Command: {}".format(command.description))
        dialog.geometry("400x200")
        dialog.grab_set()
        
        ttk.Label(dialog, text="Send '{}' command to:".format(command.description),
                 font=('TkDefaultFont', 10, 'bold')).pack(pady=10)
        
        # Server selection
        server_vars = {}
        connected_servers = [name for name, info in self.servers.items() 
                           if name in ['CG1', 'CG2'] and info.connected]
        
        if not connected_servers:
            ttk.Label(dialog, text="No CG servers connected!", foreground="red").pack(pady=10)
            ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
            return
        
        for server_name in ['CG1', 'CG2']:
            if server_name in connected_servers:
                var = tk.BooleanVar()
                server_vars[server_name] = var
                ttk.Checkbutton(dialog, text=server_name, variable=var).pack(pady=5)
        
        # FPIS option
        if self.servers['FPIS'].connected:
            fpis_var = tk.BooleanVar()
            server_vars['FPIS'] = fpis_var
            ttk.Checkbutton(dialog, text="FPIS", variable=fpis_var).pack(pady=5)
        
        def send_command():
            selected_cg_servers = [name for name, var in server_vars.items() 
                                 if name in ['CG1', 'CG2'] and var.get()]
            send_to_fpis = server_vars.get('FPIS', tk.BooleanVar()).get()
            
            if not selected_cg_servers and not send_to_fpis:
                messagebox.showwarning("No Selection", "Please select at least one server.")
                return
            
            dialog.destroy()
            self.send_cos_command(command, selected_cg_servers, send_to_fpis)
        
        ttk.Button(dialog, text="Send Command", command=send_command).pack(pady=10)
        ttk.Button(dialog, text="Cancel", command=dialog.destroy).pack()

    def send_cos_command(self, command: COSCommand, cg_servers: List[str], send_to_fpis: bool):
        """Send COS command to selected servers"""
        results = []
        
        # Send to CG servers via COS operator
        if cg_servers:
            result = self.cos_operator.write_cos_command_multiple(cg_servers, command)
            for server_name, success in result.server_results.items():
                status = "✓" if success else "✗"
                results.append("{}: {}".format(server_name, status))
        
        # Send to FPIS directly
        if send_to_fpis:
            success = self.send_fpis_cos_command(command.int_value)  # Use int_value
            status = "✓" if success else "✗"
            results.append("FPIS: {}".format(status))
        
        # Show results
        result_msg = "COS Command '{}' results:\n{}".format(command.description, "\n".join(results))
        messagebox.showinfo("Command Results", result_msg)

    def send_fpis_cos_command(self, value: int) -> bool:
        """Send COS command directly to FPIS"""
        if not self.servers['FPIS'].connected:
            return False
        
        try:
            client = self.servers['FPIS'].client
            objects = client.get_objects_node()
            
            opreq_node = objects.get_child(["1:STF_In", "1:OPREQ"])
            opreq_node.set_value(value)  # value is already an int from command.int_value
            
            logger.info("Sent COS command {} to FPIS".format(value))
            return True
            
        except Exception as e:
            logger.error("Failed to send COS command to FPIS: {}".format(e))
            return False

    def send_iop_command(self, value: int):
        """Send IOP command to FPIS"""
        description = self.iop_commands[value]
        
        result = messagebox.askyesno(
            "Confirm IOP Command",
            "Send IOP command '{}' (value: {}) to FPIS?".format(description, value)
        )
        
        if result:
            success = self.send_fpis_iop_command(value)
            if success:
                messagebox.showinfo("IOP Command", "IOP command '{}' sent successfully to FPIS.".format(description))
            else:
                messagebox.showerror("IOP Command", "Failed to send IOP command '{}' to FPIS.".format(description))

    def send_fpis_iop_command(self, value: int) -> bool:
        """Send IOP command to FPIS"""
        if not self.servers['FPIS'].connected:
            return False
        
        try:
            client = self.servers['FPIS'].client
            objects = client.get_objects_node()
            
            iopulse_node = objects.get_child(["1:STF_In", "1:IOPULSE"])
            iopulse_node.set_value(value)
            
            logger.info("Sent IOP command {} to FPIS".format(value))
            return True
            
        except Exception as e:
            logger.error("Failed to send IOP command to FPIS: {}".format(e))
            return False

    def open_hioc_dialog(self):
        """Open HIOC configuration dialog"""
        dialog = HIOCDialog(self.root, self.servers)
        dialog.show()

    def start_monitoring(self):
        """Start status monitoring thread"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_status, daemon=True)
        self.monitor_thread.start()

    def monitor_status(self):
        """Monitor server status in background thread"""
        while self.monitoring:
            try:
                # Update COS operator states for CG1/CG2
                states = self.cos_operator.read_all_system_states()
                for server_name, state in states.items():
                    if server_name in ['CG1', 'CG2']:
                        self.root.after(0, self.update_server_display, server_name, state)
                
                # Update FPIS status directly
                if self.servers['FPIS'].connected:
                    fpis_state = self.read_fpis_status()
                    self.root.after(0, self.update_fpis_display, fpis_state)
                
                # Update IOP status from FPIS
                iop_states = self.read_iop_status()
                self.root.after(0, self.update_iop_displays, iop_states)
                
                # Update PCS WD thresholds for CG1/CG2
                for server_name in ['CG1', 'CG2']:
                    if self.servers[server_name].connected:
                        threshold = self.read_pcs_wd_threshold(server_name)
                        self.root.after(0, self.update_pcs_wd_display, server_name, threshold)
                
                # NEW: Update custom variables
                self.update_custom_variables()
                
                time.sleep(0.3)  # 300ms polling
                
            except Exception as e:
                logger.error("Error in monitoring thread: {}".format(e))
                time.sleep(1)

    def read_fpis_status(self) -> Optional[SystemState]:
        """Read FPIS status directly (FPIS reports PSOS states, not COS states)"""
        try:
            client = self.servers['FPIS'].client
            objects = client.get_objects_node()
            
            cos_node = objects.get_child(["1:FTS_Out", "1:PSOS", "1:OPSTATE"])
            psos_value = cos_node.get_value()  # This is actually a PSOS state value
            
            # Map PSOS state to equivalent COS state for display purposes
            cos_state = self._map_psos_to_cos_for_display(psos_value)
            
            return SystemState(
                server_name='FPIS',
                connected=True,
                cos_state=cos_state,
                psos_state=None,  # FPIS doesn't have separate PSOS display
                cos_raw_value=psos_value,  # Show actual PSOS value
                psos_raw_value=None
            )
            
        except Exception as e:
            logger.error("Failed to read FPIS status: {}".format(e))
            return None

    def _map_psos_to_cos_for_display(self, psos_value: int):
        """Map PSOS state values to equivalent COS states for display purposes"""
        # PSOS to COS mapping for states that have congruence
        psos_to_cos_mapping = {
            1: 1,   # OFF -> OFF
            2: 2,   # NOT_READY -> NOT_READY  
            3: 3,   # READY -> READY
            4: 4,   # INITIALISING -> INITIALISING
            5: 5,   # INITIALISED -> INITIALISED
            6: 6,   # EXECUTING -> EXECUTING
            7: 7,   # POST_PULSE_CHECKS -> POST_PULSE_CHECKS
            8: 9,   # TERMINATING -> ABORTING (closest equivalent)
            9: 9,   # ABORTING -> ABORTING
            10: 9,  # PLANT_ABORT_91 -> ABORTING (closest equivalent)
            11: 9,  # INHIBIT_NEXT_PULSE -> ABORTING (closest equivalent)
            12: 11, # PSOS LOCAL -> COS LOCAL
            13: 4,  # CONFIGURE -> INITIALISING (closest equivalent)
            14: 9   # PLANT_ABORT_92 -> ABORTING (closest equivalent)
        }
        
        # Map PSOS value to equivalent COS value, then get COS state
        cos_equivalent_value = psos_to_cos_mapping.get(psos_value, 1)  # Default to OFF
        cos_state = self.cos_operator.get_cos_state_by_value(cos_equivalent_value)
        
        # If we mapped to a different state, create a custom display state
        # that shows the original PSOS state name but uses COS colors
        if psos_value != cos_equivalent_value and cos_state:
            psos_state_names = {
                8: 'TERMINATING',
                10: 'PLANT_ABORT_91', 
                11: 'INHIBIT_NEXT_PULSE',
                13: 'CONFIGURE',
                14: 'PLANT_ABORT_92'
            }
            
            if psos_value in psos_state_names:
                # Create a custom state object that shows PSOS name with COS color
                class CustomDisplayState:
                    def __init__(self, psos_name, cos_color, psos_value):
                        self.state_name = psos_name
                        self.color = cos_color
                        self.value = psos_value
                
                return CustomDisplayState(
                    psos_state_names[psos_value], 
                    cos_state.color, 
                    psos_value
                )
        
        return cos_state

    def read_iop_status(self) -> Dict[str, Optional[int]]:
        """Read IOP status for all systems from FPIS"""
        iop_states = {'CG1': None, 'CG2': None, 'FPIS': None}
        
        if not self.servers['FPIS'].connected:
            return iop_states
        
        try:
            client = self.servers['FPIS'].client
            objects = client.get_objects_node()
            
            cg1_iop = objects.get_child(["1:FTS_Out", "1:PSOS", "1:CG0IOP"]).get_value()
            cg2_iop = objects.get_child(["1:FTS_Out", "1:PSOS", "1:CG1IOP"]).get_value()  
            fpis_iop = objects.get_child(["1:FTS_Out", "1:PSOS", "1:IOP"]).get_value()
            
            iop_states['CG1'] = cg1_iop
            iop_states['CG2'] = cg2_iop
            iop_states['FPIS'] = fpis_iop
            
        except Exception as e:
            logger.error("Failed to read IOP status: {}".format(e))
        
        return iop_states

    def read_pcs_wd_threshold(self, server_name: str) -> Optional[float]:
        """Read PCS WD threshold from CG server"""
        if not self.servers[server_name].connected:
            return None
        
        try:
            client = self.servers[server_name].client
            objects = client.get_objects_node()
            
            threshold_node = objects.get_child(["1:HIOCOut", "1:F2", "1:STS", "1:TH_VAL"])
            threshold_value = threshold_node.get_value()
            
            return threshold_value
            
        except Exception as e:
            logger.error("Failed to read PCS WD threshold from {}: {}".format(server_name, e))
            return None

    def update_server_display(self, server_name: str, state: SystemState):
        """Update server status display"""
        if server_name not in self.status_labels:
            return
        
        labels = self.status_labels[server_name]
        
        # Update COS state
        if 'COS' in labels:
            if state.connected and state.cos_state:
                text = "{} ({})".format(state.cos_state.state_name, state.cos_raw_value)
                color = state.cos_state.color
                text_color = "white"
            else:
                text = "OFF (1)" if not state.connected else "Unknown ({})".format(state.cos_raw_value)
                color = "#800080" if not state.connected else "#CCCCCC"
                text_color = "white"
            
            labels['COS'].config(text=text, background=color, foreground=text_color)
        
        # Update PSOS state
        if 'PSOS' in labels and server_name != 'FPIS':
            if state.connected and state.psos_state:
                text = "{} ({})".format(state.psos_state.state_name, state.psos_raw_value)
                color = "#E0E0E0"
            else:
                text = "OFF (1)" if not state.connected else "Unknown ({})".format(state.psos_raw_value)
                color = "#CCCCCC"
            
            labels['PSOS'].config(text=text, background=color, foreground="black")

    def update_fpis_display(self, state: Optional[SystemState]):
        """Update FPIS status display (shows PSOS state mapped to COS equivalent)"""
        if 'FPIS' not in self.status_labels:
            return
        
        labels = self.status_labels['FPIS']
        
        if 'COS' in labels:
            if state and state.cos_state:
                text = "{} ({})".format(state.cos_state.state_name, state.cos_raw_value)
                color = state.cos_state.color
                text_color = "white"
            else:
                text = "OFF (1)"
                color = "#800080"
                text_color = "white"
            
            labels['COS'].config(text=text, background=color, foreground=text_color)

    def update_iop_displays(self, iop_states: Dict[str, Optional[int]]):
        """Update IOP status displays for all servers"""
        for server_name, iop_value in iop_states.items():
            if server_name in self.status_labels and 'IOP' in self.status_labels[server_name]:
                label = self.status_labels[server_name]['IOP']
                
                if iop_value is not None and iop_value in self.iop_commands:
                    state_name = self.iop_commands[iop_value]
                    color = self.iop_state_colors.get(iop_value, "#CCCCCC")
                    text = "{} ({})".format(state_name, iop_value)
                    text_color = "white"
                else:
                    text = "N/A"
                    color = "#CCCCCC"
                    text_color = "black"
                
                label.config(text=text, background=color, foreground=text_color)

    def update_pcs_wd_display(self, server_name: str, threshold_value: Optional[float]):
        """Update PCS WD threshold display"""
        if (server_name in self.status_labels and 
            'PCS_WD' in self.status_labels[server_name]):
            
            label = self.status_labels[server_name]['PCS_WD']
            
            if threshold_value is not None:
                text = "{:.3f}".format(threshold_value)
                color = "#ADD8E6"  # Light blue
            else:
                text = "N/A"
                color = "#CCCCCC"
            
            label.config(text=text, background=color, foreground="black")

    def on_closing(self):
        """Handle application closing"""
        self.monitoring = False
        
        # Disconnect all servers
        for server_name in list(self.servers.keys()):
            try:
                self.disconnect_server(server_name)
            except Exception as e:
                logger.error("Error during cleanup of {}: {}".format(server_name, e))
        
        # Cleanup COS operator
        self.cos_operator.cleanup()
        
        self.root.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = MainGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
