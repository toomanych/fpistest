"""
HIOC Module
Contains HIOCOperator, SUPOperator, HIOCSUPValidator and HIOC Dialog for GUI integration.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import os
from typing import Dict, List, Optional, Tuple, Any, Callable
from enum import Enum
from opcua import Client, ua
import logging

logger = logging.getLogger(__name__)

# Import our operator classes
from hioc_operator import HIOCOperator, HIOCOperationConfig, HIOCOperationType, HIOCStep
from sup_operator import SUPOperator, SUPOperationConfig
from hioc_sup_validator import HIOCSUPValidator, ValidationResult


class HIOCDialogOperationType(Enum):
    """HIOC Dialog operation types"""
    THRESHOLD = "threshold"
    OVERRIDE_SET = "override_set"
    OVERRIDE_UNSET = "override_unset"
    DISABLE = "disable"
    ENABLE = "enable"
    PARAMETER_SET = "parameter_set"


class ServerConnection:
    """Server connection information"""
    def __init__(self, name: str, url: str, client: Optional[Client] = None, 
                 connected: bool = False, controller_id: Optional[int] = None):
        self.name = name
        self.url = url
        self.client = client
        self.connected = connected
        self.controller_id = controller_id


class HIOCDialog:
    """
    Unified HIOC dialog that handles both HIOC and HIOCwSUP operations.
    Automatically selects appropriate operator based on operation type.
    """
    
    def __init__(self, parent, servers: Dict[str, ServerConnection]):
        self.parent = parent
        self.servers = servers
        self.dialog = None
        self.operation_in_progress = False
        
        # UI variables
        self.server_var = None
        self.fid_var = None
        self.operation_var = None
        self.progress_var = None
        self.log_text = None
        self.file_path_var = None
        self.parameter_set_radio = None
        
        # Operation data
        self.htt_values = {}
        self.fidsize_values = {}
        self.selected_threshold = None
        self.selected_file_path = None
        
        # Operators and validator
        self.current_operator = None
        self.validator = None

    def show(self):
        """Show HIOC operation dialog"""
        if self.operation_in_progress:
            messagebox.showwarning("Operation in Progress", 
                                 "Another HIOC operation is already in progress.")
            return
            
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("HIOC Parameter Configuration")
        self.dialog.geometry("700x600")
        self.dialog.grab_set()
        
        self.create_dialog_widgets()
        self.update_server_options()
        
    def create_dialog_widgets(self):
        """Create dialog widgets"""
        # Server and FID selection frame
        selection_frame = ttk.LabelFrame(self.dialog, text="Server and Function Selection", padding="5")
        selection_frame.pack(fill="x", padx=10, pady=5)
        
        # Server selection
        ttk.Label(selection_frame, text="Server:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.server_var = tk.StringVar()
        server_combo = ttk.Combobox(selection_frame, textvariable=self.server_var, 
                                   state="readonly", width=15)
        server_combo.grid(row=0, column=1, padx=5)
        server_combo.bind('<<ComboboxSelected>>', self.on_server_change)
        
        # FID selection
        ttk.Label(selection_frame, text="Function ID:").grid(row=0, column=2, padx=(20, 5))
        self.fid_var = tk.StringVar()
        fid_combo = ttk.Combobox(selection_frame, textvariable=self.fid_var,
                                values=['F0', 'F1', 'F2', 'F3', 'F4', 'F5'], 
                                state="readonly", width=5)
        fid_combo.grid(row=0, column=3, padx=5)
        fid_combo.current(0)
        fid_combo.bind('<<ComboboxSelected>>', self.on_fid_change)
        
        # Operation type selection
        op_frame = ttk.LabelFrame(self.dialog, text="Operation Type", padding="5")
        op_frame.pack(fill="x", padx=10, pady=5)
        
        self.operation_var = tk.StringVar(value="threshold")
        operations = [
            ("Threshold", "threshold"),
            ("Override Set", "override_set"),
            ("Override Unset", "override_unset"),
            ("Disable", "disable"),
            ("Enable", "enable"),
            ("Parameter Set (HIOCwSUP)", "parameter_set")
        ]
        
        for i, (text, value) in enumerate(operations):
            rb = ttk.Radiobutton(op_frame, text=text, variable=self.operation_var, 
                               value=value, command=self.on_operation_change)
            rb.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=2)
            
            # Store reference to parameter set radio button
            if value == "parameter_set":
                self.parameter_set_radio = rb
                
        # File selection frame (initially hidden)
        self.file_frame = ttk.LabelFrame(self.dialog, text="Parameter File Selection", padding="5")
        
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, width=50, state="readonly")
        file_entry.pack(side="left", padx=(0, 5))
        
        ttk.Button(self.file_frame, text="Browse...", 
                  command=self.browse_parameter_file).pack(side="left")
                  
        self.file_status_label = ttk.Label(self.file_frame, text="", foreground="blue")
        self.file_status_label.pack(side="left", padx=(10, 0))
        
        # Progress frame
        progress_frame = ttk.LabelFrame(self.dialog, text="Progress", padding="5")
        progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.progress_var = tk.StringVar(value="Ready to start")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack()
        
        # Log frame
        log_frame = ttk.LabelFrame(self.dialog, text="Operation Log", padding="5")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = tk.Text(log_frame, height=12, width=80)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        
        # Button frame
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(button_frame, text="Start Operation", 
                  command=self.start_operation).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Abort", 
                  command=self.abort_operation).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Close", 
                  command=self.close_dialog).pack(side="right", padx=5)

    def update_server_options(self):
        """Update available server options"""
        connected_servers = []
        
        # Check individual servers
        for server_name, server_info in self.servers.items():
            if server_name in ['CG1', 'CG2'] and server_info.connected:
                connected_servers.append(server_name)
        
        # Add dual option if both are connected
        if 'CG1' in connected_servers and 'CG2' in connected_servers:
            connected_servers.append('CG1 & CG2')
            
        if not connected_servers:
            messagebox.showerror("No Connection", "No CG servers are connected.")
            self.close_dialog()
            return
            
        # Update combobox
        server_combo = None
        for widget in self.dialog.winfo_children():
            if isinstance(widget, ttk.LabelFrame) and widget.cget("text") == "Server and Function Selection":
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Combobox) and child.cget("textvariable") == str(self.server_var):
                        server_combo = child
                        break
                break
        
        if server_combo:
            server_combo.config(values=connected_servers)
            if connected_servers:
                server_combo.current(0)

    def on_server_change(self, event=None):
        """Handle server selection change"""
        self.check_fid_capabilities()

    def on_fid_change(self, event=None):
        """Handle FID selection change"""
        self.check_fid_capabilities()

    def check_fid_capabilities(self):
        """Check FID capabilities and update UI accordingly"""
        server = self.server_var.get()
        fid = self.fid_var.get()
        
        if not server or not fid:
            return
            
        # For dual operations, check both servers
        servers_to_check = []
        if server == "CG1 & CG2":
            servers_to_check = ['CG1', 'CG2']
        elif server in ['CG1', 'CG2']:
            servers_to_check = [server]
        
        if not servers_to_check:
            return
            
        # Check FIDSize in background
        threading.Thread(target=self.check_fidsize_async, 
                        args=(servers_to_check, fid), daemon=True).start()

    def check_fidsize_async(self, servers_to_check: List[str], fid: str):
        """Check FIDSize asynchronously (requires HTT population via Flag=21→22 first)"""
        try:
            fidsize_support = {}
            
            for server_name in servers_to_check:
                if server_name in self.servers and self.servers[server_name].connected:
                    client = self.servers[server_name].client
                    
                    # First perform HTT request to populate HTT registry
                    htt_populated = self.populate_htt_for_fidsize_check(client, fid, server_name)
                    
                    if htt_populated:
                        fidsize = self.read_fidsize(client, fid)
                        fidsize_support[server_name] = fidsize
                    else:
                        logger.warning("Failed to populate HTT for {} on {}".format(fid, server_name))
                        fidsize_support[server_name] = None
                    
            # Update UI in main thread
            self.dialog.after(0, self.update_fidsize_availability, fidsize_support, fid)
            
        except Exception as e:
            logger.error("Error checking FIDSize: {}".format(e))
            self.dialog.after(0, self.disable_parameter_set, "Check failed: {}".format(e))

    def populate_htt_for_fidsize_check(self, client, fid: str, server_name: str) -> bool:
        """Perform Flag=21→22 sequence to populate HTT before reading FIDSize"""
        try:
            # This is similar to the HTT request in HIOCOperator but simplified for FIDSize check
            objects = client.get_objects_node()
            
            # Get controller ID for this server
            server_info = self.servers[server_name]
            controller_id = server_info.controller_id
            
            if controller_id is None:
                logger.warning("No controller ID for {}".format(server_name))
                return False
            
            # Extract FID number
            fid_num = int(fid[1:])  # F0→0, F1→1, etc.
            function_id = 2460000 + fid_num
            
            # Write HTT request challenge (Flag=21) using browse paths
            ctr_node = objects.get_child(["1:HIOCIn", "1:{}".format(fid), "1:STF", "1:CTR"])
            flg_node = objects.get_child(["1:HIOCIn", "1:{}".format(fid), "1:STF", "1:FLG"])
            msg_node = objects.get_child(["1:HIOCIn", "1:{}".format(fid), "1:STF", "1:MSG"])
            value_node = objects.get_child(["1:HIOCIn", "1:{}".format(fid), "1:STF", "1:VALUE"])
            seq_node = objects.get_child(["1:HIOCIn", "1:{}".format(fid), "1:STF", "1:SEQ"])
            
            # Write challenge data
            from opcua import ua
            ctr_node.set_value(ua.Variant(controller_id, ua.VariantType.UInt32))
            flg_node.set_value(ua.Variant(21, ua.VariantType.UInt32))  # HTT request flag
            msg_node.set_value(ua.Variant(function_id, ua.VariantType.UInt32))
            value_node.set_value(ua.Variant(0, ua.VariantType.UInt32))
            seq_node.set_value(ua.Variant(1, ua.VariantType.Int32))  # Simple sequence for check
            
            # Wait for HTT response (Flag=22)
            import time
            timeout = 5.0  # Shorter timeout for FIDSize check
            start_time = time.time()
            
            flg_response_node = objects.get_child(["1:HIOCOut", "1:{}".format(fid), "1:FTS", "1:FLG"])
            
            while time.time() - start_time < timeout:
                response_flag = flg_response_node.get_value()
                if response_flag == 22:  # HTT response flag
                    logger.info("HTT populated for {} on {}".format(fid, server_name))
                    return True
                elif response_flag == 9:  # Abort
                    logger.warning("HTT request aborted for {} on {}".format(fid, server_name))
                    return False
                time.sleep(0.1)
            
            logger.warning("HTT request timeout for {} on {}".format(fid, server_name))
            return False
            
        except Exception as e:
            logger.error("Failed to populate HTT for {} on {}: {}".format(fid, server_name, e))
            return False

    def read_fidsize(self, client: Client, fid: str) -> Optional[int]:
        """Read FIDSize for a given FID from common HTT registry"""
        try:
            objects = client.get_objects_node()
            # HTT is common registry, but FIDSize might be FID-specific within it
            # Check if this should be a common FIDSize or FID-specific based on spec
            fidsize_node = objects.get_child(["1:HTT", "1:FIDSize"])  # Common FIDSize, not FID-specific
            fidsize = fidsize_node.get_value()
            return fidsize
        except Exception as e:
            logger.error("Failed to read FIDSize for {}: {}".format(fid, e))
            return None

    def update_fidsize_availability(self, fidsize_support: Dict[str, Optional[int]], fid: str):
        """Update parameter set availability based on FIDSize"""
        # Check if all servers support HIOCwSUP (FIDSize > 1)
        all_support_sup = all(
            fidsize is not None and fidsize > 1 
            for fidsize in fidsize_support.values()
        )
        
        if all_support_sup:
            self.enable_parameter_set()
            self.fidsize_values[fid] = fidsize_support
        else:
            self.disable_parameter_set("FIDSize ≤ 1 on one or more servers")

    def enable_parameter_set(self):
        """Enable parameter set radio button"""
        if self.parameter_set_radio:
            self.parameter_set_radio.configure(state="normal")

    def disable_parameter_set(self, reason: str):
        """Disable parameter set radio button"""
        # If currently selected, switch to threshold
        if self.operation_var.get() == "parameter_set":
            self.operation_var.set("threshold")
            
        if self.parameter_set_radio:
            self.parameter_set_radio.configure(state="disabled")

    def on_operation_change(self):
        """Handle operation type change"""
        if self.operation_var.get() == "parameter_set":
            self.file_frame.pack(fill="x", padx=10, pady=5, after=self.file_frame.master.winfo_children()[2])
        else:
            self.file_frame.pack_forget()

    def browse_parameter_file(self):
        """Browse for parameter CSV file"""
        file_path = filedialog.askopenfilename(
            title="Select Parameter File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            self.file_path_var.set(file_path)
            self.selected_file_path = file_path
            
            # Validate file
            try:
                self.validate_parameter_file(file_path)
                self.file_status_label.config(
                    text="✓ Valid parameter file", 
                    foreground="green"
                )
            except Exception as e:
                self.file_status_label.config(
                    text=f"✗ Error: {str(e)}", 
                    foreground="red"
                )
                self.selected_file_path = None

    def validate_parameter_file(self, file_path: str):
        """Validate parameter CSV file"""
        with open(file_path, 'r') as file:
            content = file.read().strip().replace('\r', '')
            
        # Split by commas and validate hex format
        hex_values = [val.strip() for val in content.split(',') if val.strip()]
        
        if len(hex_values) < 1:
            raise ValueError("File must contain at least FIDSize")
        
        # Validate hex format
        for i, hex_val in enumerate(hex_values):
            try:
                int(hex_val, 16)
            except ValueError:
                raise ValueError("Invalid hex value at position {}: {}".format(i+1, hex_val))
        
        # Check parameter count
        fidsize = int(hex_values[0], 16)
        param_count = len(hex_values) - 1
        
        if param_count != fidsize - 1:
            raise ValueError("FIDSize {} expects {} parameters, found {}".format(
                fidsize, fidsize-1, param_count))

    def log_message(self, message: str):
        """Add message to log"""
        if self.log_text:
            timestamp = time.strftime('%H:%M:%S')
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)

    def update_progress(self, message: str):
        """Update progress display"""
        if self.progress_var:
            self.progress_var.set(message)
        self.log_message(message)

    def start_operation(self):
        """Start HIOC operation"""
        server = self.server_var.get()
        fid = self.fid_var.get()
        operation = self.operation_var.get()
        
        if not server or not fid:
            messagebox.showerror("Selection Required", "Please select server and function ID.")
            return
            
        if self.operation_in_progress:
            messagebox.showwarning("Operation in Progress", "Another operation is already in progress.")
            return
        
        # Validate operation requirements
        if operation == "parameter_set" and not self.selected_file_path:
            messagebox.showerror("File Required", "Please select a parameter file for parameter set operations.")
            return
        
        # Start operation in background thread
        self.operation_in_progress = True
        self.log_text.delete(1.0, tk.END)  # Clear log
        
        if server == "CG1 & CG2":
            thread = threading.Thread(target=self.execute_dual_operation, 
                                    args=(fid, operation), daemon=True)
        else:
            thread = threading.Thread(target=self.execute_single_operation, 
                                    args=(server, fid, operation), daemon=True)
        thread.start()

    def execute_single_operation(self, server: str, fid: str, operation: str):
        """Execute operation on single server"""
        try:
            server_info = self.servers[server]
            
            if operation == "threshold":
                # Need HTT values first, then show threshold selection
                self.request_htt_and_show_threshold_selection(server, fid)
                return
            elif operation == "parameter_set":
                # Use SUPOperator
                self.execute_sup_operation(server, fid)
            else:
                # Use HIOCOperator for other operations
                self.execute_hioc_operation(server, fid, operation)
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, "Error: {}".format(e))
            self.operation_in_progress = False

    def execute_dual_operation(self, fid: str, operation: str):
        """Execute operation on both CG1 and CG2"""
        try:
            # First validate compatibility
            self.dialog.after(0, self.update_progress, "Validating dual operation compatibility...")
            
            cg1_client = self.servers['CG1'].client
            cg2_client = self.servers['CG2'].client
            
            self.validator = HIOCSUPValidator(cg1_client, cg2_client)
            validation_results = self.validator.validate_for_dual_hioc_operation(fid if operation == "parameter_set" else None)
            
            if not validation_results['overall_success']:
                error_summary = self.validator.get_validation_summary(validation_results)
                self.dialog.after(0, self.update_progress, "Validation failed:")
                self.dialog.after(0, self.log_message, error_summary)
                self.operation_in_progress = False
                return
            
            self.dialog.after(0, self.update_progress, "✓ Validation passed - proceeding with dual operation")
            
            if operation == "threshold":
                # For thresholds, we already have HTT values from validation
                htt_result = validation_results['htt_comparison']
                self.htt_values = htt_result.cg1_htt  # Both are same due to validation
                self.dialog.after(0, self.show_threshold_selection_dual, fid, operation)
            elif operation == "parameter_set":
                # Execute SUP operation on both systems
                self.execute_dual_sup_operation(fid)
            else:
                # Execute HIOC operation on both systems  
                self.execute_dual_hioc_operation(fid, operation)
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, "Dual operation error: {}".format(e))
            self.operation_in_progress = False

    def request_htt_and_show_threshold_selection(self, server: str, fid: str):
        """Request HTT values using HIOCOperator auxiliary step and show threshold selection"""
        def htt_progress_callback(message: str):
            self.dialog.after(0, self.update_progress, message)
        
        # Create temporary HIOCOperator just for HTT request
        server_info = self.servers[server]
        config = HIOCOperationConfig(
            server_url=server_info.url,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.THRESHOLD,  # Will be overridden later
            progress_callback=htt_progress_callback
        )
        
        temp_operator = HIOCOperator(config)
        
        # Connect and perform HTT request (auxiliary step)
        try:
            if not temp_operator._connect_to_server():
                self.dialog.after(0, self.update_progress, "Failed to connect for HTT request")
                self.operation_in_progress = False
                return
            
            # Perform HTT request (Flag=21 auxiliary step)
            if temp_operator._perform_htt_request():
                # Read the populated HTT values
                htt_values = self.read_htt_values(temp_operator.client)
                if htt_values:
                    self.htt_values = htt_values
                    self.dialog.after(0, self.show_threshold_selection, server, fid, htt_values)
                else:
                    self.dialog.after(0, self.update_progress, "Failed to read HTT values")
                    self.operation_in_progress = False
            else:
                self.dialog.after(0, self.update_progress, "HTT request failed")
                self.operation_in_progress = False
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"HTT request error: {e}")
            self.operation_in_progress = False
        finally:
            # Cleanup temporary operator connection
            try:
                if temp_operator.client:
                    temp_operator.client.disconnect()
            except:
                pass

    def read_htt_values(self, client: Client) -> Optional[Dict[int, Any]]:
        """Read HTT threshold values from a server"""
        try:
            objects = client.get_objects_node()
            htt_values = {}
            
            for i in range(1, 16):
                try:
                    htt_node = objects.get_child(["1:HTT", f"1:TH{i}"])
                    value = htt_node.get_value()
                    htt_values[i] = value
                except Exception as e:
                    logger.warning(f"Failed to read TH{i}: {e}")
                    htt_values[i] = None
            
            return htt_values
            
        except Exception as e:
            logger.error(f"Failed to read HTT values: {e}")
            return None

    def show_threshold_selection(self, server: str, fid: str, htt_values: Dict[int, Any]):
        """Show threshold selection dialog with listbox"""
        # Create threshold selection dialog
        selection_dialog = tk.Toplevel(self.dialog)
        selection_dialog.title("Select Threshold - {} {}".format(server, fid))
        selection_dialog.geometry("400x500")
        selection_dialog.grab_set()
        
        ttk.Label(selection_dialog, 
                 text="Select threshold to modify on {} {}:".format(server, fid),
                 font=('TkDefaultFont', 10, 'bold')).pack(pady=10)
        
        # Create listbox with scrollbar
        list_frame = ttk.Frame(selection_dialog)
        list_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        listbox = tk.Listbox(list_frame, width=60, height=15, font=('TkDefaultFont', 9))
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Populate listbox with CC:Value pairs
        threshold_map = {}
        for i in range(1, 16):
            cc = i  # Command Code = threshold number
            value = htt_values.get(i, "N/A")
            
            if value is not None and value != "N/A":
                display_text = "CC={:2d} (TH{}): {}".format(cc, i, value)
            else:
                display_text = "CC={:2d} (TH{}): N/A".format(cc, i)
            
            listbox.insert(tk.END, display_text)
            threshold_map[i-1] = (cc, value)  # Map listbox index to (CC, Value)
        
        def on_threshold_select():
            selection = listbox.curselection()
            if selection:
                cc, value = threshold_map[selection[0]]
                if value is None or value == "N/A":
                    messagebox.showwarning("Invalid Selection", 
                                         "Threshold {} has no valid value (N/A)".format(cc))
                    return
                
                self.selected_threshold = (cc, value)
                selection_dialog.destroy()
                
                # Continue with threshold operation
                self.dialog.after(0, self.continue_threshold_operation, server, fid, cc)
            else:
                messagebox.showwarning("Selection Required", "Please select a threshold.")
        
        def on_threshold_cancel():
            selection_dialog.destroy()
            self.update_progress("Threshold selection cancelled")
            self.operation_in_progress = False
        
        # Button frame
        button_frame = ttk.Frame(selection_dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Select", command=on_threshold_select).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_threshold_cancel).pack(side="left", padx=5)

    def show_threshold_selection_dual(self, fid: str, operation: str):
        """Show threshold selection for dual operation (HTTs already validated as equivalent)"""
        if not self.htt_values:
            self.dialog.after(0, self.update_progress, "No HTT values available for dual operation")
            self.operation_in_progress = False
            return
        
        # Create threshold selection dialog for dual operation
        selection_dialog = tk.Toplevel(self.dialog)
        selection_dialog.title("Select Threshold - CG1 & CG2 {}".format(fid))
        selection_dialog.geometry("400x500")
        selection_dialog.grab_set()
        
        ttk.Label(selection_dialog, 
                 text="Select threshold to modify on both CG1 & CG2 {}:".format(fid),
                 font=('TkDefaultFont', 10, 'bold')).pack(pady=10)
        
        ttk.Label(selection_dialog, 
                 text="(HTT values verified equivalent between systems)",
                 font=('TkDefaultFont', 8), foreground="green").pack(pady=5)
        
        # Create listbox with scrollbar
        list_frame = ttk.Frame(selection_dialog)
        list_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        listbox = tk.Listbox(list_frame, width=60, height=15, font=('TkDefaultFont', 9))
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Populate listbox with CC:Value pairs
        threshold_map = {}
        for i in range(1, 16):
            cc = i  # Command Code = threshold number
            value = self.htt_values.get(i, "N/A")
            
            if value is not None and value != "N/A":
                display_text = "CC={:2d} (TH{}): {}".format(cc, i, value)
            else:
                display_text = "CC={:2d} (TH{}): N/A".format(cc, i)
            
            listbox.insert(tk.END, display_text)
            threshold_map[i-1] = (cc, value)  # Map listbox index to (CC, Value)
        
        def on_dual_threshold_select():
            selection = listbox.curselection()
            if selection:
                cc, value = threshold_map[selection[0]]
                if value is None or value == "N/A":
                    messagebox.showwarning("Invalid Selection", 
                                         "Threshold {} has no valid value (N/A)".format(cc))
                    return
                
                self.selected_threshold = (cc, value)
                selection_dialog.destroy()
                
                # Continue with dual threshold operation
                self.dialog.after(0, self.continue_dual_threshold_operation, fid, cc)
            else:
                messagebox.showwarning("Selection Required", "Please select a threshold.")
        
        def on_dual_threshold_cancel():
            selection_dialog.destroy()
            self.update_progress("Dual threshold selection cancelled")
            self.operation_in_progress = False
        
        # Button frame
        button_frame = ttk.Frame(selection_dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Select", command=on_dual_threshold_select).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_dual_threshold_cancel).pack(side="left", padx=5)

    def continue_threshold_operation(self, server: str, fid: str, threshold_cc: int):
        """Continue with threshold operation after selection"""
        thread = threading.Thread(target=self.execute_threshold_operation, 
                                args=(server, fid, threshold_cc), daemon=True)
        thread.start()

    def continue_dual_threshold_operation(self, fid: str, threshold_cc: int):
        """Continue with dual threshold operation after selection"""
        thread = threading.Thread(target=self.execute_dual_threshold_operation, 
                                args=(fid, threshold_cc), daemon=True)
        thread.start()

    def execute_threshold_operation(self, server: str, fid: str, threshold_cc: int):
        """Execute threshold operation using HIOCOperator"""
        server_info = self.servers[server]
        
        # Create HIOCOperator configuration for threshold
        config = HIOCOperationConfig(
            server_url=server_info.url,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.THRESHOLD,
            threshold_value=threshold_cc,
            progress_callback=lambda msg: self.dialog.after(0, self.update_progress, msg)
        )
        
        # Execute operation
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.dialog.after(0, self.update_progress, "✓ Threshold operation completed successfully")
        else:
            self.dialog.after(0, self.update_progress, "✗ Threshold operation failed")
            abort_analysis = operator.get_abort_analysis()
            self.dialog.after(0, self.log_message, "--- ABORT ANALYSIS ---")
            self.dialog.after(0, self.log_message, abort_analysis)
        
        self.operation_in_progress = False

    def execute_dual_threshold_operation(self, fid: str, threshold_cc: int):
        """Execute threshold operation on both CG1 and CG2 (CG1 first, then CG2 if CG1 succeeds)"""
        try:
            # Execute on CG1 first
            self.dialog.after(0, self.update_progress, "Starting CG1 threshold operation...")
            
            cg1_server_info = self.servers['CG1']
            cg1_config = HIOCOperationConfig(
                server_url=cg1_server_info.url,
                controller_id=cg1_server_info.controller_id,
                fid=fid,
                operation_type=HIOCOperationType.THRESHOLD,
                threshold_value=threshold_cc,
                progress_callback=lambda msg: self.dialog.after(0, self.update_progress, "CG1: {}".format(msg))
            )
            
            cg1_operator = HIOCOperator(cg1_config)
            cg1_success = cg1_operator.execute_operation()
            
            if cg1_success:
                self.dialog.after(0, self.update_progress, "✓ CG1 threshold operation completed - Starting CG2...")
                
                # Execute on CG2 automatically since CG1 succeeded
                cg2_server_info = self.servers['CG2']
                cg2_config = HIOCOperationConfig(
                    server_url=cg2_server_info.url,
                    controller_id=cg2_server_info.controller_id,
                    fid=fid,
                    operation_type=HIOCOperationType.THRESHOLD,
                    threshold_value=threshold_cc,
                    progress_callback=lambda msg: self.dialog.after(0, self.update_progress, "CG2: {}".format(msg))
                )
                
                cg2_operator = HIOCOperator(cg2_config)
                cg2_success = cg2_operator.execute_operation()
                
                if cg2_success:
                    self.dialog.after(0, self.update_progress, "✓ Both CG1 and CG2 threshold operations completed successfully")
                else:
                    self.dialog.after(0, self.update_progress, "✗ CG2 threshold operation failed")
                    abort_analysis = cg2_operator.get_abort_analysis()
                    self.dialog.after(0, self.log_message, "--- CG2 ABORT ANALYSIS ---")
                    self.dialog.after(0, self.log_message, abort_analysis)
                    
            else:
                self.dialog.after(0, self.update_progress, "✗ CG1 threshold operation failed - CG2 operation cancelled")
                abort_analysis = cg1_operator.get_abort_analysis()
                self.dialog.after(0, self.log_message, "--- CG1 ABORT ANALYSIS ---")
                self.dialog.after(0, self.log_message, abort_analysis)
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, "Dual threshold operation error: {}".format(e))
            
        self.operation_in_progress = False

    def execute_hioc_operation(self, server: str, fid: str, operation: str):
        """Execute HIOC operation using HIOCOperator"""
        server_info = self.servers[server]
        
        # Map dialog operation to HIOCOperationType
        operation_mapping = {
            "override_set": HIOCOperationType.OVERRIDE_SET,
            "override_unset": HIOCOperationType.OVERRIDE_UNSET,
            "disable": HIOCOperationType.DISABLE,
            "enable": HIOCOperationType.ENABLE
        }
        
        hioc_operation = operation_mapping.get(operation)
        if not hioc_operation:
            self.dialog.after(0, self.update_progress, f"Invalid HIOC operation: {operation}")
            self.operation_in_progress = False
            return
        
        # Create HIOCOperator configuration
        config = HIOCOperationConfig(
            server_url=server_info.url,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=hioc_operation,
            progress_callback=lambda msg: self.dialog.after(0, self.update_progress, msg)
        )
        
        # Execute operation
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.dialog.after(0, self.update_progress, "✓ Operation completed successfully")
        else:
            self.dialog.after(0, self.update_progress, "✗ Operation failed")
            abort_analysis = operator.get_abort_analysis()
            self.dialog.after(0, self.log_message, abort_analysis)
        
        self.operation_in_progress = False

    def execute_sup_operation(self, server: str, fid: str):
        """Execute SUP operation using SUPOperator"""
        server_info = self.servers[server]
        
        # Create SUPOperator configuration
        config = SUPOperationConfig(
            server_url=server_info.url,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.STRUCTURED_PARAMS,
            csv_file_path=self.selected_file_path,
            progress_callback=lambda msg: self.dialog.after(0, self.update_progress, msg)
        )
        
        # Execute operation
        operator = SUPOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.dialog.after(0, self.update_progress, "✓ SUP operation completed successfully")
        else:
            self.dialog.after(0, self.update_progress, "✗ SUP operation failed")
            abort_analysis = operator.get_abort_analysis()
            self.dialog.after(0, self.log_message, abort_analysis)
        
        self.operation_in_progress = False

    def execute_dual_hioc_operation(self, fid: str, operation: str):
        """Execute HIOC operation on both CG1 and CG2 (CG1 first, then CG2 if CG1 succeeds)"""
        try:
            # Execute on CG1 first
            self.dialog.after(0, self.update_progress, "Starting CG1 operation...")
            
            cg1_success = self.execute_single_hioc_operation_sync('CG1', fid, operation)
            
            if cg1_success:
                self.dialog.after(0, self.update_progress, "✓ CG1 completed - Starting CG2 operation...")
                
                # Execute on CG2 automatically since CG1 succeeded
                cg2_success = self.execute_single_hioc_operation_sync('CG2', fid, operation)
                
                if cg2_success:
                    self.dialog.after(0, self.update_progress, "✓ Both CG1 and CG2 operations completed successfully")
                else:
                    self.dialog.after(0, self.update_progress, "✗ CG2 operation failed")
            else:
                self.dialog.after(0, self.update_progress, "✗ CG1 operation failed - CG2 operation cancelled")
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Dual HIOC operation error: {e}")
            
        self.operation_in_progress = False

    def execute_dual_sup_operation(self, fid: str):
        """Execute SUP operation on both CG1 and CG2 (CG1 first, then CG2 if CG1 succeeds)"""
        try:
            # Execute on CG1 first
            self.dialog.after(0, self.update_progress, "Starting CG1 SUP operation...")
            
            cg1_success = self.execute_single_sup_operation_sync('CG1', fid)
            
            if cg1_success:
                self.dialog.after(0, self.update_progress, "✓ CG1 SUP completed - Starting CG2 SUP operation...")
                
                # Execute on CG2 automatically since CG1 succeeded
                cg2_success = self.execute_single_sup_operation_sync('CG2', fid)
                
                if cg2_success:
                    self.dialog.after(0, self.update_progress, "✓ Both CG1 and CG2 SUP operations completed successfully")
                else:
                    self.dialog.after(0, self.update_progress, "✗ CG2 SUP operation failed")
            else:
                self.dialog.after(0, self.update_progress, "✗ CG1 SUP operation failed - CG2 operation cancelled")
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Dual SUP operation error: {e}")
            
        self.operation_in_progress = False

    def execute_single_hioc_operation_sync(self, server: str, fid: str, operation: str) -> bool:
        """Execute HIOC operation synchronously and return success status"""
        server_info = self.servers[server]
        
        # Map dialog operation to HIOCOperationType
        operation_mapping = {
            "override_set": HIOCOperationType.OVERRIDE_SET,
            "override_unset": HIOCOperationType.OVERRIDE_UNSET,
            "disable": HIOCOperationType.DISABLE,
            "enable": HIOCOperationType.ENABLE
        }
        
        hioc_operation = operation_mapping.get(operation)
        if not hioc_operation:
            self.dialog.after(0, self.update_progress, "{}: Invalid HIOC operation: {}".format(
                server, operation))
            return False
        
        # Create HIOCOperator configuration
        config = HIOCOperationConfig(
            server_url=server_info.url,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=hioc_operation,
            progress_callback=lambda msg: self.dialog.after(0, self.update_progress, "{}: {}".format(server, msg))
        )
        
        # Execute operation
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.dialog.after(0, self.update_progress, "✓ {} operation completed successfully".format(server))
        else:
            self.dialog.after(0, self.update_progress, "✗ {} operation failed".format(server))
            abort_analysis = operator.get_abort_analysis()
            self.dialog.after(0, self.log_message, "--- {} ABORT ANALYSIS ---".format(server))
            self.dialog.after(0, self.log_message, abort_analysis)
        
        return success

    def execute_single_sup_operation_sync(self, server: str, fid: str) -> bool:
        """Execute SUP operation synchronously and return success status"""
        server_info = self.servers[server]
        
        # Create SUPOperator configuration
        config = SUPOperationConfig(
            server_url=server_info.url,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.STRUCTURED_PARAMS,
            csv_file_path=self.selected_file_path,
            progress_callback=lambda msg: self.dialog.after(0, self.update_progress, "{}: {}".format(server, msg))
        )
        
        # Execute operation
        operator = SUPOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.dialog.after(0, self.update_progress, "✓ {} SUP operation completed successfully".format(server))
        else:
            self.dialog.after(0, self.update_progress, "✗ {} SUP operation failed".format(server))
            abort_analysis = operator.get_abort_analysis()
            self.dialog.after(0, self.log_message, "--- {} SUP ABORT ANALYSIS ---".format(server))
            self.dialog.after(0, self.log_message, abort_analysis)
        
        return success

    def abort_operation(self):
        """Abort current operation"""
        if not self.operation_in_progress:
            return
        
        if self.current_operator and hasattr(self.current_operator, 'abort_operation'):
            self.current_operator.abort_operation()
            self.update_progress("Operation aborted")
        
        self.operation_in_progress = False

    def close_dialog(self):
        """Close dialog"""
        if self.operation_in_progress:
            result = messagebox.askyesno("Operation in Progress", 
                                       "An operation is in progress. Abort and close?")
            if result:
                self.abort_operation()
            else:
                return
        
        if self.dialog:
            self.dialog.destroy()


def create_hioc_dialog(parent, servers: Dict[str, ServerConnection]):
    """Factory function to create HIOC dialog"""
    return HIOCDialog(parent, servers)
