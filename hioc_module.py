"""
HIOC Module
Contains HIOCOperator, SUPOperator, HIOCSUPValidator and HIOC Dialog for GUI integration.
Complete implementation with all required widgets and functionality.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import os
from typing import Dict, List, Optional, Tuple, Any, Callable
from opcua import Client, ua
import logging

logger = logging.getLogger(__name__)

# Import our operator classes
from hioc_operator import HIOCOperator, HIOCOperationConfig, HIOCOperationType, HIOCStep
from sup_operator import SUPOperator, SUPOperationConfig
from hioc_sup_validator import HIOCSUPValidator, ValidationResult


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
        self.file_frame = None
        self.file_status_label = None
        
        # Operation data
        self.htt_values = {}
        self.fidsize_values = {}
        self.selected_threshold = None
        self.selected_file_path = None
        self.parsed_fidsize = None        # Parsed FIDSize from parameter file
        self.parsed_parameters = None     # Parsed parameter list from file
        
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
        self.server_combo = ttk.Combobox(selection_frame, textvariable=self.server_var, 
                                   state="readonly", width=15)
        self.server_combo.grid(row=0, column=1, padx=5)
        self.server_combo.bind('<<ComboboxSelected>>', self.on_server_change)
        
        # FID selection
        ttk.Label(selection_frame, text="Function ID:").grid(row=0, column=2, padx=(20, 5))
        self.fid_var = tk.StringVar()
        self.fid_combo = ttk.Combobox(selection_frame, textvariable=self.fid_var,
                                values=['F0', 'F1', 'F2', 'F3', 'F4', 'F5'], 
                                state="readonly", width=5)
        self.fid_combo.grid(row=0, column=3, padx=5)
        self.fid_combo.current(0)
        
        # Only use event binding - StringVar trace was causing duplicates
        self.fid_combo.bind('<<ComboboxSelected>>', self.on_fid_change)
        
        logger.info("FID combobox created with event binding")
        
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
                # Initially disabled until FIDSize check
                rb.configure(state="disabled")
        
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
        # Server change doesn't trigger capability check - only FID change does
        pass

    def on_fid_change(self, event=None):
        """Handle FID selection change via event binding"""
        logger.info("=== FID CHANGE EVENT TRIGGERED ===")
        
        # Directly read the current selection from the combobox widget
        current_fid = self.fid_combo.get()
        
        # Update the StringVar to match the actual selection
        self.fid_var.set(current_fid)
        
        logger.info("FID changed to: {}".format(current_fid))
        
        # Now check capabilities with the correct FID value
        self.check_fid_capabilities()
    
    def _delayed_fid_capability_check(self):
        """Delayed capability check to ensure FID variable is updated"""
        fid = self.fid_var.get()
        logger.debug("FID capability check triggered for: {}".format(fid))
        self.check_fid_capabilities()

    def check_fid_capabilities(self):
        """Check FID capabilities and update UI accordingly"""
        server = self.server_var.get()
        fid = self.fid_var.get()
        
        logger.debug("Checking FID capabilities: server={}, fid={}".format(server, fid))
        
        if not server or not fid:
            logger.debug("Server or FID not selected, skipping capability check")
            return
            
        # For dual operations, check both servers with proper HTT validation
        if server == "CG1 & CG2":
            self.check_dual_fid_capabilities(fid)
        elif server in ['CG1', 'CG2']:
            self.check_single_fid_capabilities(server, fid)

    def check_single_fid_capabilities(self, server: str, fid: str):
        """Check FID capabilities for single server"""
        if server not in self.servers or not self.servers[server].connected:
            self.disable_parameter_set("Server not connected")
            return
            
        server_info = self.servers[server]
        
        # Use HIOCOperator to perform HTT request
        htt_populated = self.perform_htt_request_for_fidsize(server_info, fid)
        
        if htt_populated:
            fidsize = self.read_fidsize(server_info.client, fid)
            if fidsize is not None and fidsize > 1:
                self.enable_parameter_set()
                logger.info("FIDSize check for {} on {}: {} - HIOCwSUP enabled".format(fid, server, fidsize))
            else:
                self.disable_parameter_set("FIDSize ≤ 1 on {}".format(server))
        else:
            self.disable_parameter_set("HTT request failed on {}".format(server))

    def check_dual_fid_capabilities(self, fid: str):
        """
        Check FID capabilities for dual CG1 & CG2 operation.
        Requests HTT from CG1 first, then CG2, and validates:
        1. Both have FIDSize > 1
        2. FIDSize values match between CG1 and CG2  
        3. All TH1-TH15 values match between CG1 and CG2
        """
        try:
            # Check both servers are connected
            if not (self.servers['CG1'].connected and self.servers['CG2'].connected):
                self.disable_parameter_set("CG1 or CG2 not connected")
                return
            
            cg1_info = self.servers['CG1']
            cg2_info = self.servers['CG2']
            
            # Step 1: Request HTT from CG1 first
            logger.info("Requesting HTT from CG1 for dual capability check...")
            cg1_htt_populated = self.perform_htt_request_for_fidsize(cg1_info, fid)
            
            if not cg1_htt_populated:
                self.disable_parameter_set("HTT request failed on CG1")
                return
            
            # Step 2: Request HTT from CG2
            logger.info("Requesting HTT from CG2 for dual capability check...")
            cg2_htt_populated = self.perform_htt_request_for_fidsize(cg2_info, fid)
            
            if not cg2_htt_populated:
                self.disable_parameter_set("HTT request failed on CG2")
                return
            
            # Step 3: Read FIDSize from both systems
            cg1_fidsize = self.read_fidsize(cg1_info.client, fid)
            cg2_fidsize = self.read_fidsize(cg2_info.client, fid)
            
            if cg1_fidsize is None or cg2_fidsize is None:
                self.disable_parameter_set("Failed to read FIDSize from one or both systems")
                return
            
            # Step 4: Validate FIDSize > 1 for both systems
            if cg1_fidsize <= 1 or cg2_fidsize <= 1:
                self.disable_parameter_set("FIDSize ≤ 1 on CG1 ({}) or CG2 ({})".format(cg1_fidsize, cg2_fidsize))
                return
            
            # Step 5: Validate FIDSize values match
            if cg1_fidsize != cg2_fidsize:
                self.disable_parameter_set("FIDSize mismatch: CG1={}, CG2={}".format(cg1_fidsize, cg2_fidsize))
                return
            
            # Step 6: Read and validate HTT values match
            cg1_htt = self.read_htt_values(cg1_info.client)
            cg2_htt = self.read_htt_values(cg2_info.client)
            
            if not cg1_htt or not cg2_htt:
                self.disable_parameter_set("Failed to read HTT values from one or both systems")
                return
            
            # Step 7: Compare all TH1-TH15 values
            htt_mismatches = []
            for i in range(1, 16):  # 1 to 15 inclusive (TH1-TH15)
                cg1_val = cg1_htt.get(i)
                cg2_val = cg2_htt.get(i)
                
                if cg1_val != cg2_val:
                    htt_mismatches.append("TH{}: CG1={}, CG2={}".format(i, cg1_val, cg2_val))
            
            if htt_mismatches:
                mismatch_summary = "; ".join(htt_mismatches[:3])  # Show first 3 mismatches
                if len(htt_mismatches) > 3:
                    mismatch_summary += " (and {} more)".format(len(htt_mismatches) - 3)
                self.disable_parameter_set("HTT mismatches: {}".format(mismatch_summary))
                return
            
            # Step 8: All validations passed - enable HIOCwSUP
            self.enable_parameter_set()
            logger.info("Dual FID capability check passed: FIDSize={}, HTT values match - HIOCwSUP enabled".format(cg1_fidsize))
            
        except Exception as e:
            logger.error("Error in dual FID capability check: {}".format(e))
            self.disable_parameter_set("Capability check error: {}".format(e))

    def perform_htt_request_for_fidsize(self, server_info: ServerConnection, fid: str) -> bool:
        """Use HIOCOperator to perform HTT request for FIDSize capability check"""
        try:
            # Create progress callback that logs to the dialog
            def capability_progress(message: str):
                self.log_message("CAPABILITY CHECK: {}".format(message))
            
            # Create temporary HIOCOperator configuration for HTT request only
            config = HIOCOperationConfig(
                client=server_info.client,
                controller_id=server_info.controller_id,
                fid=fid,
                operation_type=HIOCOperationType.THRESHOLD,  # Type doesn't matter for HTT request
                threshold_command_code=1,  # Dummy values for HTT request
                threshold_value=0,
                timeout_seconds=5.0,  # Shorter timeout for capability check
                progress_callback=capability_progress
            )
            
            # Create operator and perform only HTT request step
            temp_operator = HIOCOperator(config)
            
            # Use the operator's built-in HTT request method
            htt_success = temp_operator._perform_htt_request()
            
            # Append the complete operation trace to the dialog log
            operation_trace = temp_operator.get_operation_trace()
            self.log_message("=== HTT REQUEST TRACE FOR {} ON {} ===".format(fid, server_info.name))
            for line in operation_trace.split('\n'):
                if line.strip():  # Skip empty lines
                    self.log_message(line)
            self.log_message("=== END HTT REQUEST TRACE ===")
            
            # Log final result
            if htt_success:
                logger.info("HTT populated successfully for {} on {}".format(fid, server_info.name))
            else:
                logger.warning("HTT request failed for {} on {}".format(fid, server_info.name))
                # Log additional failure details from operation history
                if temp_operator.operation_history:
                    last_step = temp_operator.operation_history[-1]
                    if last_step.error_message:
                        self.log_message("FAILURE REASON: {}".format(last_step.error_message))
                    if last_step.timeout:
                        self.log_message("TIMEOUT: Operation timed out after {}s".format(config.timeout_seconds))
            
            return htt_success
                
        except Exception as e:
            logger.error("Failed to perform HTT request for {} on {}: {}".format(fid, server_info.name, e))
            self.log_message("ERROR: Failed to perform HTT request: {}".format(e))
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

    def enable_parameter_set(self):
        """Enable parameter set radio button"""
        if self.parameter_set_radio:
            self.parameter_set_radio.configure(state="normal")

    def disable_parameter_set(self, reason: str):
        """Disable parameter set radio button with reason"""
        # If currently selected, switch to threshold
        if self.operation_var.get() == "parameter_set":
            self.operation_var.set("threshold")
            
        if self.parameter_set_radio:
            self.parameter_set_radio.configure(state="disabled")
        
        logger.info("HIOCwSUP disabled: {}".format(reason))

    def on_operation_change(self):
        """Handle operation type change"""
        if self.operation_var.get() == "parameter_set":
            # Show the file frame - pack it after the operation type frame
            self.file_frame.pack(fill="x", padx=10, pady=5)
        else:
            # Hide the file frame
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
            
            # Validate file and store parsed data
            try:
                fidsize, parameters = self.validate_parameter_file(file_path)
                self.parsed_fidsize = fidsize
                self.parsed_parameters = parameters
                
                self.file_status_label.config(
                    text="✓ Valid: FIDSize={}, {} parameters".format(fidsize, len(parameters)), 
                    foreground="green"
                )
            except Exception as e:
                self.file_status_label.config(
                    text="✗ Error: {}".format(str(e)), 
                    foreground="red"
                )
                self.selected_file_path = None
                self.parsed_fidsize = None
                self.parsed_parameters = None

    def validate_parameter_file(self, file_path: str) -> Tuple[int, List[int]]:
        """Validate parameter CSV file and return FIDSize and parameter list"""
        with open(file_path, 'r') as file:
            content = file.read().strip().replace('\r', '')
            
        # Split by commas and validate hex format
        hex_values = [val.strip() for val in content.split(',') if val.strip()]
        
        if len(hex_values) < 1:
            raise ValueError("File must contain at least FIDSize")
        
        # Validate hex format and convert to integers
        int_values = []
        for i, hex_val in enumerate(hex_values):
            try:
                int_value = int(hex_val, 16)
                if int_value > 0xFFFFFFFF:
                    raise ValueError("Parameter {} exceeds uint32 range: {}".format(i+1, hex_val))
                int_values.append(int_value)
            except ValueError:
                raise ValueError("Invalid hex value at position {}: {}".format(i+1, hex_val))
        
        # Extract FIDSize and parameters
        fidsize = int_values[0]
        parameters = int_values[1:]
        
        # Check parameter count
        if len(parameters) != fidsize - 1:
            raise ValueError("FIDSize {} expects {} parameters, found {}".format(
                fidsize, fidsize-1, len(parameters)))
        
        # Validate parameter count limits
        if len(parameters) > 511:
            raise ValueError("Too many parameters: {} (max 511)".format(len(parameters)))
        
        return fidsize, parameters

    def log_message(self, message: str):
        """Add message to log"""
        if self.log_text:
            timestamp = time.strftime('%H:%M:%S')
            self.log_text.insert(tk.END, "[{}] {}\n".format(timestamp, message))
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
        
        # Start operation synchronously
        self.operation_in_progress = True
        self.log_text.delete(1.0, tk.END)  # Clear log
        
        if server == "CG1 & CG2":
            self.execute_dual_operation(fid, operation)
        else:
            self.execute_single_operation(server, fid, operation)

    def execute_single_operation(self, server: str, fid: str, operation: str):
        """Execute operation on single server"""
        try:
            # Validate connection before creating operator
            server_info = self.servers[server]
            if not server_info.connected or not server_info.client:
                self.update_progress("{} not connected".format(server))
                self.operation_in_progress = False
                return
            
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
            self.update_progress("Error: {}".format(e))
            self.operation_in_progress = False

    def execute_dual_operation(self, fid: str, operation: str):
        """Execute operation on both CG1 and CG2"""
        try:
            # First validate compatibility
            self.update_progress("Validating dual operation compatibility...")
            
            cg1_client = self.servers['CG1'].client
            cg2_client = self.servers['CG2'].client
            
            # Validate both clients are available
            if not cg1_client or not cg2_client:
                self.update_progress("CG1 or CG2 client not available")
                self.operation_in_progress = False
                return
            
            self.validator = HIOCSUPValidator(cg1_client, cg2_client)
            validation_results = self.validator.validate_for_dual_hioc_operation(fid if operation == "parameter_set" else None)
            
            if not validation_results['overall_success']:
                error_summary = self.validator.get_validation_summary(validation_results)
                self.update_progress("Validation failed:")
                self.log_message(error_summary)
                self.operation_in_progress = False
                return
            
            self.update_progress("✓ Validation passed - proceeding with dual operation")
            
            if operation == "threshold":
                # For thresholds, we already have HTT values from validation
                htt_result = validation_results['htt_comparison']
                self.htt_values = htt_result.cg1_htt  # Both are same due to validation
                self.show_threshold_selection_dual(fid, operation)
            elif operation == "parameter_set":
                # Execute SUP operation on both systems
                self.execute_dual_sup_operation(fid)
            else:
                # Execute HIOC operation on both systems  
                self.execute_dual_hioc_operation(fid, operation)
                
        except Exception as e:
            self.update_progress("Dual operation error: {}".format(e))
            self.operation_in_progress = False

    def request_htt_and_show_threshold_selection(self, server: str, fid: str):
        """Request HTT values using HIOCOperator and show threshold selection"""
        # Get connected client from server info
        server_info = self.servers[server]
        if not server_info.connected or not server_info.client:
            self.update_progress("Server not connected")
            self.operation_in_progress = False
            return
        
        # Use HIOCOperator to perform HTT request
        htt_populated = self.perform_htt_request_for_fidsize(server_info, fid)
        
        if htt_populated:
            # Read the populated HTT values
            htt_values = self.read_htt_values(server_info.client)
            if htt_values:
                self.htt_values = htt_values
                self.show_threshold_selection(server, fid, htt_values)
            else:
                self.update_progress("Failed to read HTT values")
                self.operation_in_progress = False
        else:
            self.update_progress("HTT request failed")
            self.operation_in_progress = False

    def read_htt_values(self, client: Client) -> Optional[Dict[int, Any]]:
        """Read HTT threshold values from a server"""
        try:
            objects = client.get_objects_node()
            htt_values = {}
            
            for i in range(1, 16):  # 1 to 15 inclusive (TH1-TH15)
                try:
                    htt_node = objects.get_child(["1:HTT", "1:TH{}".format(i)])
                    value = htt_node.get_value()
                    htt_values[i] = value
                except Exception as e:
                    logger.warning("Failed to read TH{}: {}".format(i, e))
                    htt_values[i] = None
            
            return htt_values
            
        except Exception as e:
            logger.error("Failed to read HTT values: {}".format(e))
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
        for i in range(1, 16):  # 1 to 15 inclusive (TH1-TH15)
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
        for i in range(1, 16):  # 1 to 15 inclusive (TH1-TH15)
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
        self.execute_threshold_operation(server, fid, threshold_cc)

    def continue_dual_threshold_operation(self, fid: str, threshold_cc: int):
        """Continue with dual threshold operation after selection"""
        self.execute_dual_threshold_operation(fid, threshold_cc)

    def execute_threshold_operation(self, server: str, fid: str, threshold_cc: int):
        """Execute threshold operation using HIOCOperator"""
        server_info = self.servers[server]
        
        # Validate connection
        if not server_info.connected or not server_info.client:
            self.update_progress("{} not connected".format(server))
            self.operation_in_progress = False
            return
        
        # Get the actual threshold value from HTT
        threshold_value = self.htt_values.get(threshold_cc) if self.htt_values else None
        if threshold_value is None:
            self.update_progress("Threshold value not available for CC={}".format(threshold_cc))
            self.operation_in_progress = False
            return
        
        # Create HIOCOperator configuration for threshold with both CC and value
        config = HIOCOperationConfig(
            client=server_info.client,  # Use existing connection
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.THRESHOLD,
            threshold_command_code=threshold_cc,  # CC (1-15) selected by user
            threshold_value=threshold_value,      # Actual threshold value from HTT
            progress_callback=self.update_progress
        )
        
        # Execute operation
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.update_progress("✓ Threshold operation completed successfully")
        else:
            self.update_progress("✗ Threshold operation failed")
            abort_analysis = operator.get_abort_analysis()
            self.log_message("--- ABORT ANALYSIS ---")
            self.log_message(abort_analysis)
        
        self.operation_in_progress = False

    def execute_dual_threshold_operation(self, fid: str, threshold_cc: int):
        """Execute threshold operation on both CG1 and CG2 (CG1 first, then CG2 if CG1 succeeds)"""
        try:
            # Get the actual threshold value from HTT
            threshold_value = self.htt_values.get(threshold_cc) if self.htt_values else None
            if threshold_value is None:
                self.update_progress("Threshold value not available for CC={}".format(threshold_cc))
                self.operation_in_progress = False
                return
            
            # Execute on CG1 first
            self.update_progress("Starting CG1 threshold operation...")
            
            cg1_server_info = self.servers['CG1']
            if not cg1_server_info.connected or not cg1_server_info.client:
                self.update_progress("CG1 not connected")
                self.operation_in_progress = False
                return
            
            cg1_config = HIOCOperationConfig(
                client=cg1_server_info.client,  # Use existing connection
                controller_id=cg1_server_info.controller_id,
                fid=fid,
                operation_type=HIOCOperationType.THRESHOLD,
                threshold_command_code=threshold_cc,  # CC (1-15) selected by user
                threshold_value=threshold_value,      # Actual threshold value from HTT
                progress_callback=lambda msg: self.update_progress("CG1: {}".format(msg))
            )
            
            cg1_operator = HIOCOperator(cg1_config)
            cg1_success = cg1_operator.execute_operation()
            
            if cg1_success:
                self.update_progress("✓ CG1 threshold operation completed - Starting CG2...")
                
                # Execute on CG2 automatically since CG1 succeeded
                cg2_server_info = self.servers['CG2']
                if not cg2_server_info.connected or not cg2_server_info.client:
                    self.update_progress("CG2 not connected")
                    self.operation_in_progress = False
                    return
                
                cg2_config = HIOCOperationConfig(
                    client=cg2_server_info.client,  # Use existing connection
                    controller_id=cg2_server_info.controller_id,
                    fid=fid,
                    operation_type=HIOCOperationType.THRESHOLD,
                    threshold_command_code=threshold_cc,  # CC (1-15) selected by user
                    threshold_value=threshold_value,      # Actual threshold value from HTT
                    progress_callback=lambda msg: self.update_progress("CG2: {}".format(msg))
                )
                
                cg2_operator = HIOCOperator(cg2_config)
                cg2_success = cg2_operator.execute_operation()
                
                if cg2_success:
                    self.update_progress("✓ Both CG1 and CG2 threshold operations completed successfully")
                else:
                    self.update_progress("✗ CG2 threshold operation failed")
                    abort_analysis = cg2_operator.get_abort_analysis()
                    self.log_message("--- CG2 ABORT ANALYSIS ---")
                    self.log_message(abort_analysis)
                    
            else:
                self.update_progress("✗ CG1 threshold operation failed - CG2 operation cancelled")
                abort_analysis = cg1_operator.get_abort_analysis()
                self.log_message("--- CG1 ABORT ANALYSIS ---")
                self.log_message(abort_analysis)
                
        except Exception as e:
            self.update_progress("Dual threshold operation error: {}".format(e))
            
        self.operation_in_progress = False

    def execute_hioc_operation(self, server: str, fid: str, operation: str):
        """Execute HIOC operation using HIOCOperator"""
        server_info = self.servers[server]
        
        # Validate connection
        if not server_info.connected or not server_info.client:
            self.update_progress("{} not connected".format(server))
            self.operation_in_progress = False
            return
        
        # Map dialog operation to HIOCOperationType
        operation_mapping = {
            "override_set": HIOCOperationType.OVERRIDE_SET,
            "override_unset": HIOCOperationType.OVERRIDE_UNSET,
            "disable": HIOCOperationType.DISABLE,
            "enable": HIOCOperationType.ENABLE
        }
        
        hioc_operation = operation_mapping.get(operation)
        if not hioc_operation:
            self.update_progress("Invalid HIOC operation: {}".format(operation))
            self.operation_in_progress = False
            return
        
        # Create HIOCOperator configuration with connected client
        config = HIOCOperationConfig(
            client=server_info.client,  # Use existing connection
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=hioc_operation,
            progress_callback=self.update_progress
        )
        
        # Execute operation
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.update_progress("✓ Operation completed successfully")
        else:
            self.update_progress("✗ Operation failed")
            abort_analysis = operator.get_abort_analysis()
            self.log_message(abort_analysis)
        
        self.operation_in_progress = False

    def execute_sup_operation(self, server: str, fid: str):
        """Execute SUP operation using SUPOperator"""
        server_info = self.servers[server]
        
        # Validate connection
        if not server_info.connected or not server_info.client:
            self.update_progress("{} not connected".format(server))
            self.operation_in_progress = False
            return
        
        # Validate parsed parameter data is available
        if self.parsed_fidsize is None or self.parsed_parameters is None:
            self.update_progress("Parameter file not properly parsed")
            self.operation_in_progress = False
            return
        
        # Create SUPOperator configuration with parsed data
        config = SUPOperationConfig(
            client=server_info.client,  # Use existing connection
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.STRUCTURED_PARAMS,
            fidsize=self.parsed_fidsize,
            parameters=self.parsed_parameters,
            progress_callback=self.update_progress
        )
        
        # Execute operation
        operator = SUPOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.update_progress("✓ SUP operation completed successfully")
        else:
            self.update_progress("✗ SUP operation failed")
            abort_analysis = operator.get_abort_analysis()
            self.log_message(abort_analysis)
        
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
            self.dialog.after(0, self.update_progress, "Dual HIOC operation error: {}".format(e))
            
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
            self.dialog.after(0, self.update_progress, "Dual SUP operation error: {}".format(e))
            
        self.operation_in_progress = False

    def execute_single_hioc_operation_sync(self, server: str, fid: str, operation: str) -> bool:
        """Execute HIOC operation synchronously and return success status"""
        server_info = self.servers[server]
        
        # Validate connection
        if not server_info.connected or not server_info.client:
            self.update_progress("{}: Not connected".format(server))
            return False
        
        # Map dialog operation to HIOCOperationType
        operation_mapping = {
            "override_set": HIOCOperationType.OVERRIDE_SET,
            "override_unset": HIOCOperationType.OVERRIDE_UNSET,
            "disable": HIOCOperationType.DISABLE,
            "enable": HIOCOperationType.ENABLE
        }
        
        hioc_operation = operation_mapping.get(operation)
        if not hioc_operation:
            self.update_progress("{}: Invalid HIOC operation: {}".format(server, operation))
            return False
        
        # Create HIOCOperator configuration with connected client
        config = HIOCOperationConfig(
            client=server_info.client,  # Use existing connection
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=hioc_operation,
            progress_callback=lambda msg: self.update_progress("{}: {}".format(server, msg))
        )
        
        # Execute operation
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.update_progress("✓ {} operation completed successfully".format(server))
        else:
            self.update_progress("✗ {} operation failed".format(server))
            abort_analysis = operator.get_abort_analysis()
            self.log_message("--- {} ABORT ANALYSIS ---".format(server))
            self.log_message(abort_analysis)
        
        return success

    def execute_single_sup_operation_sync(self, server: str, fid: str) -> bool:
        """Execute SUP operation synchronously and return success status"""
        server_info = self.servers[server]
        
        # Validate connection
        if not server_info.connected or not server_info.client:
            self.update_progress("{}: Not connected".format(server))
            return False
        
        # Create SUPOperator configuration with connected client
        config = SUPOperationConfig(
            client=server_info.client,  # Use existing connection
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.STRUCTURED_PARAMS,
            csv_file_path=self.selected_file_path,
            progress_callback=lambda msg: self.update_progress("{}: {}".format(server, msg))
        )
        
        # Execute operation
        operator = SUPOperator(config)
        success = operator.execute_operation()
        
        # Show results
        if success:
            self.update_progress("✓ {} SUP operation completed successfully".format(server))
        else:
            self.update_progress("✗ {} SUP operation failed".format(server))
            abort_analysis = operator.get_abort_analysis()
            self.log_message("--- {} SUP ABORT ANALYSIS ---".format(server))
            self.log_message(abort_analysis)
        
        hioc_operation=operation_mapping.get(operation)
        if not hioc_operation:
            self.dialog.after(0, self.update_progress, "{}: Invalid HIOC operation: {}".format(
                server, operation))
            return False
        
        # Create HIOCOperator configuration with connected client
        config = HIOCOperationConfig(
            client=server_info.client,  # Use existing connection
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
        
        # Validate connection
        if not server_info.connected or not server_info.client:
            self.dialog.after(0, self.update_progress, "{}: Not connected".format(server))
            return False
        
        # Create SUPOperator configuration with connected client
        config = SUPOperationConfig(
            client=server_info.client,  # Use existing connection
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
    """
    Factory function to create and return a HIOC dialog instance.
    
    Args:
        parent: Parent tkinter widget (typically root window)
        servers: Dictionary of server connections {name: ServerConnection}
                Only CG1 and CG2 servers are used for HIOC operations
    
    Returns:
        HIOCDialog: Configured HIOC dialog instance ready to show()
        
    Raises:
        ValueError: If no valid CG servers are provided
        
    Example:
        dialog = create_hioc_dialog(root, servers)
        dialog.show()  # Display the dialog
    """
    # Validate that we have the required server connections
    if not servers:
        raise ValueError("Server connections dictionary cannot be empty")
    
    # Check for CG1/CG2 availability (HIOC operations require these)
    cg_servers = {name: conn for name, conn in servers.items() 
                  if name in ['CG1', 'CG2']}
    
    if not cg_servers:
        raise ValueError("HIOC operations require CG1 and/or CG2 server connections")
    
    # Create and return the dialog instance
    # The dialog will handle its own initialization and widget creation
    dialog = HIOCDialog(parent, servers)
    
    return dialog
