"""
HIOC Module - Simplified with HIOCSUPValidator
Removes all custom HTT request code and delegates to HIOCSUPValidator.
Clean integration with proper radio button enabling logic.
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
from hiocwsup_operator import HIOCwSUPOperator  
from hioc_sup_validator import HIOCSUPValidator


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
    Uses HIOCSUPValidator for all HTT validation and capability checking.
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
        self.threshold_radio = None  # NEW: Reference to threshold radio button
        self.file_frame = None
        self.file_status_label = None
        
        # Operation data
        self.selected_file_path = None
        self.parsed_fidsize = None        # Parsed FIDSize from parameter file
        self.parsed_parameters = None     # Parsed parameter list from file
        
        # Validation state - managed by HIOCSUPValidator
        self.current_validator = None     # Current HIOCSUPValidator instance
        
        # Operators
        self.current_operator = None

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
        self.fid_combo.bind('<<ComboboxSelected>>', self.on_fid_change)
        
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
            
            # Store references to specific radio buttons
            if value == "parameter_set":
                self.parameter_set_radio = rb
                rb.configure(state="disabled")  # Initially disabled
            elif value == "threshold":
                self.threshold_radio = rb
                rb.configure(state="disabled")  # Initially disabled until validation
        
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
        self.server_combo.config(values=connected_servers)
        if connected_servers:
            self.server_combo.current(0)

    def on_server_change(self, event=None):
        """Handle server selection change - trigger FID capability check"""
        self.check_fid_capabilities()

    def on_fid_change(self, event=None):
        """Handle FID selection change"""
        # Update the StringVar to match the actual selection
        current_fid = self.fid_combo.get()
        self.fid_var.set(current_fid)
        
        # Check capabilities with HIOCSUPValidator
        self.check_fid_capabilities()
    
    def check_fid_capabilities(self):
        """Check FID capabilities using HIOCSUPValidator"""
        server = self.server_var.get()
        fid = self.fid_var.get()
        
        if not server or not fid:
            self.disable_all_operation_types("Server or FID not selected")
            return
        
        # Create validator based on server selection
        try:
            if server == "CG1 & CG2":
                if not (self.servers['CG1'].connected and self.servers['CG2'].connected):
                    self.disable_all_operation_types("CG1 or CG2 not connected")
                    return
                    
                validator = HIOCSUPValidator(
                    self.servers['CG1'].client,
                    self.servers['CG2'].client,
                    progress_callback=self.update_progress,
                    cg1_controller_id=self.servers['CG1'].controller_id,
                    cg2_controller_id=self.servers['CG2'].controller_id
                )
            elif server in ['CG1', 'CG2']:
                if not self.servers[server].connected:
                    self.disable_all_operation_types("{} not connected".format(server))
                    return
                    
                validator = HIOCSUPValidator(
                    self.servers[server].client,
                    progress_callback=self.update_progress,
                    cg1_controller_id=self.servers[server].controller_id
                )
            else:
                self.disable_all_operation_types("Invalid server selection")
                return
            
            # Perform validation
            self.log_message("=== FID CAPABILITY CHECK FOR {} ===".format(fid))
            validation_success = validator.validate(fid)
            
            if validation_success:
                self.current_validator = validator
                self.enable_operation_types_based_on_validation()
                self.log_message("✓ Capability check completed successfully")
                self.log_message(validator.get_validation_summary())
            else:
                self.current_validator = None
                self.disable_all_operation_types("HTT validation failed")
                self.log_message("✗ Capability check failed")
                
        except Exception as e:
            self.current_validator = None
            self.disable_all_operation_types("Capability check error: {}".format(e))
            self.log_message("✗ Capability check error: {}".format(e))

    def enable_operation_types_based_on_validation(self):
        """Enable operation types based on HIOCSUPValidator results"""
        if not self.current_validator:
            self.disable_all_operation_types("No validation data")
            return
        
        # Enable threshold operations only if HIOC_TH (fidsize == 1)
        if self.current_validator.is_hioc_th():
            if self.threshold_radio:
                self.threshold_radio.configure(state="normal")
        else:
            if self.threshold_radio:
                self.threshold_radio.configure(state="disabled")
                # Switch away from threshold if currently selected
                if self.operation_var.get() == "threshold":
                    self.operation_var.set("override_set")
        
        # Enable parameter set operations only if HIOC_PS (fidsize > 1)
        if self.current_validator.supports_hiocwsup():
            if self.parameter_set_radio:
                self.parameter_set_radio.configure(state="normal")
        else:
            if self.parameter_set_radio:
                self.parameter_set_radio.configure(state="disabled")
                # Switch away from parameter_set if currently selected
                if self.operation_var.get() == "parameter_set":
                    self.operation_var.set("override_set")
        
        # Override, disable, enable operations are always available for any validated FID
        # (They correspond to HIOC_BO functionality which should work regardless of FIDSize)

    def disable_all_operation_types(self, reason: str):
        """Disable all operation radio buttons"""
        if self.threshold_radio:
            self.threshold_radio.configure(state="disabled")
        if self.parameter_set_radio:
            self.parameter_set_radio.configure(state="disabled")
            
        # Switch to a basic operation if threshold/parameter_set was selected
        if self.operation_var.get() in ["threshold", "parameter_set"]:
            self.operation_var.set("override_set")
        
        logger.info("Operation types disabled: {}".format(reason))

    def on_operation_change(self):
        """Handle operation type change"""
        if self.operation_var.get() == "parameter_set":
            # Show the file frame
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
                    text="✓ Valid: FIDSize={}, {} parameters parsed".format(
                        fidsize, len(parameters)), 
                    foreground="green"
                )
                
                self.log_parameter_data_summary()
                
            except Exception as e:
                self.file_status_label.config(
                    text="✗ Error: {}".format(str(e)), 
                    foreground="red"
                )
                self.selected_file_path = None
                self.parsed_fidsize = None
                self.parsed_parameters = None
                self.log_message("CSV parsing failed: {}".format(str(e)))

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
        
        self.log_message("✓ Parsed CSV: FIDSize={}, {} parameters ready for HIOCwSUP".format(
            fidsize, len(parameters)))
        
        return fidsize, parameters

    def is_parameter_data_ready(self) -> bool:
        """Check if parameter data is ready for SUP operation"""
        return (self.parsed_fidsize is not None and 
                self.parsed_parameters is not None and 
                len(self.parsed_parameters) > 0)

    def log_parameter_data_summary(self):
        """Log summary of current parameter data"""
        if self.is_parameter_data_ready():
            self.log_message("Parameter Data Summary:")
            self.log_message("  FIDSize: {}".format(self.parsed_fidsize))
            self.log_message("  Parameter count: {}".format(len(self.parsed_parameters)))
            self.log_message("  First 3 parameters: {}".format(
                [hex(p) for p in self.parsed_parameters[:3]]))
            if len(self.parsed_parameters) > 3:
                self.log_message("  Last 3 parameters: {}".format(
                    [hex(p) for p in self.parsed_parameters[-3:]]))

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
        """Start HIOC operation with validation"""
        server = self.server_var.get()
        fid = self.fid_var.get()
        operation = self.operation_var.get()
        
        if not server or not fid:
            messagebox.showerror("Selection Required", "Please select server and function ID.")
            return
            
        if self.operation_in_progress:
            messagebox.showwarning("Operation in Progress", "Another operation is already in progress.")
            return
        
        # Validate using HIOCSUPValidator (fresh validation at operation start)
        self.log_message("=== OPERATION VALIDATION ===")
        self.operation_in_progress = True
        
        try:
            # Create fresh validator for operation
            if server == "CG1 & CG2":
                validator = HIOCSUPValidator(
                    self.servers['CG1'].client,
                    self.servers['CG2'].client,
                    progress_callback=self.update_progress,
                    cg1_controller_id=self.servers['CG1'].controller_id,
                    cg2_controller_id=self.servers['CG2'].controller_id
                )
            else:
                validator = HIOCSUPValidator(
                    self.servers[server].client,
                    progress_callback=self.update_progress,
                    cg1_controller_id=self.servers[server].controller_id
                )
            
            if not validator.validate(fid):
                self.update_progress("✗ Operation validation failed")
                self.operation_in_progress = False
                return
            
            # Validate operation type against validation results
            if operation == "threshold" and not validator.is_hioc_th():
                self.update_progress("✗ Threshold operations not supported for this FID (FIDSize={})".format(validator.fidsize))
                self.operation_in_progress = False
                return
            
            if operation == "parameter_set" and not validator.supports_hiocwsup():
                self.update_progress("✗ HIOCwSUP operations not supported for this FID (FIDSize={})".format(validator.fidsize))
                self.operation_in_progress = False
                return
            
            # Additional validation for parameter set operations
            if operation == "parameter_set":
                if not self.selected_file_path or not self.is_parameter_data_ready():
                    self.update_progress("✗ Parameter file required for HIOCwSUP operations")
                    self.operation_in_progress = False
                    return
            
            self.update_progress("✓ Operation validation successful - proceeding...")
            
            # Clear log and start operation
            self.log_text.delete(1.0, tk.END)
            
            # Execute operation based on type
            if operation == "threshold":
                self.execute_threshold_operation(server, fid, validator)
            elif operation == "parameter_set":
                self.execute_sup_operation(server, fid)
            else:
                self.execute_hioc_operation(server, fid, operation)
                
        except Exception as e:
            self.update_progress("✗ Operation error: {}".format(e))
            self.operation_in_progress = False

    def execute_threshold_operation(self, server: str, fid: str, validator: HIOCSUPValidator):
        """Execute threshold operation with validated HTT values"""
        if server == "CG1 & CG2":
            self.show_threshold_selection_dual(fid, validator.th_val_array)
        else:
            self.show_threshold_selection_single(server, fid, validator.th_val_array)

    def show_threshold_selection_single(self, server: str, fid: str, htt_values: Dict[int, Any]):
        """Show threshold selection for single server"""
        self.show_threshold_selection_dialog(
            title="Select Threshold - {} {}".format(server, fid),
            htt_values=htt_values,
            callback=lambda cc, value: self.continue_single_threshold_operation(server, fid, cc, value)
        )

    def show_threshold_selection_dual(self, fid: str, htt_values: Dict[int, Any]):
        """Show threshold selection for dual operation"""
        self.show_threshold_selection_dialog(
            title="Select Threshold - CG1 & CG2 {}".format(fid),
            htt_values=htt_values,
            callback=lambda cc, value: self.continue_dual_threshold_operation(fid, cc, value),
            subtitle="(HTT values verified equivalent between systems)"
        )

    def show_threshold_selection_dialog(self, title: str, htt_values: Dict[int, Any], 
                                      callback: Callable, subtitle: str = None):
        """Generic threshold selection dialog"""
        selection_dialog = tk.Toplevel(self.dialog)
        selection_dialog.title(title)
        selection_dialog.geometry("400x500")
        selection_dialog.grab_set()
        
        ttk.Label(selection_dialog, text=title + ":", 
                 font=('TkDefaultFont', 10, 'bold')).pack(pady=10)
        
        if subtitle:
            ttk.Label(selection_dialog, text=subtitle,
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
                
                selection_dialog.destroy()
                callback(cc, value)
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

    def continue_single_threshold_operation(self, server: str, fid: str, threshold_cc: int, threshold_value: Any):
        """Continue with single server threshold operation"""
        server_info = self.servers[server]
        
        config = HIOCOperationConfig(
            client=server_info.client,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=HIOCOperationType.THRESHOLD,
            threshold_command_code=threshold_cc,
            threshold_value=threshold_value,
            progress_callback=self.update_progress
        )
        
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        if success:
            self.update_progress("✓ Threshold operation completed successfully")
        else:
            self.update_progress("✗ Threshold operation failed")
            self.log_message(operator.get_abort_analysis())
        
        self.operation_in_progress = False

    def continue_dual_threshold_operation(self, fid: str, threshold_cc: int, threshold_value: Any):
        """Continue with dual server threshold operation"""
        try:
            # Execute on CG1 first
            self.update_progress("Starting CG1 threshold operation...")
            
            cg1_config = HIOCOperationConfig(
                client=self.servers['CG1'].client,
                controller_id=self.servers['CG1'].controller_id,
                fid=fid,
                operation_type=HIOCOperationType.THRESHOLD,
                threshold_command_code=threshold_cc,
                threshold_value=threshold_value,
                progress_callback=lambda msg: self.update_progress("CG1: {}".format(msg))
            )
            
            cg1_operator = HIOCOperator(cg1_config)
            cg1_success = cg1_operator.execute_operation()
            
            if cg1_success:
                self.update_progress("✓ CG1 completed - Starting CG2...")
                
                cg2_config = HIOCOperationConfig(
                    client=self.servers['CG2'].client,
                    controller_id=self.servers['CG2'].controller_id,
                    fid=fid,
                    operation_type=HIOCOperationType.THRESHOLD,
                    threshold_command_code=threshold_cc,
                    threshold_value=threshold_value,
                    progress_callback=lambda msg: self.update_progress("CG2: {}".format(msg))
                )
                
                cg2_operator = HIOCOperator(cg2_config)
                cg2_success = cg2_operator.execute_operation()
                
                if cg2_success:
                    self.update_progress("✓ Both CG1 and CG2 threshold operations completed successfully")
                else:
                    self.update_progress("✗ CG2 threshold operation failed")
                    self.log_message("--- CG2 ABORT ANALYSIS ---")
                    self.log_message(cg2_operator.get_abort_analysis())
            else:
                self.update_progress("✗ CG1 threshold operation failed - CG2 cancelled")
                self.log_message("--- CG1 ABORT ANALYSIS ---")
                self.log_message(cg1_operator.get_abort_analysis())
                
        except Exception as e:
            self.update_progress("✗ Dual threshold operation error: {}".format(e))
            
        self.operation_in_progress = False

    def execute_sup_operation(self, server: str, fid: str):
        """Execute SUP operation (single or dual)"""
        if server == "CG1 & CG2":
            self.execute_dual_sup_operation(fid)
        else:
            self.execute_single_sup_operation(server, fid)

    def execute_single_sup_operation(self, server: str, fid: str):
        """Execute SUP operation on single server"""
        try:
            success = self.execute_single_sup_operation_sync(server, fid)
            
            if success:
                self.update_progress("✓ {} HIOCwSUP operation completed successfully".format(server))
            else:
                self.update_progress("✗ {} HIOCwSUP operation failed".format(server))
                
        except Exception as e:
            self.update_progress("✗ {} HIOCwSUP operation error: {}".format(server, e))
            
        self.operation_in_progress = False

    def execute_dual_sup_operation(self, fid: str):
        """Execute SUP operation on both CG1 and CG2"""
        try:
            # Execute on CG1 first
            self.update_progress("Starting CG1 HIOCwSUP operation...")
            cg1_success = self.execute_single_sup_operation_sync('CG1', fid)
            
            if cg1_success:
                self.update_progress("✓ CG1 completed - Starting CG2 HIOCwSUP operation...")
                cg2_success = self.execute_single_sup_operation_sync('CG2', fid)
                
                if cg2_success:
                    self.update_progress("✓ Both CG1 and CG2 HIOCwSUP operations completed successfully")
                else:
                    self.update_progress("✗ CG2 HIOCwSUP operation failed")
            else:
                self.update_progress("✗ CG1 HIOCwSUP operation failed - CG2 cancelled")
                
        except Exception as e:
            self.update_progress("✗ Dual HIOCwSUP operation error: {}".format(e))
            
        self.operation_in_progress = False

    def execute_single_sup_operation_sync(self, server: str, fid: str) -> bool:
        """Execute SUP operation synchronously and return success status"""
        server_info = self.servers[server]
        
        if not server_info.connected or not server_info.client:
            self.update_progress("{}: Not connected".format(server))
            return False
        
        if not self.is_parameter_data_ready():
            self.update_progress("{}: Parameter data not available".format(server))
            return False
        
        try:
            # Step 1: Request nonce
            self.update_progress("{}: Requesting nonce...".format(server))
            
            sup_config_nonce = SUPOperationConfig(
                client=server_info.client,
                controller_id=server_info.controller_id,
                fid=fid,
                parameters=self.parsed_parameters,
                progress_callback=lambda msg: self.update_progress("{}: {}".format(server, msg))
            )
            
            sup_operator_nonce = SUPOperator(sup_config_nonce)
            nonce_success = sup_operator_nonce.request_nonce()
            
            if not nonce_success:
                self.update_progress("{}: Nonce request failed".format(server))
                self.log_message("--- {} NONCE ABORT ANALYSIS ---".format(server))
                self.log_message(sup_operator_nonce.get_abort_analysis())
                return False
            
            # Step 2: Calculate CRC32
            self.update_progress("{}: Calculating CRC32...".format(server))
            crc32_success = sup_operator_nonce.calculate_crc32()
            
            if not crc32_success:
                self.update_progress("{}: CRC32 calculation failed".format(server))
                return False
            
            crc32_value = sup_operator_nonce.crc32_value
            
            # Step 3: HIOC unlock
            self.update_progress("{}: HIOC unlock sequence...".format(server))
            
            hioc_config = HIOCOperationConfig(
                client=server_info.client,
                controller_id=server_info.controller_id,
                fid=fid,
                operation_type=HIOCOperationType.THRESHOLD,  # Placeholder
                threshold_command_code=50,  # Unlock command
                threshold_value=crc32_value,
                progress_callback=lambda msg: self.update_progress("{}: {}".format(server, msg))
            )
            
            hiocwsup_operator = HIOCwSUPOperator(hioc_config)
            unlock_success = hiocwsup_operator.perform_unlock_sequence(crc32_value)
            
            if not unlock_success:
                self.update_progress("{}: HIOC unlock failed".format(server))
                self.log_message("--- {} HIOC UNLOCK ABORT ANALYSIS ---".format(server))
                self.log_message(hiocwsup_operator.get_abort_analysis())
                return False
            
            # Step 4: SUP operation
            self.update_progress("{}: SUP sequence...".format(server))
            
            sup_config_final = SUPOperationConfig(
                client=server_info.client,
                controller_id=server_info.controller_id,
                fid=fid,
                parameters=self.parsed_parameters,
                nonce=sup_operator_nonce.nonce_value,
                progress_callback=lambda msg: self.update_progress("{}: {}".format(server, msg))
            )
            
            sup_operator_final = SUPOperator(sup_config_final)
            sup_success = sup_operator_final.execute_operation()
            
            if sup_success:
                self.update_progress("✓ {} HIOCwSUP operation completed successfully".format(server))
                return True
            else:
                self.update_progress("✗ {} SUP operation failed".format(server))
                self.log_message("--- {} SUP ABORT ANALYSIS ---".format(server))
                self.log_message(sup_operator_final.get_abort_analysis())
                return False
                
        except Exception as e:
            self.update_progress("✗ {} HIOCwSUP operation error: {}".format(server, e))
            return False

    def execute_hioc_operation(self, server: str, fid: str, operation: str):
        """Execute standard HIOC operation (single or dual)"""
        if server == "CG1 & CG2":
            self.execute_dual_hioc_operation(fid, operation)
        else:
            self.execute_single_hioc_operation(server, fid, operation)

    def execute_single_hioc_operation(self, server: str, fid: str, operation: str):
        """Execute HIOC operation on single server"""
        try:
            success = self.execute_single_hioc_operation_sync(server, fid, operation)
            
            if success:
                self.update_progress("✓ {} operation completed successfully".format(server))
            else:
                self.update_progress("✗ {} operation failed".format(server))
                
        except Exception as e:
            self.update_progress("✗ {} operation error: {}".format(server, e))
            
        self.operation_in_progress = False

    def execute_dual_hioc_operation(self, fid: str, operation: str):
        """Execute HIOC operation on both CG1 and CG2"""
        try:
            # Execute on CG1 first
            self.update_progress("Starting CG1 operation...")
            cg1_success = self.execute_single_hioc_operation_sync('CG1', fid, operation)
            
            if cg1_success:
                self.update_progress("✓ CG1 completed - Starting CG2 operation...")
                cg2_success = self.execute_single_hioc_operation_sync('CG2', fid, operation)
                
                if cg2_success:
                    self.update_progress("✓ Both CG1 and CG2 operations completed successfully")
                else:
                    self.update_progress("✗ CG2 operation failed")
            else:
                self.update_progress("✗ CG1 operation failed - CG2 cancelled")
                
        except Exception as e:
            self.update_progress("✗ Dual operation error: {}".format(e))
            
        self.operation_in_progress = False

    def execute_single_hioc_operation_sync(self, server: str, fid: str, operation: str) -> bool:
        """Execute HIOC operation synchronously and return success status"""
        server_info = self.servers[server]
        
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
            self.update_progress("{}: Invalid operation: {}".format(server, operation))
            return False
        
        # Create HIOCOperator configuration
        config = HIOCOperationConfig(
            client=server_info.client,
            controller_id=server_info.controller_id,
            fid=fid,
            operation_type=hioc_operation,
            progress_callback=lambda msg: self.update_progress("{}: {}".format(server, msg))
        )
        
        # Execute operation
        operator = HIOCOperator(config)
        success = operator.execute_operation()
        
        if success:
            self.update_progress("✓ {} operation completed successfully".format(server))
        else:
            self.update_progress("✗ {} operation failed".format(server))
            self.log_message("--- {} ABORT ANALYSIS ---".format(server))
            self.log_message(operator.get_abort_analysis())
        
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
    dialog = HIOCDialog(parent, servers)
    
    return dialog