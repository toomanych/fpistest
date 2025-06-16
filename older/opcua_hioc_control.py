#!/usr/bin/env python3
"""
OPC-UA Server Control GUI with IOP (In-Out Pulse) Support and HIOC Protocol
Python 3.6+ compatible
Requires: opcua library (pip install opcua)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from opcua import Client
from opcua.common.node import Node
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Reduce OPC-UA library logging to WARNING level to reduce chatter
logging.getLogger('opcua').setLevel(logging.WARNING)
logging.getLogger('opcua.client').setLevel(logging.WARNING)
logging.getLogger('opcua.uaprotocol').setLevel(logging.WARNING)
logging.getLogger('opcua.client.ua_client').setLevel(logging.WARNING)

class HIOCProtocol:
    def __init__(self, controller):
        self.controller = controller
        self.current_sequence = 1
        self.last_response_sequence = 0  # Track last response sequence
        self.current_server = None
        self.current_fid = None
        self.operation_in_progress = False
        self.operation_log = []
        self.selected_threshold = None
        self.htt_values = {}
        
        # Controller IDs
        self.controller_ids = {
            'CG1': 1464099,
            'CG2': 1464098
        }
        
        # Message IDs
        self.message_types = {
            'FUNCTION': lambda fid_num: 2460000 + fid_num,
            'COMMAND': lambda cc: 3460000 + cc,
            'CONFIRMATION': lambda fid_num, cc: 4000000 + fid_num * 100 + cc,  # Fixed: 4NNNNCC format
            'ABORT_CONTROLLER': 9000000,
            'ABORT_USER': 9100000,
            'ABORT_TIME': 9300000,
            'SUCCESS': 7500000
        }
        
        # Command codes
        self.command_codes = {
            'threshold': list(range(1, 16)),  # 1-15
            'override_set': 20,
            'override_unset': 25,
            'disable': 30,
            'enable': 35
        }
        
        # Flag mappings
        self.flags = {
            'function_th_override_disable': 1,
            'function_unset_enable': 11,
            'command_th_override_disable': 3,
            'command_unset_enable': 13,
            'confirmation_th_override_disable': 5,
            'confirmation_unset_enable': 15,
            'abort': 9,
            'htt_request': 21,
            'htt_response': 22,
            'success': 6
        }

    def reset_sequence(self, server, fid):
        """Reset sequence number based on current server response"""
        try:
            # Read current response sequence from server
            current_response_seq = self.read_current_response_sequence(server, fid)
            if current_response_seq is not None:
                self.last_response_sequence = current_response_seq
                logger.info(f"Read current response SEQ: {current_response_seq}")
            else:
                # If can't read, assume starting fresh
                self.last_response_sequence = 0
                logger.info("Could not read current response SEQ, starting from 0")
        except Exception as e:
            logger.warning(f"Error reading current response sequence: {e}, starting from 0")
            self.last_response_sequence = 0

    def read_current_response_sequence(self, server, fid):
        """Read current response sequence number from server"""
        try:
            if not self.controller.servers[server]['connected']:
                return None
                
            client = self.controller.servers[server]['client']
            objects = client.get_objects_node()
            
            seq_node = objects.get_child(["1:HIOCOut", f"1:{fid}", "1:FTS", "1:SEQ"])
            sequence = seq_node.get_value()
            return sequence
            
        except Exception as e:
            logger.warning(f"Failed to read current response sequence: {e}")
            return None

    def get_next_challenge_sequence(self):
        """Get next challenge sequence number based on last response"""
        if self.last_response_sequence == 0:
            # First challenge or after server overflow
            seq = 1
        else:
            # Challenge SEQ are always odd: 1, 3, 5, ..., 251, 253
            # Response SEQ are always even or 0: 0, 2, 4, ..., 252, 254
            # Next challenge = last_response + 1 (which makes it odd)
            next_seq = self.last_response_sequence + 1
            
            # Handle challenge overflow: after 253 -> 1
            if next_seq > 253:
                seq = 1
            else:
                seq = next_seq
        
        self.current_sequence = seq
        logger.info(f"Next challenge SEQ: {seq} (last response was {self.last_response_sequence})")
        return seq

    def update_response_sequence(self, response_seq):
        """Update the last response sequence number"""
        self.last_response_sequence = response_seq

    def write_challenge(self, server, fid, controller_id, flag, message_id, value):
        """Write a challenge to the server"""
        try:
            client = self.controller.servers[server]['client']
            objects = client.get_objects_node()
            
            seq = self.get_next_challenge_sequence()
            
            # Debug logging
            logger.info(f"Writing challenge to {server} {fid}: SEQ={seq}, CTR={controller_id}, FLG={flag}, MSG={message_id}, VAL={value}")
            
            # Convert values to correct types: uint32 for most fields, int32 for SEQ
            controller_id = int(controller_id) & 0xFFFFFFFF  # uint32
            flag = int(flag) & 0xFFFFFFFF  # uint32
            message_id = int(message_id) & 0xFFFFFFFF  # uint32
            value = int(value) & 0xFFFFFFFF  # uint32
            
            # SEQ is int32, so handle signed integer range
            seq = int(seq)
            if seq > 0x7FFFFFFF:  # Handle int32 range
                seq = seq - 0x100000000
            
            # Write challenge variables in order
            ctr_node = objects.get_child(["1:HIOCIn", f"1:{fid}", "1:STF", "1:CTR"])
            ctr_node.set_value(controller_id)
            logger.info(f"CTR written: {controller_id}")
            
            flg_node = objects.get_child(["1:HIOCIn", f"1:{fid}", "1:STF", "1:FLG"])
            flg_node.set_value(flag)
            logger.info(f"FLG written: {flag}")
            
            msg_node = objects.get_child(["1:HIOCIn", f"1:{fid}", "1:STF", "1:MSG"])
            msg_node.set_value(message_id)
            logger.info(f"MSG written: {message_id}")
            
            val_node = objects.get_child(["1:HIOCIn", f"1:{fid}", "1:STF", "1:VALUE"])
            val_node.set_value(value)
            logger.info(f"VALUE written: {value}")
            
            # Write sequence number last with proper type handling
            seq_path = ["1:HIOCIn", f"1:{fid}", "1:STF", "1:SEQ"]
            logger.info(f"SEQ browse path: {seq_path}")
            seq_node = objects.get_child(seq_path)
            
            # Inspect the node's data type
            try:
                data_type = seq_node.get_data_type()
                logger.info(f"SEQ node data type: {data_type}")
                
                # Get the current value to see its type
                current_value = seq_node.get_value()
                logger.info(f"SEQ current value: {current_value} (type: {type(current_value)})")
            except Exception as inspect_error:
                logger.warning(f"Could not inspect SEQ node: {inspect_error}")
            
            logger.info(f"SEQ node found: {seq_node}, writing value: {seq} (type: {type(seq)})")
            
            # Try different approaches to write the sequence number
            try:
                # Use Int32 variant as this was successful
                from opcua import ua
                seq_variant = ua.Variant(seq, ua.VariantType.Int32)
                seq_node.set_value(seq_variant)
                logger.info(f"SEQ written successfully: {seq}")
            except Exception as e:
                logger.error(f"Failed to write SEQ: {e}")
                raise e
            
            # Verify the write by reading back
            try:
                read_back = seq_node.get_value()
                logger.info(f"SEQ read back: {read_back}")
            except Exception as read_error:
                logger.error(f"Failed to read back SEQ: {read_error}")
            
            # Log the challenge
            challenge = {
                'type': 'challenge',
                'sequence': seq,
                'controller_id': controller_id,
                'flag': flag,
                'message_id': message_id,
                'value': value,
                'timestamp': time.time()
            }
            self.operation_log.append(challenge)
            
            logger.info(f"Challenge completed: SEQ={seq}, FLG={flag}, MSG={message_id}, VAL={value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write challenge: {e}")
            logger.error(f"Exception details: {type(e).__name__}: {str(e)}")
            return False

    def read_response(self, server, fid, expected_sequence):
        """Read response from server"""
        try:
            client = self.controller.servers[server]['client']
            objects = client.get_objects_node()
            
            # Read response variables
            ctr_node = objects.get_child(["1:HIOCOut", f"1:{fid}", "1:FTS", "1:CTR"])
            controller_id = ctr_node.get_value()
            
            flg_node = objects.get_child(["1:HIOCOut", f"1:{fid}", "1:FTS", "1:FLG"])
            flag = flg_node.get_value()
            
            msg_node = objects.get_child(["1:HIOCOut", f"1:{fid}", "1:FTS", "1:MSG"])
            message_id = msg_node.get_value()
            
            val_node = objects.get_child(["1:HIOCOut", f"1:{fid}", "1:FTS", "1:VALUE"])
            value = val_node.get_value()
            
            seq_node = objects.get_child(["1:HIOCOut", f"1:{fid}", "1:FTS", "1:SEQ"])
            sequence = seq_node.get_value()
            
            # Log what we read regardless of whether it matches expected
            logger.info(f"Read response: SEQ={sequence}, FLG={flag}, MSG={message_id}, VAL={value} (expected SEQ={expected_sequence})")
            
            # Check if this is a response to our challenge
            if sequence == expected_sequence:
                # Update our last response sequence
                self.update_response_sequence(sequence)
                
                response = {
                    'type': 'response',
                    'sequence': sequence,
                    'controller_id': controller_id,
                    'flag': flag,
                    'message_id': message_id,
                    'value': value,
                    'timestamp': time.time()
                }
                self.operation_log.append(response)
                
                logger.info(f"✓ Response matched: SEQ={sequence}, FLG={flag}, MSG={message_id}, VAL={value}")
                return response
            else:
                logger.debug(f"Response SEQ {sequence} doesn't match expected {expected_sequence}")
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to read response: {e}")
            return None

    def read_htt_values(self, server):
        """Read HTT threshold values"""
        try:
            client = self.controller.servers[server]['client']
            objects = client.get_objects_node()
            
            htt_values = {}
            for i in range(1, 16):
                try:
                    htt_node = objects.get_child(["1:HTT", f"1:TH{i}"])
                    value = htt_node.get_value()
                    htt_values[i] = value
                except:
                    htt_values[i] = None
            
            return htt_values
            
        except Exception as e:
            logger.error(f"Failed to read HTT values: {e}")
            return {}

    def wait_for_response(self, server, fid, expected_sequence, timeout=10):
        """Wait for response with timeout"""
        logger.info(f"Waiting for response SEQ={expected_sequence} from {server} {fid}")
        start_time = time.time()
        while time.time() - start_time < timeout:
            response = self.read_response(server, fid, expected_sequence)
            if response:
                return response
            time.sleep(0.1)
        
        logger.error(f"Timeout waiting for response SEQ={expected_sequence} after {timeout}s")
        return None

    def send_abort(self, server, fid):
        """Send abort command"""
        controller_id = self.controller_ids[server]
        return self.write_challenge(server, fid, controller_id, self.flags['abort'], 
                                  self.message_types['ABORT_USER'], 0)


class HIOCDialog:
    def __init__(self, parent, hioc_protocol):
        self.parent = parent
        self.hioc = hioc_protocol
        self.dialog = None
        self.progress_var = None
        self.log_text = None
        
    def show(self):
        """Show HIOC operation dialog"""
        if self.hioc.operation_in_progress:
            messagebox.showwarning("Operation in Progress", 
                                 "Another HIOC operation is already in progress.")
            return
            
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("HIOC Parameter Configuration")
        self.dialog.geometry("600x500")
        self.dialog.grab_set()
        
        # Server selection
        server_frame = ttk.LabelFrame(self.dialog, text="Server Selection", padding="5")
        server_frame.pack(fill="x", padx=10, pady=5)
        
        self.server_var = tk.StringVar()
        servers = []
        cg1_connected = self.hioc.controller.servers['CG1']['connected']
        cg2_connected = self.hioc.controller.servers['CG2']['connected']
        
        if cg1_connected:
            servers.append('CG1')
        if cg2_connected:
            servers.append('CG2')
        if cg1_connected and cg2_connected:
            servers.append('CG1 & CG2')
            
        if not servers:
            messagebox.showerror("No Connection", "No CG servers are connected.")
            self.dialog.destroy()
            return
            
        ttk.Label(server_frame, text="Server:").pack(side="left")
        server_combo = ttk.Combobox(server_frame, textvariable=self.server_var, 
                                   values=servers, state="readonly", width=15)
        server_combo.pack(side="left", padx=5)
        if servers:
            server_combo.current(0)
        
        # FID selection
        ttk.Label(server_frame, text="Function ID:").pack(side="left", padx=(20, 0))
        self.fid_var = tk.StringVar()
        fid_combo = ttk.Combobox(server_frame, textvariable=self.fid_var,
                                values=['F0', 'F1', 'F2', 'F3', 'F4', 'F5'], 
                                state="readonly", width=5)
        fid_combo.pack(side="left", padx=5)
        fid_combo.current(0)
        
        # Operation selection
        op_frame = ttk.LabelFrame(self.dialog, text="Operation Type", padding="5")
        op_frame.pack(fill="x", padx=10, pady=5)
        
        self.operation_var = tk.StringVar(value="threshold")
        operations = [
            ("Threshold", "threshold"),
            ("Override Set", "override_set"),
            ("Override Unset", "override_unset"),
            ("Disable", "disable"),
            ("Enable", "enable")
        ]
        
        for i, (text, value) in enumerate(operations):
            ttk.Radiobutton(op_frame, text=text, variable=self.operation_var, 
                           value=value).grid(row=i//3, column=i%3, sticky="w", padx=10)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(self.dialog, text="Progress", padding="5")
        progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.progress_var = tk.StringVar(value="Ready to start")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack()
        
        # Log frame
        log_frame = ttk.LabelFrame(self.dialog, text="Operation Log", padding="5")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = tk.Text(log_frame, height=10, width=70)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        
        # Button frame
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(button_frame, text="Start Operation", 
                  command=self.start_operation).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel/Abort", 
                  command=self.abort_operation).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Close", 
                  command=self.close_dialog).pack(side="right", padx=5)

    def log_message(self, message):
        """Add message to log"""
        if self.log_text:
            self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')}: {message}\n")
            self.log_text.see(tk.END)

    def update_progress(self, message):
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
            
        if self.hioc.operation_in_progress:
            messagebox.showwarning("Operation in Progress", 
                                 "Another operation is already in progress.")
            return
        
        # Start operation in background thread
        self.hioc.operation_in_progress = True
        self.hioc.operation_log = []
        self.hioc.current_server = server
        self.hioc.current_fid = fid
        
        if server == "CG1 & CG2":
            # Dual server operation
            self.hioc.reset_sequence('CG1', fid)  # Start with CG1 sequence
            thread = threading.Thread(target=self.execute_dual_operation, 
                                    args=(fid, operation), daemon=True)
        else:
            # Single server operation
            self.hioc.reset_sequence(server, fid)
            thread = threading.Thread(target=self.execute_operation, 
                                    args=(server, fid, operation), daemon=True)
        thread.start()

    def execute_operation(self, server, fid, operation):
        """Execute HIOC operation for single server"""
        try:
            controller_id = self.hioc.controller_ids[server]
            fid_num = int(fid[1])  # Extract number from F0, F1, etc.
            
            # Step 1: Function validation
            self.dialog.after(0, self.update_progress, "Step 1: Validating function...")
            
            if operation == "threshold":
                # Request HTT values first
                flag = self.hioc.flags['htt_request']
                message_id = self.hioc.message_types['FUNCTION'](fid_num)
                success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, 0)
                
                if not success:
                    self.dialog.after(0, self.update_progress, "Failed to send HTT request")
                    self.hioc.operation_in_progress = False
                    return
                
                # Wait for HTT response
                expected_seq = self.hioc.current_sequence + 1
                logger.info(f"Waiting for HTT response with SEQ={expected_seq} (challenge was {self.hioc.current_sequence})")
                response = self.hioc.wait_for_response(server, fid, expected_seq)
                
                if not response:
                    self.dialog.after(0, self.update_progress, "Timeout waiting for HTT response")
                    self.hioc.operation_in_progress = False
                    return
                
                if response['flag'] != self.hioc.flags['htt_response']:
                    self.dialog.after(0, self.update_progress, "Invalid HTT response")
                    self.hioc.operation_in_progress = False
                    return
                
                # Read HTT values and show selection dialog
                self.dialog.after(0, self.show_threshold_selection, server)
                return  # Wait for user selection
            
            # For non-threshold operations, proceed with normal function validation
            flag = (self.hioc.flags['function_th_override_disable'] if operation in ['threshold', 'override_set', 'disable']
                   else self.hioc.flags['function_unset_enable'])
            message_id = self.hioc.message_types['FUNCTION'](fid_num)
            
            success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, 0)
            if not success:
                self.dialog.after(0, self.update_progress, "Failed to send function validation")
                self.hioc.operation_in_progress = False
                return
            
            # Continue with step 1
            self.dialog.after(0, self.continue_with_step1, server, fid, operation, None)
            
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Error: {e}")
            self.hioc.operation_in_progress = False

    def execute_dual_operation(self, fid, operation):
        """Execute HIOC operation on both CG1 and CG2"""
        try:
            fid_num = int(fid[1])
            
            if operation == "threshold":
                # Dual HTT request and comparison
                self.dialog.after(0, self.update_progress, "Requesting HTT from both CG1 and CG2...")
                
                # Reset sequences for both servers and send HTT requests
                self.hioc.reset_sequence('CG1', fid)
                cg1_challenge_seq = self.hioc.current_sequence
                cg1_success = self.send_htt_request('CG1', fid, fid_num)
                
                self.hioc.reset_sequence('CG2', fid) 
                cg2_challenge_seq = self.hioc.current_sequence
                cg2_success = self.send_htt_request('CG2', fid, fid_num)
                
                if not (cg1_success and cg2_success):
                    self.dialog.after(0, self.update_progress, "Failed to send HTT requests")
                    self.hioc.operation_in_progress = False
                    return
                
                # Wait for both HTT responses with correct expected sequences
                cg1_expected_seq = cg1_challenge_seq + 1
                cg2_expected_seq = cg2_challenge_seq + 1
                
                cg1_response = self.hioc.wait_for_response('CG1', fid, cg1_expected_seq)
                cg2_response = self.hioc.wait_for_response('CG2', fid, cg2_expected_seq)
                
                if not (cg1_response and cg2_response):
                    self.dialog.after(0, self.update_progress, "Timeout waiting for HTT responses")
                    self.hioc.operation_in_progress = False
                    return
                
                # Update response sequences for both servers
                self.hioc.update_response_sequence(cg1_response['sequence'])  # This will be overwritten, but that's ok
                
                # Read and compare HTT values
                cg1_htt = self.hioc.read_htt_values('CG1')
                cg2_htt = self.hioc.read_htt_values('CG2')
                
                if not self.compare_htt_values(cg1_htt, cg2_htt):
                    # HTT values don't match - abort both systems
                    self.dialog.after(0, self.update_progress, "HTT values mismatch - aborting both systems")
                    self.hioc.send_abort('CG1', fid)
                    self.hioc.send_abort('CG2', fid)
                    self.hioc.operation_in_progress = False
                    return
                
                # HTT values match - show threshold selection
                self.dialog.after(0, self.show_threshold_selection_dual, cg1_htt, fid, operation)
                return
            
            # For non-threshold operations, proceed with CG1 first
            self.execute_single_system_operation('CG1', fid, operation, None, continue_with_cg2=True)
            
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Error in dual operation: {e}")
            self.hioc.operation_in_progress = False

    def send_htt_request(self, server, fid, fid_num):
        """Send HTT request to a single server"""
        try:
            controller_id = self.hioc.controller_ids[server]
            flag = self.hioc.flags['htt_request']
            message_id = self.hioc.message_types['FUNCTION'](fid_num)
            # Note: sequence is managed by write_challenge which calls get_next_challenge_sequence
            return self.hioc.write_challenge(server, fid, controller_id, flag, message_id, 0)
        except Exception as e:
            logger.error(f"Failed to send HTT request to {server}: {e}")
            return False

    def wait_for_htt_response(self, server, fid):
        """Wait for HTT response from a single server"""
        try:
            expected_seq = self.hioc.current_sequence + 1
            response = self.hioc.wait_for_response(server, fid, expected_seq)
            
            if response and response['flag'] == self.hioc.flags['htt_response']:
                return response
            return None
        except Exception as e:
            logger.error(f"Error waiting for HTT response from {server}: {e}")
            return None

    def compare_htt_values(self, cg1_htt, cg2_htt):
        """Compare HTT values between CG1 and CG2"""
        if not cg1_htt or not cg2_htt:
            logger.error("Missing HTT values for comparison")
            return False
        
        mismatches = []
        for i in range(1, 16):
            cg1_val = cg1_htt.get(i)
            cg2_val = cg2_htt.get(i)
            
            if cg1_val != cg2_val:
                mismatches.append(f"TH{i}: CG1={cg1_val}, CG2={cg2_val}")
        
        if mismatches:
            logger.error(f"HTT mismatches found: {'; '.join(mismatches)}")
            self.dialog.after(0, self.show_htt_mismatch_error, mismatches)
            return False
        
        logger.info("HTT values match between CG1 and CG2")
        return True

    def show_htt_mismatch_error(self, mismatches):
        """Show HTT mismatch error dialog"""
        error_msg = "HTT threshold values don't match between CG1 and CG2:\n\n"
        error_msg += "\n".join(mismatches)
        error_msg += "\n\nOperation aborted for both systems."
        messagebox.showerror("HTT Mismatch", error_msg)

    def show_threshold_selection_dual(self, htt_values, fid, operation):
        """Show threshold selection dialog for dual operation"""
        # Create selection dialog
        selection_dialog = tk.Toplevel(self.dialog)
        selection_dialog.title("Select Threshold (CG1 & CG2)")
        selection_dialog.geometry("350x400")
        selection_dialog.grab_set()
        
        ttk.Label(selection_dialog, text="Select threshold to modify on both systems:").pack(pady=10)
        
        # Listbox with threshold values
        listbox = tk.Listbox(selection_dialog, width=50, height=15)
        listbox.pack(pady=10, padx=20, fill="both", expand=True)
        
        threshold_map = {}
        for i in range(1, 16):
            value = htt_values.get(i, "N/A")
            display_text = f"{i}: {value}"
            listbox.insert(tk.END, display_text)
            threshold_map[i-1] = i
        
        def on_select():
            selection = listbox.curselection()
            if selection:
                threshold_num = threshold_map[selection[0]]
                threshold_value = htt_values[threshold_num]
                selection_dialog.destroy()
                self.hioc.selected_threshold = (threshold_num, threshold_value)
                # Continue with dual operation
                self.execute_single_system_operation('CG1', fid, operation, threshold_num, continue_with_cg2=True)
            else:
                messagebox.showwarning("Selection Required", "Please select a threshold.")
        
        def on_cancel():
            selection_dialog.destroy()
            self.update_progress("Threshold selection cancelled")
            self.hioc.operation_in_progress = False
        
        button_frame = ttk.Frame(selection_dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="OK", command=on_select).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side="left", padx=5)

    def execute_single_system_operation(self, server, fid, operation, threshold_num=None, continue_with_cg2=False):
        """Execute HIOC operation on a single system"""
        thread = threading.Thread(target=self.execute_single_system_steps, 
                                args=(server, fid, operation, threshold_num, continue_with_cg2), daemon=True)
        thread.start()

    def execute_single_system_steps(self, server, fid, operation, threshold_num=None, continue_with_cg2=False):
        """Execute all steps for a single system"""
        try:
            # Reset sequence for this server
            self.hioc.reset_sequence(server, fid)
            
            # Execute Step 1: Function validation
            self.dialog.after(0, self.update_progress, f"{server}: Step 1 - Validating function...")
            
            controller_id = self.hioc.controller_ids[server]
            fid_num = int(fid[1])
            
            flag = (self.hioc.flags['function_th_override_disable'] if operation in ['threshold', 'override_set', 'disable']
                   else self.hioc.flags['function_unset_enable'])
            message_id = self.hioc.message_types['FUNCTION'](fid_num)
            
            success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, 0)
            if not success:
                self.dialog.after(0, self.update_progress, f"{server}: Failed to send function validation")
                if continue_with_cg2:
                    self.dialog.after(0, self.update_progress, "CG1 failed - not attempting CG2")
                self.hioc.operation_in_progress = False
                return
            
            # Wait for function validation response
            expected_seq = self.hioc.current_sequence + 1
            response = self.hioc.wait_for_response(server, fid, expected_seq)
            
            if not response:
                self.dialog.after(0, self.update_progress, f"{server}: Timeout waiting for function validation")
                if continue_with_cg2:
                    self.dialog.after(0, self.update_progress, "CG1 failed - not attempting CG2")
                self.hioc.operation_in_progress = False
                return
            
            if self.check_abort_response(response):
                if continue_with_cg2:
                    self.dialog.after(0, self.update_progress, "CG1 aborted - not attempting CG2")
                self.hioc.operation_in_progress = False
                return
            
            # Execute Steps 2 and 3
            success = self.execute_steps_2_and_3(server, fid, operation, threshold_num)
            
            if not success:
                if continue_with_cg2:
                    self.dialog.after(0, self.update_progress, "CG1 failed - not attempting CG2")
                self.hioc.operation_in_progress = False
                return
            
            # CG1 completed successfully
            self.dialog.after(0, self.update_progress, f"✓ {server} completed successfully!")
            
            # If this was CG1 and we need to continue with CG2
            if continue_with_cg2 and server == 'CG1':
                self.execute_single_system_operation('CG2', fid, operation, threshold_num, continue_with_cg2=False)
            else:
                # All operations completed
                if continue_with_cg2:
                    self.dialog.after(0, self.update_progress, "✓ Both CG1 and CG2 completed successfully!")
                self.hioc.operation_in_progress = False
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Error in {server}: {e}")
            if continue_with_cg2:
                self.dialog.after(0, self.update_progress, f"{server} failed - not attempting CG2")
            self.hioc.operation_in_progress = False

    def execute_steps_2_and_3(self, server, fid, operation, threshold_num=None):
        """Execute steps 2 and 3 for a single system"""
        try:
            controller_id = self.hioc.controller_ids[server]
            fid_num = int(fid[1])
            
            # Step 2: Command readiness
            self.dialog.after(0, self.update_progress, f"{server}: Step 2 - Sending command...")
            
            if operation == "threshold" and threshold_num:
                command_code = threshold_num
                value = self.hioc.selected_threshold[1] if self.hioc.selected_threshold else 0
                flag = self.hioc.flags['command_th_override_disable']
            elif operation == "override_set":
                command_code = self.hioc.command_codes['override_set']
                value = 0
                flag = self.hioc.flags['command_th_override_disable']
            elif operation == "override_unset":
                command_code = self.hioc.command_codes['override_unset']
                value = 0
                flag = self.hioc.flags['command_unset_enable']
            elif operation == "disable":
                command_code = self.hioc.command_codes['disable']
                value = 0
                flag = self.hioc.flags['command_th_override_disable']
            elif operation == "enable":
                command_code = self.hioc.command_codes['enable']
                value = 0
                flag = self.hioc.flags['command_unset_enable']
            
            message_id = self.hioc.message_types['COMMAND'](command_code)
            success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, value)
            
            if not success:
                self.dialog.after(0, self.update_progress, f"{server}: Failed to send command")
                return False
            
            # Wait for command response
            expected_seq = self.hioc.current_sequence + 1
            response = self.hioc.wait_for_response(server, fid, expected_seq)
            
            if not response:
                self.dialog.after(0, self.update_progress, f"{server}: Timeout waiting for command response")
                return False
            
            if self.check_abort_response(response):
                return False
            
            # Step 3: Confirmation
            self.dialog.after(0, self.update_progress, f"{server}: Step 3 - Awaiting confirmation...")
            
            # Ask user for final confirmation (only once for dual operations)
            if server == 'CG1' or self.hioc.current_server != "CG1 & CG2":
                operation_desc = {
                    'threshold': f'set threshold {command_code} to {value}',
                    'override_set': 'set override',
                    'override_unset': 'unset override', 
                    'disable': 'disable function',
                    'enable': 'enable function'
                }
                
                desc = operation_desc.get(operation, operation)
                system_desc = server if self.hioc.current_server != "CG1 & CG2" else "both CG1 & CG2"
                
                result = messagebox.askyesno(
                    "Final Confirmation",
                    f"Confirm: {desc} on {system_desc} {fid}?\n\nThis will modify the system configuration."
                )
                
                if not result:
                    # User cancelled - send abort
                    self.hioc.send_abort(server, fid)
                    return False
            
            # Send confirmation
            flag = (self.hioc.flags['confirmation_th_override_disable'] 
                   if operation in ['threshold', 'override_set', 'disable']
                   else self.hioc.flags['confirmation_unset_enable'])
            
            message_id = self.hioc.message_types['CONFIRMATION'](fid_num, command_code)
            success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, value)
            
            if not success:
                self.dialog.after(0, self.update_progress, f"{server}: Failed to send confirmation")
                return False
            
            # Wait for final response
            expected_seq = self.hioc.current_sequence + 1
            response = self.hioc.wait_for_response(server, fid, expected_seq)
            
            if not response:
                self.dialog.after(0, self.update_progress, f"{server}: Timeout waiting for final response")
                return False
            
            # Check for success or abort
            if response['message_id'] == self.hioc.message_types['SUCCESS']:
                return True
            elif response['message_id'] in [
                self.hioc.message_types['ABORT_CONTROLLER'],
                self.hioc.message_types['ABORT_USER'], 
                self.hioc.message_types['ABORT_TIME']
            ]:
                self.check_abort_response(response)
                return False
            else:
                # Unexpected response
                self.dialog.after(0, self.update_progress, f"{server}: Unexpected response to confirmation")
                return False
                
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Error in {server} steps 2-3: {e}")
            return False

    def show_threshold_selection(self, server):
        """Show threshold selection dialog"""
        # Read HTT values
        htt_values = self.hioc.read_htt_values(server)
        
        if not htt_values:
            self.update_progress("Failed to read HTT values")
            self.hioc.operation_in_progress = False
            return
        
        # Create selection dialog
        selection_dialog = tk.Toplevel(self.dialog)
        selection_dialog.title("Select Threshold")
        selection_dialog.geometry("300x400")
        selection_dialog.grab_set()
        
        ttk.Label(selection_dialog, text="Select threshold to modify:").pack(pady=10)
        
        # Listbox with threshold values
        listbox = tk.Listbox(selection_dialog, width=40, height=15)
        listbox.pack(pady=10, padx=20, fill="both", expand=True)
        
        threshold_map = {}
        for i in range(1, 16):
            value = htt_values.get(i, "N/A")
            display_text = f"{i}: {value}"
            listbox.insert(tk.END, display_text)
            threshold_map[i-1] = i  # Map listbox index to threshold number
        
        def on_select():
            selection = listbox.curselection()
            if selection:
                threshold_num = threshold_map[selection[0]]
                threshold_value = htt_values[threshold_num]
                selection_dialog.destroy()
                self.hioc.selected_threshold = (threshold_num, threshold_value)
                # Continue with Step 1: Function validation after threshold selection
                self.continue_with_step1(server, self.hioc.current_fid, "threshold", threshold_num)
            else:
                messagebox.showwarning("Selection Required", "Please select a threshold.")
        
        def on_cancel():
            selection_dialog.destroy()
            self.update_progress("Threshold selection cancelled")
            self.hioc.operation_in_progress = False
        
        button_frame = ttk.Frame(selection_dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="OK", command=on_select).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side="left", padx=5)

    def continue_with_step1(self, server, fid, operation, threshold_num=None):
        """Continue with Step 1: Function validation after HTT (for thresholds) or directly (for others)"""
        thread = threading.Thread(target=self.execute_step1, 
                                args=(server, fid, operation, threshold_num), daemon=True)
        thread.start()

    def execute_step1(self, server, fid, operation, threshold_num=None):
        """Execute Step 1: Function validation"""
        try:
            controller_id = self.hioc.controller_ids[server]
            fid_num = int(fid[1])
            
            # Step 1: Function validation (normal step after HTT for thresholds)
            self.dialog.after(0, self.update_progress, "Step 1: Validating function...")
            
            # For all operations (including threshold), do normal function validation
            flag = (self.hioc.flags['function_th_override_disable'] if operation in ['threshold', 'override_set', 'disable']
                   else self.hioc.flags['function_unset_enable'])
            message_id = self.hioc.message_types['FUNCTION'](fid_num)
            
            success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, 0)
            if not success:
                self.dialog.after(0, self.update_progress, "Failed to send function validation")
                self.hioc.operation_in_progress = False
                return
            
            # Wait for function validation response
            expected_seq = self.hioc.current_sequence + 1
            response = self.hioc.wait_for_response(server, fid, expected_seq)
            
            if not response:
                self.dialog.after(0, self.update_progress, "Timeout waiting for function validation")
                self.hioc.operation_in_progress = False
                return
            
            if self.check_abort_response(response):
                return
            
            # Continue with Step 2
            self.dialog.after(0, self.continue_operation, server, fid, operation, threshold_num)
            
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Error in Step 1: {e}")
            self.hioc.operation_in_progress = False

    def continue_operation(self, server, fid, operation, threshold_num=None):
        """Continue operation with Steps 2 and 3 (after Step 1 is complete)"""
        thread = threading.Thread(target=self.execute_remaining_steps, 
                                args=(server, fid, operation, threshold_num), daemon=True)
        thread.start()

    def execute_remaining_steps(self, server, fid, operation, threshold_num=None):
        """Execute steps 2 and 3 of HIOC protocol (after Step 1 is complete)"""
        try:
            controller_id = self.hioc.controller_ids[server]
            fid_num = int(fid[1])
            
            # Step 2: Command readiness
            self.dialog.after(0, self.update_progress, "Step 2: Sending command...")
            
            if operation == "threshold" and threshold_num:
                command_code = threshold_num
                value = self.hioc.selected_threshold[1] if self.hioc.selected_threshold else 0
                flag = self.hioc.flags['command_th_override_disable']
            elif operation == "override_set":
                command_code = self.hioc.command_codes['override_set']
                value = 0
                flag = self.hioc.flags['command_th_override_disable']
            elif operation == "override_unset":
                command_code = self.hioc.command_codes['override_unset']
                value = 0
                flag = self.hioc.flags['command_unset_enable']
            elif operation == "disable":
                command_code = self.hioc.command_codes['disable']
                value = 0
                flag = self.hioc.flags['command_th_override_disable']
            elif operation == "enable":
                command_code = self.hioc.command_codes['enable']
                value = 0
                flag = self.hioc.flags['command_unset_enable']
            
            message_id = self.hioc.message_types['COMMAND'](command_code)
            success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, value)
            
            if not success:
                self.dialog.after(0, self.update_progress, "Failed to send command")
                self.hioc.operation_in_progress = False
                return
            
            # Wait for command response
            expected_seq = self.hioc.current_sequence + 1
            response = self.hioc.wait_for_response(server, fid, expected_seq)
            
            if not response:
                self.dialog.after(0, self.update_progress, "Timeout waiting for command response")
                self.hioc.operation_in_progress = False
                return
            
            if self.check_abort_response(response):
                return
            
            # Step 3: Confirmation
            self.dialog.after(0, self.update_progress, "Step 3: Awaiting confirmation...")
            
            # Ask user for final confirmation
            self.dialog.after(0, self.ask_final_confirmation, server, fid, operation, 
                            command_code, value, fid_num)
            
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Error in operation: {e}")
            self.hioc.operation_in_progress = False

    def ask_final_confirmation(self, server, fid, operation, command_code, value, fid_num):
        """Ask user for final confirmation"""
        operation_desc = {
            'threshold': f'set threshold {command_code} to {value}',
            'override_set': 'set override',
            'override_unset': 'unset override', 
            'disable': 'disable function',
            'enable': 'enable function'
        }
        
        desc = operation_desc.get(operation, operation)
        result = messagebox.askyesno(
            "Final Confirmation",
            f"Confirm: {desc} on {server} {fid}?\n\nThis will modify the system configuration."
        )
        
        if result:
            # Send confirmation
            thread = threading.Thread(target=self.send_confirmation, 
                                    args=(server, fid, command_code, value, fid_num), daemon=True)
            thread.start()
        else:
            # Send abort
            self.abort_operation()

    def send_confirmation(self, server, fid, command_code, value, fid_num):
        """Send final confirmation"""
        try:
            controller_id = self.hioc.controller_ids[server]
            flag = (self.hioc.flags['confirmation_th_override_disable'] 
                   if self.operation_var.get() in ['threshold', 'override_set', 'disable']
                   else self.hioc.flags['confirmation_unset_enable'])
            
            message_id = self.hioc.message_types['CONFIRMATION'](fid_num, command_code)
            success = self.hioc.write_challenge(server, fid, controller_id, flag, message_id, value)
            
            if not success:
                self.dialog.after(0, self.update_progress, "Failed to send confirmation")
                self.hioc.operation_in_progress = False
                return
            
            # Wait for final response
            expected_seq = self.hioc.current_sequence + 1
            response = self.hioc.wait_for_response(server, fid, expected_seq)
            
            if not response:
                self.dialog.after(0, self.update_progress, "Timeout waiting for final response")
                self.hioc.operation_in_progress = False
                return
            
            # Check for success or abort
            if response['message_id'] == self.hioc.message_types['SUCCESS']:
                self.dialog.after(0, self.update_progress, "✓ Operation completed successfully!")
            elif response['message_id'] in [
                self.hioc.message_types['ABORT_CONTROLLER'],
                self.hioc.message_types['ABORT_USER'], 
                self.hioc.message_types['ABORT_TIME']
            ]:
                self.check_abort_response(response)
            else:
                # Unexpected response
                self.dialog.after(0, self.update_progress, "Unexpected response to confirmation")
            
            self.hioc.operation_in_progress = False
            
        except Exception as e:
            self.dialog.after(0, self.update_progress, f"Error in confirmation: {e}")
            self.hioc.operation_in_progress = False

    def check_abort_response(self, response):
        """Check if response is an abort and handle accordingly"""
        abort_messages = [
            self.hioc.message_types['ABORT_CONTROLLER'],
            self.hioc.message_types['ABORT_USER'], 
            self.hioc.message_types['ABORT_TIME']
        ]
        
        if response['message_id'] in abort_messages:
            abort_type = {
                self.hioc.message_types['ABORT_CONTROLLER']: 'Controller Abort',
                self.hioc.message_types['ABORT_USER']: 'User Abort',
                self.hioc.message_types['ABORT_TIME']: 'Timeout Abort'
            }[response['message_id']]
            
            self.dialog.after(0, self.update_progress, f"Operation aborted: {abort_type}")
            self.dialog.after(0, self.show_operation_log, f"Operation aborted: {abort_type}")
            self.hioc.operation_in_progress = False
            return True
        
        return False

    def show_operation_log(self, title):
        """Show detailed operation log in popup"""
        log_dialog = tk.Toplevel(self.dialog)
        log_dialog.title(f"Operation Log - {title}")
        log_dialog.geometry("600x400")
        
        text_widget = tk.Text(log_dialog, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(log_dialog, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        # Format operation log
        log_content = f"Operation Log - {title}\n{'='*50}\n\n"
        for i, entry in enumerate(self.hioc.operation_log, 1):
            timestamp = time.strftime('%H:%M:%S', time.localtime(entry['timestamp']))
            log_content += f"{i}. {entry['type'].upper()} at {timestamp}\n"
            log_content += f"   Sequence: {entry['sequence']}\n"
            log_content += f"   Controller ID: {entry['controller_id']}\n"
            log_content += f"   Flag: {entry['flag']}\n"
            log_content += f"   Message ID: {entry['message_id']}\n"
            log_content += f"   Value: {entry['value']}\n\n"
        
        text_widget.insert(tk.END, log_content)
        text_widget.config(state=tk.DISABLED)
        
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        ttk.Button(log_dialog, text="Close", command=log_dialog.destroy).pack(pady=10)

    def abort_operation(self):
        """Abort current operation"""
        if not self.hioc.operation_in_progress:
            return
        
        if self.hioc.current_server == "CG1 & CG2":
            # Abort both servers
            if self.hioc.current_fid:
                success1 = self.hioc.send_abort('CG1', self.hioc.current_fid)
                success2 = self.hioc.send_abort('CG2', self.hioc.current_fid)
                if success1 or success2:
                    self.update_progress("Abort command sent to both systems")
                else:
                    self.update_progress("Failed to send abort command to both systems")
        elif self.hioc.current_server and self.hioc.current_fid:
            success = self.hioc.send_abort(self.hioc.current_server, self.hioc.current_fid)
            if success:
                self.update_progress("Abort command sent")
            else:
                self.update_progress("Failed to send abort command")
        
        self.hioc.operation_in_progress = False

    def close_dialog(self):
        """Close dialog"""
        if self.hioc.operation_in_progress:
            result = messagebox.askyesno("Operation in Progress", 
                                       "An operation is in progress. Abort and close?")
            if result:
                self.abort_operation()
            else:
                return
        
        if self.dialog:
            self.dialog.destroy()


class OPCUAController:
    def __init__(self):
        self.servers = {
            'CG1': {'url': 'opc.tcp://4602tv-cpu-4201.codac.iter.org:4840', 'client': None, 'connected': False},
            'CG2': {'url': 'opc.tcp://4602tv-cpu-4202.codac.iter.org:4840', 'client': None, 'connected': False},
            'FPIS': {'url': 'opc.tcp://4602tv-SRV-5101.codac.iter.org:4840', 'client': None, 'connected': False}
        }
        
        # Variable URNs
        self.urns = {
            'CG1': {
                'COS_OPREQ': 'CGX.COS.COS_OPREQ',
                'COS_OPSTATE': 'CGX.COS.COS_OPSTATE',
                'PSOS_OPSTATE': 'CGX.COS.PSOS_OPSTATE'
            },
            'CG2': {
                'COS_OPREQ': 'CGX.COS.COS_OPREQ',
                'COS_OPSTATE': 'CGX.COS.COS_OPSTATE',
                'PSOS_OPSTATE': 'CGX.COS.PSOS_OPSTATE'
            },
            'FPIS': {
                'COS_OPREQ': 'FTS_In.OPREQ',
                'COS_OPSTATE': 'FTS_Out.PSOS.OPSTATE',
                'PSOS_OPSTATE': None  # FPIS doesn't report PSOS
            }
        }
        
        # Command values and descriptions
        self.commands = {
            3: 'gotoReady',
            11: 'gotoLocal',
            2: 'goNotReady',
            4: 'Initialise',
            9: 'Abort',
            6: 'Execute',
            7: 'PostCheck'
        }
        
        # IOP command values and descriptions
        self.iop_commands = {
            3: 'Out-of-Pulse',
            0: 'In-Pulse'
        }
        
        # COS_OPSTATE values and colors
        self.cos_states = {
            1: ('OFF', '#800080'),  # Purple
            2: ('NOT_READY', '#0000FF'),  # Blue
            3: ('READY', '#FFA500'),  # Orange
            4: ('INITIALISING', '#808080'),  # Gray
            5: ('INITIALISED', '#808080'),  # Gray
            6: ('EXECUTING', '#00FF00'),  # Green
            7: ('POST_PULSE_CHECKS', '#FF0000'),  # Red
            9: ('ABORTING', '#808080'),  # Gray
            11: ('LOCAL','#0000FF') #Blue
        }
        
        # PSOS_OPSTATE values
        self.psos_states = {
            1: 'OFF',
            2: 'NOT_READY',
            12: 'LOCAL',
            13: 'CONFIGURE',
            3: 'READY',
            11: 'INHIBIT_NEXT_PULSE',
            4: 'INITIALISING',
            10: 'PLANT_ABORT_91',
            14: 'PLANT_ABORT_92',
            5: 'INITIALISED',
            6: 'EXECUTING',
            7: 'POST_PULSE_CHECKS',
            8: 'TERMINATING',
            9: 'ABORTING'
        }
        
        # IOP state values and colors
        self.iop_states = {
            3: ('Out-of-Pulse', '#FF6B6B'),  # Light Red
            0: ('In-Pulse', '#4ECDC4')  # Light Teal
        }

    def connect_server(self, server_name):
        """Connect to an OPC-UA server"""
        try:
            if self.servers[server_name]['client'] is None:
                self.servers[server_name]['client'] = Client(self.servers[server_name]['url'])
            
            self.servers[server_name]['client'].connect()
            self.servers[server_name]['connected'] = True
            logger.info(f"Connected to {server_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {server_name}: {e}")
            self.servers[server_name]['connected'] = False
            return False

    def disconnect_server(self, server_name):
        """Disconnect from an OPC-UA server"""
        try:
            if self.servers[server_name]['client'] and self.servers[server_name]['connected']:
                self.servers[server_name]['client'].disconnect()
                self.servers[server_name]['connected'] = False
                logger.info(f"Disconnected from {server_name}")
        except Exception as e:
            logger.error(f"Error disconnecting from {server_name}: {e}")

    def write_cos_opreq(self, value):
        """Write COS_OPREQ value to all connected servers"""
        results = {}
        for server_name in self.servers:
            if self.servers[server_name]['connected']:
                try:
                    client = self.servers[server_name]['client']
                    if server_name in ['CG1', 'CG2']:
                        # Try multiple methods to write to CGX.COS.COS_OPREQ
                        # Method 1: Direct string addressing         
                        objects = client.get_objects_node()
                        target_node = objects.get_child(["1:CGX", "1:COS", "1:COS_OPREQ"])
                        target_node.set_value(value)
                    else:  # FPIS
                        # Try multiple methods to write to FTS_In.OPREQ
                        # Method 1: Direct string addressing
                        objects = client.get_objects_node()
                        target_node = objects.get_child(["1:STF_In", "1:OPREQ"])
                        target_node.set_value(value)
                    
                    results[server_name] = True
                    logger.info(f"Successfully wrote {value} to {server_name}")
                except Exception as e:
                    logger.error(f"Failed to write to {server_name}: {e}")
                    results[server_name] = False
            else:
                results[server_name] = False
        return results

    def write_iop_command(self, value):
        """Write IOP command to FPIS server only"""
        if not self.servers['FPIS']['connected']:
            logger.error("FPIS server not connected")
            return False
        
        try:
            client = self.servers['FPIS']['client']
            objects = client.get_objects_node()
            target_node = objects.get_child(["1:STF_In", "1:IOPULSE"])
            target_node.set_value(value)
            logger.info(f"Successfully wrote IOP command {value} to FPIS")
            return True
        except Exception as e:
            logger.error(f"Failed to write IOP command to FPIS: {e}")
            return False

    def read_iop_status(self):
        """Read IOP status for all systems from FPIS server"""
        if not self.servers['FPIS']['connected']:
            return None, None, None
        
        try:
            client = self.servers['FPIS']['client']
            objects = client.get_objects_node()
            
            # Read IOP status for each system
            cg1_iop = objects.get_child(["1:FTS_Out", "1:PSOS", "1:CG0IOP"]).get_value()
            cg2_iop = objects.get_child(["1:FTS_Out", "1:PSOS", "1:CG1IOP"]).get_value()
            fpis_iop = objects.get_child(["1:FTS_Out", "1:PSOS", "1:IOP"]).get_value()
            
            return cg1_iop, cg2_iop, fpis_iop
        except Exception as e:
            logger.error(f"Failed to read IOP status from FPIS: {e}")
            return None, None, None

    def read_server_status(self, server_name):
        """Read COS and PSOS status from a server"""
        if not self.servers[server_name]['connected']:
            return None, None
        
        try:
            client = self.servers[server_name]['client']
            cos_value = None
            psos_value = None
            
            if server_name in ['CG1', 'CG2']:
                # Try multiple approaches to find the correct path
                objects = client.get_objects_node()
                cos_opstate_node = objects.get_child(["1:CGX", "1:COS", "1:COS_OPSTATE"])
                cos_value = cos_opstate_node.get_value()
                psos_opstate_node = objects.get_child(["1:CGX", "1:COS", "1:PSOS_OPSTATE"])
                psos_value = psos_opstate_node.get_value()
                
            else:  # FPIS
                objects = client.get_objects_node()
                op_node = objects.get_child(["1:FTS_Out", "1:PSOS", "1:OPSTATE"])
                cos_value = op_node.get_value()
                
                # FPIS does not report PSOS_OPSTATE
                psos_value = None
            
            return cos_value, psos_value
        except Exception as e:
            logger.error(f"Failed to read status from {server_name}: {e}")
            return None, None

    def read_pcs_wd_threshold(self, server_name):
        """Read PCS WD Threshold setting from CG1 or CG2 server"""
        if server_name not in ['CG1', 'CG2'] or not self.servers[server_name]['connected']:
            return None
        
        try:
            client = self.servers[server_name]['client']
            objects = client.get_objects_node()
            
            # Browse path: ['HIOCOut', 'F2', 'STS', 'TH_VAL']
            threshold_node = objects.get_child(["1:HIOCOut", "1:F2", "1:STS", "1:TH_VAL"])
            threshold_value = threshold_node.get_value()
            
            return threshold_value
        except Exception as e:
            logger.error(f"Failed to read PCS WD threshold from {server_name}: {e}")
            return None


class OPCUAControlGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OPC-UA Server Control with IOP and HIOC")
        self.root.geometry("1200x800")
        
        self.controller = OPCUAController()
        self.hioc = HIOCProtocol(self.controller)
        self.monitoring = True  # Always monitoring
        self.monitor_thread = None
        
        self.create_widgets()
        self.update_connection_status()
        
        # Start monitoring immediately
        self.start_monitoring()

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Server connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Server Connections", padding="5")
        conn_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.connection_labels = {}
        self.connection_buttons = {}
        
        for i, server in enumerate(['CG1', 'CG2', 'FPIS']):
            ttk.Label(conn_frame, text=f"{server}:").grid(row=i, column=0, sticky=tk.W, padx=(0, 5))
            
            self.connection_labels[server] = ttk.Label(conn_frame, text="Disconnected", foreground="red")
            self.connection_labels[server].grid(row=i, column=1, sticky=tk.W, padx=(0, 10))
            
            self.connection_buttons[server] = ttk.Button(
                conn_frame, 
                text="Connect", 
                command=lambda s=server: self.toggle_connection(s)
            )
            self.connection_buttons[server].grid(row=i, column=2, padx=5)
            
            # URL entry
            url_var = tk.StringVar(value=self.controller.servers[server]['url'])
            url_entry = ttk.Entry(conn_frame, textvariable=url_var, width=30)
            url_entry.grid(row=i, column=3, padx=(10, 0))
            url_entry.bind('<FocusOut>', lambda e, s=server, v=url_var: self.update_server_url(s, v.get()))
        
        # Command buttons frame
        cmd_frame = ttk.LabelFrame(main_frame, text="COS Commands", padding="5")
        cmd_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N), pady=(0, 10))
        
        # Create command buttons
        row = 0
        col = 0
        for value, description in self.controller.commands.items():
            btn = ttk.Button(
                cmd_frame, 
                text=f"{description}\n({value})", 
                command=lambda v=value: self.send_command(v),
                width=15
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky=(tk.W, tk.E))
            col += 1
            if col > 2:  # 3 buttons per row
                col = 0
                row += 1
        
        # IOP Commands frame
        iop_frame = ttk.LabelFrame(main_frame, text="IOP Commands (FPIS Only)", padding="5")
        iop_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N), pady=(0, 10), padx=(10, 0))
        
        # Create IOP command buttons
        for i, (value, description) in enumerate(self.controller.iop_commands.items()):
            btn = ttk.Button(
                iop_frame,
                text=f"{description}\n({value})",
                command=lambda v=value: self.send_iop_command(v),
                width=15
            )
            btn.grid(row=0, column=i, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # HIOC Commands frame
        hioc_frame = ttk.LabelFrame(main_frame, text="HIOC Parameter Configuration", padding="5")
        hioc_frame.grid(row=1, column=2, sticky=(tk.W, tk.E, tk.N), pady=(0, 10), padx=(10, 0))
        
        # HIOC button
        ttk.Button(
            hioc_frame,
            text="Open HIOC\nConfiguration",
            command=self.open_hioc_dialog,
            width=15
        ).grid(row=0, column=0, padx=5, pady=5)
        
        # HIOC status
        self.hioc_status_label = ttk.Label(hioc_frame, text="Ready", foreground="green")
        self.hioc_status_label.grid(row=1, column=0, padx=5, pady=5)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Server Status", padding="5")
        status_frame.grid(row=1, column=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))
        
        # Status display
        self.status_labels = {}
        for i, server in enumerate(['CG1', 'CG2', 'FPIS']):
            # Server name
            ttk.Label(status_frame, text=f"{server}:", font=('TkDefaultFont', 10, 'bold')).grid(
                row=i*5, column=0, sticky=tk.W, pady=(10, 0)
            )
            
            # COS status
            ttk.Label(status_frame, text="COS:").grid(row=i*5+1, column=0, sticky=tk.W, padx=(10, 0))
            self.status_labels[f"{server}_COS"] = ttk.Label(
                status_frame, text="N/A", relief="sunken", width=20
            )
            self.status_labels[f"{server}_COS"].grid(row=i*5+1, column=1, sticky=(tk.W, tk.E), padx=5)
            
            # PSOS status (not for FPIS)
            if server != 'FPIS':
                ttk.Label(status_frame, text="PSOS:").grid(row=i*5+2, column=0, sticky=tk.W, padx=(10, 0))
                self.status_labels[f"{server}_PSOS"] = ttk.Label(
                    status_frame, text="N/A", relief="sunken", width=20
                )
                self.status_labels[f"{server}_PSOS"].grid(row=i*5+2, column=1, sticky=(tk.W, tk.E), padx=5)
            
            # IOP status
            ttk.Label(status_frame, text="IOP:").grid(row=i*5+3, column=0, sticky=tk.W, padx=(10, 0))
            self.status_labels[f"{server}_IOP"] = ttk.Label(
                status_frame, text="N/A", relief="sunken", width=20
            )
            self.status_labels[f"{server}_IOP"].grid(row=i*5+3, column=1, sticky=(tk.W, tk.E), padx=5)
            
            # PCS WD Threshold (only for CG1 and CG2)
            if server in ['CG1', 'CG2']:
                ttk.Label(status_frame, text="PCS WD:").grid(row=i*5+4, column=0, sticky=tk.W, padx=(10, 0))
                self.status_labels[f"{server}_PCS_WD"] = ttk.Label(
                    status_frame, text="N/A", relief="sunken", width=20
                )
                self.status_labels[f"{server}_PCS_WD"].grid(row=i*5+4, column=1, sticky=(tk.W, tk.E), padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(3, weight=1)
        status_frame.columnconfigure(1, weight=1)

    def update_server_url(self, server, url):
        """Update server URL"""
        self.controller.servers[server]['url'] = url

    def toggle_connection(self, server):
        """Toggle connection to a server"""
        if self.controller.servers[server]['connected']:
            self.controller.disconnect_server(server)
        else:
            self.controller.connect_server(server)
        self.update_connection_status()

    def update_connection_status(self):
        """Update connection status display"""
        for server in ['CG1', 'CG2', 'FPIS']:
            if self.controller.servers[server]['connected']:
                self.connection_labels[server].config(text="Connected", foreground="green")
                self.connection_buttons[server].config(text="Disconnect")
            else:
                self.connection_labels[server].config(text="Disconnected", foreground="red")
                self.connection_buttons[server].config(text="Connect")

    def send_command(self, value):
        """Send command to all servers"""
        description = self.controller.commands[value]
        result = messagebox.askyesno(
            "Confirm Command", 
            f"Send command '{description}' (value: {value}) to all connected servers?"
        )
        
        if result:
            results = self.controller.write_cos_opreq(value)
            success_servers = [server for server, success in results.items() if success]
            failed_servers = [server for server, success in results.items() if not success]
            
            message = f"Command '{description}' sent.\n"
            if success_servers:
                message += f"Success: {', '.join(success_servers)}\n"
            if failed_servers:
                message += f"Failed: {', '.join(failed_servers)}"
            
            messagebox.showinfo("Command Result", message)

    def send_iop_command(self, value):
        """Send IOP command to FPIS server"""
        description = self.controller.iop_commands[value]
        result = messagebox.askyesno(
            "Confirm IOP Command", 
            f"Send IOP command '{description}' (value: {value}) to FPIS server?"
        )
        
        if result:
            success = self.controller.write_iop_command(value)
            if success:
                message = f"IOP command '{description}' sent successfully to FPIS."
            else:
                message = f"Failed to send IOP command '{description}' to FPIS."
            
            messagebox.showinfo("IOP Command Result", message)

    def open_hioc_dialog(self):
        """Open HIOC configuration dialog"""
        dialog = HIOCDialog(self.root, self.hioc)
        dialog.show()

    def update_hioc_status(self):
        """Update HIOC status display"""
        if self.hioc.operation_in_progress:
            self.hioc_status_label.config(text="Operation in Progress", foreground="orange")
        else:
            self.hioc_status_label.config(text="Ready", foreground="green")

    def update_status_display(self, server, cos_value, psos_value):
        """Update status display for a server"""
        # Update COS status
        cos_label = self.status_labels[f"{server}_COS"]
        if cos_value is not None and cos_value in self.controller.cos_states:
            state_name, color = self.controller.cos_states[cos_value]
            cos_label.config(text=f"{state_name} ({cos_value})", background=color, foreground="white")
        else:
            cos_label.config(text="N/A", background="white", foreground="black")
        
        # Update PSOS status (if applicable)
        if server != 'FPIS' and f"{server}_PSOS" in self.status_labels:
            psos_label = self.status_labels[f"{server}_PSOS"]
            if psos_value is not None and psos_value in self.controller.psos_states:
                state_name = self.controller.psos_states[psos_value]
                psos_label.config(text=f"{state_name} ({psos_value})", background="lightgray")
            else:
                psos_label.config(text="N/A", background="white")

    def update_iop_display(self, server, iop_value):
        """Update IOP status display for a server"""
        iop_label = self.status_labels[f"{server}_IOP"]
        if iop_value is not None and iop_value in self.controller.iop_states:
            state_name, color = self.controller.iop_states[iop_value]
            iop_label.config(text=f"{state_name} ({iop_value})", background=color, foreground="white")
        else:
            iop_label.config(text="N/A", background="white", foreground="black")

    def update_pcs_wd_display(self, server, threshold_value):
        """Update PCS WD Threshold display for a server"""
        if server in ['CG1', 'CG2'] and f"{server}_PCS_WD" in self.status_labels:
            pcs_wd_label = self.status_labels[f"{server}_PCS_WD"]
            if threshold_value is not None:
                pcs_wd_label.config(text=f"{threshold_value}", background="lightblue")
            else:
                pcs_wd_label.config(text="N/A", background="white")

    def start_monitoring(self):
        """Start status monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_status, daemon=True)
        self.monitor_thread.start()

    def monitor_status(self):
        """Monitor status in background thread"""
        while self.monitoring:
            try:
                # Monitor COS and PSOS status
                for server in ['CG1', 'CG2', 'FPIS']:
                    if self.controller.servers[server]['connected']:
                        cos_value, psos_value = self.controller.read_server_status(server)
                        # Schedule GUI update in main thread
                        self.root.after(0, self.update_status_display, server, cos_value, psos_value)
                
                # Monitor PCS WD Threshold for CG1 and CG2
                for server in ['CG1', 'CG2']:
                    if self.controller.servers[server]['connected']:
                        threshold_value = self.controller.read_pcs_wd_threshold(server)
                        self.root.after(0, self.update_pcs_wd_display, server, threshold_value)
                
                # Monitor IOP status (from FPIS only)
                if self.controller.servers['FPIS']['connected']:
                    cg1_iop, cg2_iop, fpis_iop = self.controller.read_iop_status()
                    self.root.after(0, self.update_iop_display, 'CG1', cg1_iop)
                    self.root.after(0, self.update_iop_display, 'CG2', cg2_iop)
                    self.root.after(0, self.update_iop_display, 'FPIS', fpis_iop)
                
                # Update HIOC status
                self.root.after(0, self.update_hioc_status)
                
                time.sleep(0.3)  # Update every 300ms
            except Exception as e:
                logger.error(f"Error in monitoring thread: {e}")
                time.sleep(1)

    def on_closing(self):
        """Handle application closing"""
        self.monitoring = False
        
        # Abort any ongoing HIOC operation
        if self.hioc.operation_in_progress:
            self.hioc.send_abort(self.hioc.current_server, self.hioc.current_fid)
        
        for server in ['CG1', 'CG2', 'FPIS']:
            self.controller.disconnect_server(server)
        self.root.destroy()


def main():
    root = tk.Tk()
    app = OPCUAControlGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
