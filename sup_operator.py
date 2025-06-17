"""
SUP Protocol Implementation
Contains HIOCwSUPOperator (extends HIOCOperator) and SUPOperator for HIOCwSUP operations.
Clean implementation following the specified protocol flow.
"""

import time
import zlib
from typing import List, Optional, Dict, Any, Tuple, Callable
from enum import Enum
from opcua import ua, Client

# Import the base HIOCOperator
from hioc_operator import HIOCOperator, HIOCOperationConfig, HIOCStep, HIOCStepResult, HIOCOperationType
from hiocwsup_operator import HIOCwSUPStep, HIOCwSUPOperator

class SUPStep(Enum):
    """SUP protocol steps for HSUP interface operations"""
    NONCE_REQUEST = "nonce_request"
    NONCE_RESPONSE = "nonce_response"
    CRC32_CALCULATION = "crc32_calculation"
    CTFSS_POPULATE = "ctfss_populate"
    HSUP_STEP1_CHALLENGE = "hsup_step1_challenge"
    HSUP_STEP1_RESPONSE = "hsup_step1_response"
    HSUP_STEP2_CHALLENGE = "hsup_step2_challenge"
    HSUP_STEP2_RESPONSE = "hsup_step2_response"
    HSUP_STEP3_CHALLENGE = "hsup_step3_challenge"
    HSUP_STEP3_RESPONSE = "hsup_step3_response"

class SUPOperationConfig:
    """Configuration for SUP operation"""
    
    def __init__(self, client: Client, controller_id: int, fid: str, 
                 parameters: List[int], nonce: Optional[int] = None,
                 timeout_seconds: float = 10.0, 
                 progress_callback: Optional[Callable[[str], None]] = None):
        self.client = client
        self.controller_id = controller_id
        self.fid = fid
        self.parameters = parameters
        self.nonce = nonce
        self.timeout_seconds = timeout_seconds
        self.progress_callback = progress_callback


class SUPOperator:
    """
    Handles SUP protocol operations for HSUP interface.
    Independent sequence management from HIOC.
    """
    
    def __init__(self, config: SUPOperationConfig):
        self.config = config
        self.client = config.client
        self.operation_history: List[HIOCStepResult] = []
        self.abort_requested = False
        
        # Independent HSUP sequence management
        self.hsup_current_sequence = 1
        self.hsup_last_response_sequence = 0
        
        # Operation data
        self.nonce_value: Optional[int] = config.nonce
        self.crc32_value: Optional[int] = None

    def _report_progress(self, message: str):
        """Report progress to GUI callback"""
        if self.config.progress_callback:
            self.config.progress_callback(message)

    def _log_sup_step(self, step: SUPStep, success: bool, challenge_data=None, 
                      response_data=None, error_message=None, timeout=False):
        """Log SUP step"""
        result = HIOCStepResult(
            step=HIOCStep(step.value) if hasattr(HIOCStep, step.value) else HIOCStep.CONNECTING,
            success=success,
            timestamp=time.time(),
            challenge_data=challenge_data,
            response_data=response_data,
            error_message=error_message,
            timeout=timeout
        )
        self.operation_history.append(result)
        
        # Report progress
        if success:
            self._report_progress("✓ {}: Success".format(step.value))
        else:
            if timeout:
                self._report_progress("✗ {}: Timeout".format(step.value))
            else:
                self._report_progress("✗ {}: {}".format(step.value, error_message or 'Failed'))

    def _read_last_hsup_response_sequence(self) -> Optional[int]:
        """Read the current HSUP response sequence from the server"""
        try:
            objects = self.client.get_objects_node()
            seq_node = objects.get_child(["1:HSUPOut", "1:{}".format(self.config.fid), "1:FTC", "1:SEQ"])
            last_seq = seq_node.get_value()
            return last_seq
        except Exception:
            return self.hsup_last_response_sequence

    def _get_next_hsup_sequence(self) -> int:
        """Get next HSUP challenge sequence number (independent from HIOC)"""
        server_last_seq = self._read_last_hsup_response_sequence()
        
        if server_last_seq is not None:
            last_response = server_last_seq
        else:
            last_response = self.hsup_last_response_sequence
        
        if last_response == 0:
            next_challenge = 1
        elif last_response == 254:
            next_challenge = 1
        else:
            next_challenge = last_response + 1
            if next_challenge > 253:
                next_challenge = 1
        
        # Ensure challenge sequences are always odd
        if next_challenge % 2 == 0:
            next_challenge += 1
            if next_challenge > 253:
                next_challenge = 1
        
        return next_challenge

    def _update_hsup_sequence(self, response_seq: int):
        """Update HSUP sequence tracking"""
        self.hsup_last_response_sequence = response_seq
        self.hsup_current_sequence = self._get_next_hsup_sequence()

    def request_nonce(self) -> bool:
        """
        Request nonce for CRC32 calculation using HSUP interface.
        
        Flow:
        1. NONCE_REQUEST: FLG=11, MSG=FunctionID (via HSUPIn)
        2. NONCE_RESPONSE: Expected FLG=12, VALUE=nonce (via HSUPOut)
        """
        try:
            fid_num = int(self.config.fid[1:])
            function_id = 2460000 + fid_num  # FunctionID format
            
            seq = self._get_next_hsup_sequence()
            
            # Write to HSUPIn interface
            objects = self.client.get_objects_node()
            ctr_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:CTR"])
            flg_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:FLG"])
            msg_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:MSG"])
            value_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:VALUE"])
            seq_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:SEQ"])
            
            # Write challenge data (SEQ last)
            ctr_node.set_value(ua.Variant(self.config.controller_id, ua.VariantType.UInt32))
            flg_node.set_value(ua.Variant(11, ua.VariantType.UInt32))  # Nonce request flag
            msg_node.set_value(ua.Variant(function_id, ua.VariantType.UInt32))
            value_node.set_value(ua.Variant(0, ua.VariantType.UInt32))
            time.sleep(0.001)  # Ensure ordering
            seq_node.set_value(ua.Variant(seq, ua.VariantType.Int32))
            
            challenge_data = {
                'CTR': self.config.controller_id, 'FLG': 11, 'MSG': function_id, 'VALUE': 0, 'SEQ': seq
            }
            
            self._log_sup_step(SUPStep.NONCE_REQUEST, True, challenge_data=challenge_data)
            
            # Wait for nonce response
            success, response_data = self._wait_for_hsup_response(12, challenge_data)
            
            if success:
                self.nonce_value = response_data['VALUE']
                self._update_hsup_sequence(response_data['SEQ'])
                self._log_sup_step(SUPStep.NONCE_RESPONSE, True, response_data=response_data)
                self._report_progress("Received nonce: 0x{:08X}".format(self.nonce_value))
                return True
            else:
                self._log_sup_step(SUPStep.NONCE_RESPONSE, False,
                                 error_message="Nonce response timeout or abort", timeout=True)
                return False
                
        except Exception as e:
            self._log_sup_step(SUPStep.NONCE_REQUEST, False, error_message=str(e))
            return False

    def _wait_for_hsup_response(self, expected_flag: int, challenge_data: Dict[str, Any], 
                                timeout: float = None) -> Tuple[bool, Dict[str, Any]]:
        """Wait for HSUP response with validation"""
        if timeout is None:
            timeout = self.config.timeout_seconds
            
        start_time = time.time()
        challenge_seq = challenge_data['SEQ']
        expected_response_seq = challenge_seq + 1 if challenge_seq < 254 else 0
        
        while time.time() - start_time < timeout:
            if self.abort_requested:
                return False, {}
                
            try:
                # Read from HSUPOut interface
                objects = self.client.get_objects_node()
                ctr_node = objects.get_child(["1:HSUPOut", "1:{}".format(self.config.fid), "1:FTC", "1:CTR"])
                flg_node = objects.get_child(["1:HSUPOut", "1:{}".format(self.config.fid), "1:FTC", "1:FLG"])
                msg_node = objects.get_child(["1:HSUPOut", "1:{}".format(self.config.fid), "1:FTC", "1:MSG"])
                value_node = objects.get_child(["1:HSUPOut", "1:{}".format(self.config.fid), "1:FTC", "1:VALUE"])
                seq_node = objects.get_child(["1:HSUPOut", "1:{}".format(self.config.fid), "1:FTC", "1:SEQ"])
                
                response = {
                    'CTR': ctr_node.get_value(),
                    'FLG': flg_node.get_value(),
                    'MSG': msg_node.get_value(),
                    'VALUE': value_node.get_value(),
                    'SEQ': seq_node.get_value()
                }
                
                # Check for correct sequence
                if response['SEQ'] == expected_response_seq:
                    self._report_progress("HSUP Response: SEQ={}, FLG={}, MSG={}, VALUE={}".format(
                        response['SEQ'], response['FLG'], response['MSG'], response['VALUE']))
                    
                    # Check for abort
                    if response['FLG'] in [7, 8, 9, 10]:
                        self._report_progress("HSUP server aborted with FLG={}".format(response['FLG']))
                        return False, response
                    
                    # Check expected flag
                    if response['FLG'] == expected_flag:
                        return True, response
                    else:
                        self._report_progress("Unexpected HSUP flag: expected {}, got {}".format(
                            expected_flag, response['FLG']))
                        return False, response
                        
            except Exception:
                pass
                
            time.sleep(0.1)
        
        return False, {}  # Timeout

    def calculate_crc32(self) -> bool:
        """Calculate CRC32 for parameters + nonce"""
        try:
            if self.nonce_value is None:
                raise ValueError("Nonce value not available")
            
            # Create buffer: [parameters + nonce]
            buffer = self.config.parameters + [self.nonce_value]
            
            # Convert to little-endian bytes
            buffer_bytes = b''.join(val.to_bytes(4, byteorder='little') for val in buffer)
            
            # Calculate CRC32
            self.crc32_value = zlib.crc32(buffer_bytes) & 0xFFFFFFFF
            
            self._log_sup_step(SUPStep.CRC32_CALCULATION, True)
            self._report_progress("Calculated CRC32: 0x{:08X} over {} words".format(
                self.crc32_value, len(buffer)))
            
            return True
            
        except Exception as e:
            self._log_sup_step(SUPStep.CRC32_CALCULATION, False, error_message=str(e))
            return False

    def populate_ctfss_buffer(self) -> bool:
        """Populate CTFSS buffer with structured parameters and metadata"""
        try:
            self._report_progress("Populating CTFSS buffer with {} parameters...".format(
                len(self.config.parameters)))
        
            # Calculate required values
            fid_num = int(self.config.fid[1:])  # Extract FID number (0-5)
            function_id = 2460000 + fid_num     # FunctionID format: 246NNNN
            unlock_command_code = 50            # Unlock command code
            confirmation_id = 4000000 + fid_num * 100 + unlock_command_code  # ConfirmationID: 4NNNNCC
        
            # SIMPLE FIX: FIDSize = number of parameters + 1
            fidsize = len(self.config.parameters) + 1
        
            # Get objects node
            objects = self.client.get_objects_node()
        
            # Get CTFSS nodes using proper browse paths
            ctr_node = objects.get_child(["1:CTFSS", "1:CTR"])
            flg_node = objects.get_child(["1:CTFSS", "1:FLG"])
            msg_node = objects.get_child(["1:CTFSS", "1:MSG"])
            value_node = objects.get_child(["1:CTFSS", "1:VALUE"])
            dsize_node = objects.get_child(["1:CTFSS", "1:DSIZE"])
            data_node = objects.get_child(["1:CTFSS", "1:DATA"])
        
            # Set metadata fields with CORRECT values
            ctr_node.set_value(ua.Variant(self.config.controller_id, ua.VariantType.UInt32))
            flg_node.set_value(ua.Variant(1, ua.VariantType.UInt32))  # Standard flag for CTFSS
            msg_node.set_value(ua.Variant(function_id, ua.VariantType.UInt32))  # FIXED: FunctionID
            value_node.set_value(ua.Variant(confirmation_id, ua.VariantType.UInt32))  # FIXED: ConfirmationID  
            dsize_node.set_value(ua.Variant(fidsize, ua.VariantType.UInt32))  # FIXED: parameters + 1
        
            # Create 512-element array with parameters + zeros
            data_array = self.config.parameters + [0] * (512 - len(self.config.parameters))
            current_data_value = data_node.get_data_value()
            # Obtain the exact variant type here because the data_node is an opcua array.
            data_variant_type = current_data_value.Value.VariantType
            data_node.set_value(ua.Variant(data_array, data_variant_type))
        
            self._log_sup_step(SUPStep.CTFSS_POPULATE, True)
            self._report_progress("✓ CTFSS buffer populated successfully")
            self._report_progress("  DSIZE (FIDSize): {}".format(fidsize))
            self._report_progress("  MSG (FunctionID): 0x{:X}".format(function_id))
            self._report_progress("  VALUE (ConfirmationID): 0x{:X}".format(confirmation_id))
            self._report_progress("  DATA: {} parameters + {} zeros".format(
                len(self.config.parameters), 512 - len(self.config.parameters)))
        
            return True
        
        except Exception as e:
            self._log_sup_step(SUPStep.CTFSS_POPULATE, False, error_message=str(e))
            return False

    def perform_hsup_sequence(self) -> bool:
        """
        Perform HSUP 3-step sequence.
        
        Flow:
        1. HSUP_STEP1: FLG=1, MSG=FunctionID
        2. HSUP_STEP2: FLG=3, MSG=CommandID
        3. HSUP_STEP3: FLG=5, MSG=ConfirmationID
        """
        try:
            self._report_progress("Starting HSUP 3-step sequence...")
            
            fid_num = int(self.config.fid[1:])
            
            # Step 1: Function validation
            if not self._perform_hsup_step(1, 2, 2460000 + fid_num):  # FunctionID
                return False
            
            if self.abort_requested:
                return False
            
            # Step 2: Command
            if not self._perform_hsup_step(2, 4, 3460050):  # CommandID with CC=50
                return False
            
            if self.abort_requested:
                return False
            
            # Step 3: Confirmation
            confirmation_id = 4000000 + fid_num * 100 + 50  # ConfirmationID with CC=50
            if not self._perform_hsup_step(3, 6, confirmation_id):
                return False
            
            self._report_progress("✓ HSUP sequence completed successfully")
            return True
            
        except Exception as e:
            self._report_progress("✗ HSUP sequence failed: {}".format(e))
            return False

    def _perform_hsup_step(self, step_num: int, expected_flag: int, msg_id: int) -> bool:
        """Perform a single HSUP step"""
        try:
            step_mapping = {
                1: (SUPStep.HSUP_STEP1_CHALLENGE, SUPStep.HSUP_STEP1_RESPONSE),
                2: (SUPStep.HSUP_STEP2_CHALLENGE, SUPStep.HSUP_STEP2_RESPONSE),
                3: (SUPStep.HSUP_STEP3_CHALLENGE, SUPStep.HSUP_STEP3_RESPONSE)
            }
            
            challenge_step, response_step = step_mapping[step_num]
            
            flag_mapping = {1: 1, 2: 3, 3: 5}  # Step to flag mapping
            flag = flag_mapping[step_num]
            
            # FIXED: Calculate ConfirmationID for VALUE field
            fid_num = int(self.config.fid[1:])
            unlock_command_code = 50  # Unlock command code
            confirmation_id = 4000000 + fid_num * 100 + unlock_command_code  # ConfirmationID: 4NNNNCC
            
            seq = self._get_next_hsup_sequence()
            
            # Write to HSUPIn interface
            objects = self.client.get_objects_node()
            ctr_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:CTR"])
            flg_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:FLG"])
            msg_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:MSG"])
            value_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:VALUE"])
            seq_node = objects.get_child(["1:HSUPIn", "1:{}".format(self.config.fid), "1:CTF", "1:SEQ"])
            
            # Write challenge data (SEQ last)
            ctr_node.set_value(ua.Variant(self.config.controller_id, ua.VariantType.UInt32))
            flg_node.set_value(ua.Variant(flag, ua.VariantType.UInt32))
            msg_node.set_value(ua.Variant(msg_id, ua.VariantType.UInt32))
            value_node.set_value(ua.Variant(confirmation_id, ua.VariantType.UInt32))  # FIXED: ConfirmationID
            time.sleep(0.001)
            seq_node.set_value(ua.Variant(seq, ua.VariantType.Int32))
            
            challenge_data = {
                'CTR': self.config.controller_id, 'FLG': flag, 'MSG': msg_id, 
                'VALUE': confirmation_id, 'SEQ': seq  # FIXED: ConfirmationID in log
            }
            
            self._log_sup_step(challenge_step, True, challenge_data=challenge_data)
            
            # Wait for response
            success, response_data = self._wait_for_hsup_response(expected_flag, challenge_data)
            
            if success:
                self._update_hsup_sequence(response_data['SEQ'])
                
                # Check for success/abort in final step
                if step_num == 3:
                    if response_data['MSG'] == 7500000:  # SuccessID
                        self._log_sup_step(response_step, True, response_data=response_data)
                        return True
                    else:
                        abort_msg = {
                            9000000: "Controller abort",
                            9100000: "User abort", 
                            9300000: "Timeout abort"
                        }.get(response_data['MSG'], "Unknown abort: {}".format(response_data['MSG']))
                        
                        self._log_sup_step(response_step, False, response_data=response_data, 
                                         error_message=abort_msg)
                        return False
                else:
                    self._log_sup_step(response_step, True, response_data=response_data)
                    return True
            else:
                self._log_sup_step(response_step, False, 
                                 error_message="HSUP response timeout or abort", timeout=True)
                return False
                
        except Exception as e:
            self._log_sup_step(challenge_step, False, error_message=str(e))
            return False

    def execute_operation(self) -> bool:
        """
        Execute SUP operation (CTFSS populate + HSUP sequence).
        Note: Nonce request and CRC32 calculation should be done before this.
        """
        try:
            self.abort_requested = False
            
            # Step 1: Populate CTFSS buffer
            if not self.populate_ctfss_buffer():
                return False
            
            if self.abort_requested:
                return False
            
            # Step 2: Perform HSUP sequence
            if not self.perform_hsup_sequence():
                return False
            
            self._report_progress("✓ SUP operation completed successfully")
            return True
            
        except Exception as e:
            self._report_progress("✗ SUP operation failed: {}".format(e))
            return False

    def get_abort_analysis(self) -> str:
        """Get analysis of steps leading to abort"""
        if not self.operation_history:
            return "No SUP operation history available for abort analysis"
        
        analysis_lines = []
        analysis_lines.append("SUP ABORT ANALYSIS")
        analysis_lines.append("=" * 40)
        
        # Find failure point
        for i, step in enumerate(self.operation_history):
            timestamp = time.strftime('%H:%M:%S', time.localtime(step.timestamp))
            status = "✓" if step.success else "✗ FAILED"
            analysis_lines.append("{}. [{}] {} - {}".format(i+1, timestamp, status, step.step.value))
            
            if not step.success:
                if step.error_message:
                    analysis_lines.append("   Error: {}".format(step.error_message))
                if step.timeout:
                    analysis_lines.append("   Timeout after {}s".format(self.config.timeout_seconds))
                break
        
        return "\n".join(analysis_lines)

    def get_operation_trace(self) -> str:
        """Get detailed trace of all SUP operation steps"""
        if not self.operation_history:
            return "No SUP operation history available"
        
        trace_lines = []
        trace_lines.append("SUP Operation Trace")
        trace_lines.append("FID: {}".format(self.config.fid))
        trace_lines.append("Parameters: {} values".format(len(self.config.parameters)))
        if self.nonce_value:
            trace_lines.append("Nonce: 0x{:08X}".format(self.nonce_value))
        if self.crc32_value:
            trace_lines.append("CRC32: 0x{:08X}".format(self.crc32_value))
        trace_lines.append("-" * 50)
        
        for i, step in enumerate(self.operation_history, 1):
            timestamp = time.strftime('%H:%M:%S', time.localtime(step.timestamp))
            status = "✓" if step.success else "✗"
            
            trace_lines.append("{:2d}. [{}] {} {}".format(i, timestamp, status, step.step.value))
            
            if step.challenge_data:
                trace_lines.append("    Challenge: {}".format(step.challenge_data))
            
            if step.response_data:
                trace_lines.append("    Response:  {}".format(step.response_data))
            
            if step.error_message:
                trace_lines.append("    Error:     {}".format(step.error_message))
        
        return "\n".join(trace_lines)


# Example usage for integration with hioc_module.py
def create_example_hiocwsup_flow():
    """
    Example of complete HIOCwSUP flow as it would be used in hioc_module.py
    """
    
    def progress_callback(message: str):
        print("Progress: {}".format(message))
    
    # Mock client for example
    from opcua import Client
    client = Client("opc.tcp://localhost:4840")
    # client.connect()  # Connection managed by main_gui
    
    # Example parameters (parsed from CSV by hioc_module.py)
    parameters = [0x64, 0xC8, 0x12C, 0x190, 0x1F4, 0x258, 0x2BC, 0x320, 0x384, 0x3E8]
    
    try:
        # Step 1: Request nonce using SUPOperator
        sup_config_nonce = SUPOperationConfig(
            client=client,
            controller_id=1464099,  # CG1
            fid="F3",
            parameters=parameters,
            progress_callback=progress_callback
        )
        
        sup_operator_nonce = SUPOperator(sup_config_nonce)
        nonce_success = sup_operator_nonce.request_nonce()
        
        if not nonce_success:
            print("Nonce request failed")
            return False
        
        # Step 2: Calculate CRC32
        crc32_success = sup_operator_nonce.calculate_crc32()
        if not crc32_success:
            print("CRC32 calculation failed")
            return False
        
        crc32_value = sup_operator_nonce.crc32_value
        
        # Step 3: HIOC unlock using HIOCwSUPOperator
        hioc_config = HIOCOperationConfig(
            client=client,
            controller_id=1464099,
            fid="F3",
            operation_type=HIOCOperationType.THRESHOLD,  # Placeholder
            threshold_command_code=50,  # Unlock command
            threshold_value=crc32_value,
            progress_callback=progress_callback
        )
        
        hiocwsup_operator = HIOCwSUPOperator(hioc_config)
        unlock_success = hiocwsup_operator.perform_unlock_sequence(crc32_value)
        
        if not unlock_success:
            print("HIOC unlock failed")
            print(hiocwsup_operator.get_abort_analysis())
            return False
        
        # Step 4: SUP operation (CTFSS + HSUP)
        sup_config_final = SUPOperationConfig(
            client=client,
            controller_id=1464099,
            fid="F3",
            parameters=parameters,
            nonce=sup_operator_nonce.nonce_value,
            progress_callback=progress_callback
        )
        
        sup_operator_final = SUPOperator(sup_config_final)
        sup_success = sup_operator_final.execute_operation()
        
        if sup_success:
            print("✓ Complete HIOCwSUP operation successful")
            return True
        else:
            print("✗ SUP operation failed")
            print(sup_operator_final.get_abort_analysis())
            return False
            
    except Exception as e:
        print("Error in HIOCwSUP flow: {}".format(e))
        return False


# Integration notes for hioc_module.py:
#
# 1. Import both classes:
#    from sup_operator import HIOCwSUPOperator, SUPOperator, SUPOperationConfig
#
# 2. For HIOCwSUP operations, the flow should be:
#    a) Create SUPOperator to request nonce and calculate CRC32
#    b) Create HIOCwSUPOperator to perform HIOC unlock
#    c) Create SUPOperator to perform CTFSS populate + HSUP sequence
#
# 3. The existing HIOC functionality in hioc_module.py remains unchanged
#
# 4. Parameters are parsed by hioc_module.py and passed to SUPOperator
#
# 5. Progress reporting goes to the same HIOC dialog text box
