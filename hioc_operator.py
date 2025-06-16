"""
HIOC Protocol Operator Class
Handles HIOC_BO and HIOC_TH operations for a single FID on one server
with comprehensive progress reporting and abort tracing.
Fixed sequence management to properly read last response and handle overflow.
All progress reporting through _log_step and _report_progress methods.
"""

import time
import threading
from enum import Enum
from typing import Callable, Optional, List, Dict, Any, Tuple
from opcua import Client, ua


class HIOCOperationType(Enum):
    """Types of HIOC operations for HIOC_BO and HIOC_TH"""
    THRESHOLD = "threshold"          # HIOC_TH
    OVERRIDE_SET = "override_set"    # HIOC_BO
    OVERRIDE_UNSET = "override_unset"  # HIOC_BO
    DISABLE = "disable"              # HIOC_BO
    ENABLE = "enable"                # HIOC_BO
    STRUCTURED_PARAMS = "structured_params"  # HIOCwSUP


class HIOCStep(Enum):
    """HIOC protocol steps"""
    HTT_REQUEST = "htt_request"      # Auxiliary step for thresholds
    HTT_RESPONSE = "htt_response"    # Auxiliary step for thresholds
    STEP1_CHALLENGE = "step1_challenge"
    STEP1_RESPONSE = "step1_response"
    STEP2_CHALLENGE = "step2_challenge"
    STEP2_RESPONSE = "step2_response"
    STEP3_CHALLENGE = "step3_challenge"
    STEP3_RESPONSE = "step3_response"
    COMPLETED = "completed"
    ABORTED = "aborted"
    CONNECTING = "connecting"  # Added for compatibility


class HIOCStepResult:
    """Result of a single HIOC step"""
    def __init__(self, step: HIOCStep, success: bool, timestamp: float, 
                 challenge_data: Optional[Dict[str, Any]] = None, 
                 response_data: Optional[Dict[str, Any]] = None, 
                 error_message: Optional[str] = None, timeout: bool = False):
        self.step = step
        self.success = success
        self.timestamp = timestamp
        self.challenge_data = challenge_data
        self.response_data = response_data
        self.error_message = error_message
        self.timeout = timeout


class HIOCOperationConfig:
    """Configuration for HIOC operation"""
    def __init__(self, client: Client, controller_id: int, fid: str, 
                 operation_type: HIOCOperationType, threshold_command_code: Optional[int] = None,
                 threshold_value: Optional[int] = None, timeout_seconds: float = 10.0, 
                 progress_callback: Optional[Callable[[str], None]] = None):
        self.client = client
        self.controller_id = controller_id
        self.fid = fid  # F0-F5
        self.operation_type = operation_type
        self.threshold_command_code = threshold_command_code  # CC (1-15) for threshold operations
        self.threshold_value = threshold_value  # Actual threshold value from HTT for threshold operations
        self.timeout_seconds = timeout_seconds
        self.progress_callback = progress_callback


class HIOCOperator:
    """
    Handles HIOC_BO and HIOC_TH protocol operations for a single FID on one server.
    Provides comprehensive progress reporting and abort tracing.
    """
    
    def __init__(self, config: HIOCOperationConfig):
        self.config = config
        self.client = config.client  # Use provided client directly
        self.operation_history: List[HIOCStepResult] = []
        self.current_sequence = 1
        self.last_response_sequence = 0
        self.operation_thread: Optional[threading.Thread] = None
        self.abort_requested = False
        
        # Validate configuration
        self._validate_config()
        
        # Command codes mapping
        self.command_codes = {
            HIOCOperationType.THRESHOLD: lambda th: th,  # 1-15
            HIOCOperationType.OVERRIDE_SET: 20,
            HIOCOperationType.OVERRIDE_UNSET: 25,
            HIOCOperationType.DISABLE: 30,
            HIOCOperationType.ENABLE: 35,
        }
        
        # Flag values mapping
        self.flag_values = {
            'function_validation': {
                HIOCOperationType.THRESHOLD: 1,
                HIOCOperationType.OVERRIDE_SET: 1,
                HIOCOperationType.DISABLE: 1,
                HIOCOperationType.OVERRIDE_UNSET: 11,
                HIOCOperationType.ENABLE: 11,
            },
            'command': {
                HIOCOperationType.THRESHOLD: 3,
                HIOCOperationType.OVERRIDE_SET: 3,
                HIOCOperationType.DISABLE: 3,
                HIOCOperationType.OVERRIDE_UNSET: 13,
                HIOCOperationType.ENABLE: 13,
            },
            'confirmation': {
                HIOCOperationType.THRESHOLD: 5,
                HIOCOperationType.OVERRIDE_SET: 5,
                HIOCOperationType.DISABLE: 5,
                HIOCOperationType.OVERRIDE_UNSET: 15,
                HIOCOperationType.ENABLE: 15,
            }
        }

    def _validate_config(self):
        """Validate the operation configuration"""
        if not self.config.client:
            raise ValueError("Connected client is required")
            
        if self.config.operation_type == HIOCOperationType.THRESHOLD:
            if (not self.config.threshold_command_code or 
                not (1 <= self.config.threshold_command_code <= 15)):
                raise ValueError("Threshold operations require threshold_command_code between 1-15")
            if self.config.threshold_value is None:
                raise ValueError("Threshold operations require threshold_value")
        
        # Generate valid FID list F0-F31 for generic support
        valid_fids = ['F{}'.format(i) for i in range(32)]
        if not self.config.fid or self.config.fid not in valid_fids:
            raise ValueError("FID must be one of F0-F31")

    def _report_progress(self, message: str):
        """Report progress to GUI callback"""
        if self.config.progress_callback:
            self.config.progress_callback(message)

    def _log_step(self, step: HIOCStep, success: bool, challenge_data=None, 
                  response_data=None, error_message=None, timeout=False):
        """Log a step result to operation history"""
        result = HIOCStepResult(
            step=step,
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

    def _read_last_response_sequence(self) -> Optional[int]:
        """Read the current response sequence from the server to ensure proper sequence management"""
        try:
            objects = self.client.get_objects_node()
            seq_node = objects.get_child(["1:HIOCOut", "1:{}".format(self.config.fid), "1:FTS", "1:SEQ"])
            last_seq = seq_node.get_value()
            return last_seq
        except Exception as e:
            # If we can't read the sequence, fall back to internal tracking
            return self.last_response_sequence

    def _get_next_sequence(self) -> int:
        """
        Get next challenge sequence number (always odd).
        Properly reads last response sequence and handles overflow correctly.
        Challenge sequences: 1, 3, 5, ..., 251, 253, then back to 1
        Response sequences: 0, 2, 4, ..., 252, 254, then back to 0
        """
        # First try to read the actual last response sequence from server
        server_last_seq = self._read_last_response_sequence()
        
        # Use server sequence if available, otherwise fall back to internal tracking
        if server_last_seq is not None:
            last_response = server_last_seq
        else:
            last_response = self.last_response_sequence
        
        # Calculate next challenge sequence
        if last_response == 0:
            # First operation or after response sequence 254→0 overflow
            next_challenge = 1
        elif last_response == 254:
            # Response sequence overflow: 254 → next challenge is 1
            next_challenge = 1
        else:
            # Normal case: last_response + 1
            next_challenge = last_response + 1
            # Handle challenge sequence overflow: 253 → 1
            if next_challenge > 253:
                next_challenge = 1
        
        # Ensure challenge sequences are always odd
        if next_challenge % 2 == 0:
            next_challenge += 1
            if next_challenge > 253:
                next_challenge = 1
        
        return next_challenge

    def _update_sequence(self, response_seq: int):
        """Update sequence tracking based on response"""
        self.last_response_sequence = response_seq
        self.current_sequence = self._get_next_sequence()

    def _write_challenge_data(self, ctr: int, flg: int, msg: int, value: int, seq: int):
        """Write challenge data to HIOCIn nodes with guaranteed SEQ field written last"""
        try:
            # Get objects node
            objects = self.client.get_objects_node()
            
            # Get nodes using proper browse paths
            ctr_node = objects.get_child(["1:HIOCIn", "1:{}".format(self.config.fid), "1:STF", "1:CTR"])
            flg_node = objects.get_child(["1:HIOCIn", "1:{}".format(self.config.fid), "1:STF", "1:FLG"])
            msg_node = objects.get_child(["1:HIOCIn", "1:{}".format(self.config.fid), "1:STF", "1:MSG"])
            value_node = objects.get_child(["1:HIOCIn", "1:{}".format(self.config.fid), "1:STF", "1:VALUE"])
            seq_node = objects.get_child(["1:HIOCIn", "1:{}".format(self.config.fid), "1:STF", "1:SEQ"])
            
            # Write all fields EXCEPT SEQ first (guaranteed ordering)
            ctr_node.set_value(ua.Variant(int(ctr) & 0xFFFFFFFF, ua.VariantType.UInt32))
            flg_node.set_value(ua.Variant(int(flg) & 0xFFFFFFFF, ua.VariantType.UInt32))
            msg_node.set_value(ua.Variant(int(msg) & 0xFFFFFFFF, ua.VariantType.UInt32))
            value_node.set_value(ua.Variant(int(value) & 0xFFFFFFFF, ua.VariantType.UInt32))
            
            # Ensure all previous writes are complete before writing SEQ
            # SEQ acts as the "commit" signal for the challenge
            time.sleep(0.001)  # Small delay to ensure write ordering
            seq_node.set_value(ua.Variant(int(seq), ua.VariantType.Int32))
            
            challenge_data = {
                'CTR': ctr, 'FLG': flg, 'MSG': msg, 'VALUE': value, 'SEQ': seq
            }
            
            # Log the challenge that was sent
            self._report_progress("Challenge sent: CTR={}, FLG={}, MSG={}, VALUE={}, SEQ={}".format(
                ctr, flg, msg, value, seq))
            
            return challenge_data
            
        except Exception as e:
            raise Exception("Failed to write challenge data: {}".format(e))

    def _read_response_data(self) -> Dict[str, Any]:
        """Read response data from HIOCOut nodes"""
        try:
            # Get objects node
            objects = self.client.get_objects_node()
            
            # Get nodes and read values using proper browse paths
            ctr_node = objects.get_child(["1:HIOCOut", "1:{}".format(self.config.fid), "1:FTS", "1:CTR"])
            flg_node = objects.get_child(["1:HIOCOut", "1:{}".format(self.config.fid), "1:FTS", "1:FLG"])
            msg_node = objects.get_child(["1:HIOCOut", "1:{}".format(self.config.fid), "1:FTS", "1:MSG"])
            value_node = objects.get_child(["1:HIOCOut", "1:{}".format(self.config.fid), "1:FTS", "1:VALUE"])
            seq_node = objects.get_child(["1:HIOCOut", "1:{}".format(self.config.fid), "1:FTS", "1:SEQ"])
            
            return {
                'CTR': ctr_node.get_value(),
                'FLG': flg_node.get_value(),
                'MSG': msg_node.get_value(),
                'VALUE': value_node.get_value(),
                'SEQ': seq_node.get_value()
            }
            
        except Exception as e:
            raise Exception("Failed to read response data: {}".format(e))

    def _wait_for_response(self, expected_flag: int, challenge_data: Dict[str, Any], timeout: float = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Wait for response with correct SEQ, then validate according to HIOC specification.
        Returns success/failure based on proper response validation.
        """
        if timeout is None:
            timeout = self.config.timeout_seconds
            
        start_time = time.time()
        challenge_seq = challenge_data['SEQ']
        expected_response_seq = challenge_seq + 1 if challenge_seq < 254 else 0  # SEQ overflow handling
        
        while time.time() - start_time < timeout:
            if self.abort_requested:
                return False, {}
                
            try:
                response = self._read_response_data()
                
                # Wait for the response to OUR challenge (correct SEQ)
                if response['SEQ'] == expected_response_seq:
                    # Found our response - now validate it
                    
                    # Log the actual response received
                    self._report_progress("Response received: SEQ={}, FLG={}, CTR={}, MSG={}, VALUE={}".format(
                        response['SEQ'], response['FLG'], response['CTR'], response['MSG'], response['VALUE']))
                    
                    # Check for abort responses (FLG in [7,8,9,10])
                    if response['FLG'] in [7, 8, 9, 10]:
                        self._report_progress("Server aborted operation with FLG={}".format(response['FLG']))
                        return False, response
                    
                    # Check if we got the expected response flag
                    if response['FLG'] != expected_flag:
                        self._report_progress("Unexpected response flag: expected {}, got {}".format(
                            expected_flag, response['FLG']))
                        return False, response
                    
                    # Validate Controller ID - response should have correct CTR for this system
                    if response['CTR'] != challenge_data['CTR']:
                        self._report_progress("Controller ID mismatch: challenge used {}, response from {}".format(
                            challenge_data['CTR'], response['CTR']))
                        return False, response
                    
                    # Validate Message ID - should echo challenge MSG unless abort/success
                    if response['MSG'] != challenge_data['MSG']:
                        # Check if this is an abort or success message
                        if response['MSG'] in [9000000, 9100000, 9300000, 7500000]:
                            self._report_progress("Operation result: MSG={}".format(response['MSG']))
                        else:
                            self._report_progress("Message ID mismatch: expected {}, got {}".format(
                                challenge_data['MSG'], response['MSG']))
                            return False, response
                    
                    # Validate VALUE for Step 2 threshold operations
                    if (self.config.operation_type == HIOCOperationType.THRESHOLD and 
                        expected_flag == 4 and  # Step 2 response flag
                        response['VALUE'] != challenge_data['VALUE']):
                        self._report_progress("Value mismatch in step 2: expected {}, got {}".format(
                            challenge_data['VALUE'], response['VALUE']))
                        return False, response
                    
                    # All validations passed
                    self._report_progress("Valid response: all validations passed")
                    return True, response
                    
            except Exception as e:
                self._log_step(HIOCStep.CONNECTING, False, error_message="Error reading response: {}".format(e))
                pass
                
            time.sleep(0.1)  # 100ms polling
        
        # Timeout occurred
        self._report_progress("Timeout waiting for response to challenge SEQ={}".format(challenge_seq))
        return False, {}  # Timeout

    def _perform_htt_request(self) -> bool:
        """Perform HTT (threshold table) request - auxiliary step for HIOC_TH"""
        try:
            fid_num = int(self.config.fid[1:])  # Extract number from F0-F5
            function_id = 2460000 + fid_num
            
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=21,  # HTT request flag
                msg=function_id,
                value=0,
                seq=seq
            )
            
            self._log_step(HIOCStep.HTT_REQUEST, True, challenge_data=challenge_data)
            
            # Wait for HTT response (flag 22) with proper validation
            success, response_data = self._wait_for_response(22, challenge_data)
            
            if success:
                self._update_sequence(response_data['SEQ'])
                self._log_step(HIOCStep.HTT_RESPONSE, True, response_data=response_data)
                self._report_progress("HTT table populated - threshold values available")
                return True
            else:
                self._log_step(HIOCStep.HTT_RESPONSE, False, 
                             error_message="HTT response timeout or abort",
                             timeout=True)
                return False
                
        except Exception as e:
            self._log_step(HIOCStep.HTT_REQUEST, False, error_message=str(e))
            return False

    def _perform_hioc_step(self, step_num: int, expected_response_flag: int) -> bool:
        """Perform a single HIOC protocol step"""
        try:
            step_mapping = {
                1: (HIOCStep.STEP1_CHALLENGE, HIOCStep.STEP1_RESPONSE),
                2: (HIOCStep.STEP2_CHALLENGE, HIOCStep.STEP2_RESPONSE),
                3: (HIOCStep.STEP3_CHALLENGE, HIOCStep.STEP3_RESPONSE)
            }
            
            challenge_step, response_step = step_mapping[step_num]
            
            # Determine message ID and flag based on step and operation type
            fid_num = int(self.config.fid[1:])
            
            if step_num == 1:
                # Function validation
                msg_id = 2460000 + fid_num  # FunctionID format
                flag = self.flag_values['function_validation'][self.config.operation_type]
                # For threshold operations, VALUE should contain the selected threshold value
                if self.config.operation_type == HIOCOperationType.THRESHOLD:
                    value = self.config.threshold_value  # Actual threshold value from HTT
                else:
                    value = 0
            elif step_num == 2:
                # Command step
                if self.config.operation_type == HIOCOperationType.THRESHOLD:
                    command_code = self.config.threshold_command_code  # CC (1-15) selected by user
                    value = self.config.threshold_value  # Actual threshold value from HTT
                else:
                    command_code = self.command_codes[self.config.operation_type]
                    value = 0
                    
                msg_id = 3460000 + command_code  # CommandID format: 3460000 + CC
                flag = self.flag_values['command'][self.config.operation_type]
            else:  # step_num == 3
                # Confirmation step
                if self.config.operation_type == HIOCOperationType.THRESHOLD:
                    command_code = self.config.threshold_command_code  # CC (1-15) selected by user
                    value = self.config.threshold_value  # Actual threshold value from HTT
                else:
                    command_code = self.command_codes[self.config.operation_type]
                    value = 0
                    
                msg_id = 4000000 + fid_num * 100 + command_code  # ConfirmationID format: 4000000 + FID*100 + CC
                flag = self.flag_values['confirmation'][self.config.operation_type]
            
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=flag,
                msg=msg_id,
                value=value,
                seq=seq
            )
            
            self._log_step(challenge_step, True, challenge_data=challenge_data)
            
            # Wait for response with proper validation
            success, response_data = self._wait_for_response(expected_response_flag, challenge_data)
            
            if success:
                self._update_sequence(response_data['SEQ'])
                
                # Check for success/abort in final step
                if step_num == 3:
                    if response_data['MSG'] == 7500000:  # Success
                        self._log_step(response_step, True, response_data=response_data)
                        return True
                    else:  # Abort codes
                        abort_msg = {
                            9000000: "Controller abort",
                            9100000: "User abort", 
                            9300000: "Timeout abort"
                        }.get(response_data['MSG'], "Unknown abort: {}".format(response_data['MSG']))
                        
                        self._log_step(response_step, False, response_data=response_data, 
                                     error_message=abort_msg)
                        return False
                else:
                    self._log_step(response_step, True, response_data=response_data)
                    return True
            else:
                self._log_step(response_step, False, 
                             error_message="Response timeout or abort",
                             timeout=True)
                return False
                
        except Exception as e:
            self._log_step(challenge_step, False, error_message=str(e))
            return False

    def execute_operation(self) -> bool:
        """Execute the complete HIOC operation"""
        try:
            self.abort_requested = False
            self.operation_history.clear()
            
            # Client already provided and validated - no connection step needed
            
            # Auxiliary Step: HTT request for threshold operations
            if self.config.operation_type == HIOCOperationType.THRESHOLD:
                if not self._perform_htt_request():
                    return False
            
            # Step 1: Function validation
            expected_flag_1 = 12 if self.config.operation_type in [
                HIOCOperationType.OVERRIDE_UNSET, HIOCOperationType.ENABLE
            ] else 2
            
            if not self._perform_hioc_step(1, expected_flag_1):
                return False
            
            if self.abort_requested:
                self._log_step(HIOCStep.ABORTED, True, error_message="User abort requested")
                return False
            
            # Step 2: Command
            expected_flag_2 = 14 if self.config.operation_type in [
                HIOCOperationType.OVERRIDE_UNSET, HIOCOperationType.ENABLE
            ] else 4
            
            if not self._perform_hioc_step(2, expected_flag_2):
                return False
            
            if self.abort_requested:
                self._log_step(HIOCStep.ABORTED, True, error_message="User abort requested")
                return False
            
            # Step 3: Confirmation
            expected_flag_3 = 16 if self.config.operation_type in [
                HIOCOperationType.OVERRIDE_UNSET, HIOCOperationType.ENABLE
            ] else 6
            
            if not self._perform_hioc_step(3, expected_flag_3):
                return False
            
            # Operation completed successfully
            self._log_step(HIOCStep.COMPLETED, True)
            self._report_progress("✓ HIOC operation completed successfully")
            return True
            
        except Exception as e:
            self._log_step(HIOCStep.ABORTED, False, error_message=str(e))
            self._report_progress("✗ Operation failed: {}".format(e))
            return False

    def execute_operation_async(self, completion_callback: Optional[Callable[[bool], None]] = None):
        """Execute operation in background thread"""
        def operation_thread():
            success = self.execute_operation()
            if completion_callback:
                completion_callback(success)
        
        self.operation_thread = threading.Thread(target=operation_thread, daemon=True)
        self.operation_thread.start()

    def abort_operation(self):
        """Request operation abort"""
        self.abort_requested = True
        self._report_progress("Abort requested - stopping operation...")

    def get_operation_trace(self) -> str:
        """Get detailed trace of all operation steps for debugging/audit"""
        if not self.operation_history:
            return "No operation history available"
        
        trace_lines = []
        trace_lines.append("HIOC Operation Trace - {}".format(self.config.operation_type.value))
        trace_lines.append("Controller: {}".format(self.config.controller_id))
        trace_lines.append("FID: {}".format(self.config.fid))
        if self.config.threshold_value:
            trace_lines.append("Threshold: TH{}".format(self.config.threshold_value))
        trace_lines.append("-" * 60)
        
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
            
            if step.timeout:
                trace_lines.append("    Timeout:   {}s exceeded".format(self.config.timeout_seconds))
        
        return "\n".join(trace_lines)

    def get_abort_analysis(self) -> str:
        """Get analysis of steps leading to abort"""
        if not self.operation_history:
            return "No operation history available for abort analysis"
        
        # Find the point of failure
        last_success_idx = -1
        failure_step = None
        
        for i, step in enumerate(self.operation_history):
            if step.success:
                last_success_idx = i
            else:
                failure_step = step
                break
        
        if failure_step is None:
            return "No failure detected in operation history"
        
        analysis_lines = []
        analysis_lines.append("HIOC ABORT ANALYSIS")
        analysis_lines.append("=" * 50)
        analysis_lines.append("Operation Type: {}".format(self.config.operation_type.value))
        analysis_lines.append("Failed at Step: {}".format(failure_step.step.value))
        analysis_lines.append("Error: {}".format(failure_step.error_message or 'Unknown error'))
        analysis_lines.append("")
        
        analysis_lines.append("Steps Leading to Abort:")
        analysis_lines.append("-" * 30)
        
        for i, step in enumerate(self.operation_history):
            timestamp = time.strftime('%H:%M:%S', time.localtime(step.timestamp))
            status = "✓" if step.success else "✗ FAILED"
            analysis_lines.append("{}. [{}] {} - {}".format(i+1, timestamp, status, step.step.value))
            
            if not step.success:
                if step.error_message:
                    analysis_lines.append("   Error: {}".format(step.error_message))
                if step.timeout:
                    analysis_lines.append("   Timeout after {}s".format(self.config.timeout_seconds))
                if step.response_data and step.response_data.get('MSG') in [9000000, 9100000, 9300000]:
                    abort_types = {
                        9000000: "Controller-initiated abort",
                        9100000: "User-initiated abort",
                        9300000: "Timeout abort"
                    }
                    analysis_lines.append("   Abort Type: {}".format(abort_types[step.response_data['MSG']]))
                break
        
        return "\n".join(analysis_lines)


# Example usage for GUI integration
def create_example_hioc_operator():
    """Example of how to create and use HIOCOperator"""
    
    def progress_callback(message: str):
        print("Progress: {}".format(message))
    
    # Note: In real usage, client would be provided from main_gui
    from opcua import Client
    client = Client("opc.tcp://localhost:4840")
    # client.connect()  # Connection managed by main_gui
    
    # Example configuration for threshold operation
    config = HIOCOperationConfig(
        client=client,
        controller_id=1464099,  # CG1
        fid="F2",
        operation_type=HIOCOperationType.THRESHOLD,
        threshold_value=5,  # TH5
        timeout_seconds=10.0,
        progress_callback=progress_callback
    )
    
    operator = HIOCOperator(config)
    
    # Execute synchronously
    success = operator.execute_operation()
    
    if not success:
        print("\nAbort Analysis:")
        print(operator.get_abort_analysis())
    
    print("\nOperation Trace:")
    print(operator.get_operation_trace())
    
    return operator
