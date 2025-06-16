"""
HIOC Protocol Operator Class
Handles HIOC_BO and HIOC_TH operations for a single FID on one server
with comprehensive progress reporting and abort tracing.
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
    CONNECTING = "connecting"
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
    def __init__(self, server_url: str, controller_id: int, fid: str, 
                 operation_type: HIOCOperationType, threshold_value: Optional[int] = None,
                 timeout_seconds: float = 10.0, progress_callback: Optional[Callable[[str], None]] = None):
        self.server_url = server_url
        self.controller_id = controller_id
        self.fid = fid  # F0-F5
        self.operation_type = operation_type
        self.threshold_value = threshold_value  # TH1-TH15 (1-15) for HIOC_TH operations
        self.timeout_seconds = timeout_seconds
        self.progress_callback = progress_callback


class HIOCOperator:
    """
    Handles HIOC_BO and HIOC_TH protocol operations for a single FID on one server.
    Provides comprehensive progress reporting and abort tracing.
    """
    
    def __init__(self, config: HIOCOperationConfig):
        self.config = config
        self.client: Optional[Client] = None
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
        if self.config.operation_type == HIOCOperationType.THRESHOLD:
            if not self.config.threshold_value or not (1 <= self.config.threshold_value <= 15):
                raise ValueError("Threshold operations require threshold_value between 1-15")
        
        if not self.config.fid or self.config.fid not in ['F0', 'F1', 'F2', 'F3', 'F4', 'F5']:
            raise ValueError("FID must be one of F0-F5")

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
            self._report_progress(f"✓ {step.value}: Success")
        else:
            if timeout:
                self._report_progress(f"✗ {step.value}: Timeout")
            else:
                self._report_progress(f"✗ {step.value}: {error_message or 'Failed'}")

    def _get_next_sequence(self) -> int:
        """Get next challenge sequence number (always odd)"""
        if self.last_response_sequence == 0:
            return 1
        next_seq = self.last_response_sequence + 1
        return 1 if next_seq > 253 else next_seq

    def _update_sequence(self, response_seq: int):
        """Update sequence tracking based on response"""
        self.current_sequence = self._get_next_sequence()
        self.last_response_sequence = response_seq

    def _connect_to_server(self) -> bool:
        """Connect to OPC-UA server"""
        try:
            self._report_progress(f"Connecting to {self.config.server_url}...")
            self.client = Client(self.config.server_url)
            self.client.connect()
            
            self._log_step(HIOCStep.CONNECTING, True)
            self._report_progress("Connected to server successfully")
            return True
            
        except Exception as e:
            self._log_step(HIOCStep.CONNECTING, False, error_message=str(e))
            return False

    def _write_challenge_data(self, ctr: int, flg: int, msg: int, value: int, seq: int):
        """Write challenge data to HIOCIn nodes with guaranteed SEQ field written last"""
        try:
            # Build node paths
            ctr_path = ['HIOCIn', self.config.fid, 'STF', 'CTR']
            flg_path = ['HIOCIn', self.config.fid, 'STF', 'FLG']
            msg_path = ['HIOCIn', self.config.fid, 'STF', 'MSG']
            value_path = ['HIOCIn', self.config.fid, 'STF', 'VALUE']
            seq_path = ['HIOCIn', self.config.fid, 'STF', 'SEQ']
            
            # Get nodes
            ctr_node = self.client.get_node("ns=2;s=" + ".".join(ctr_path))
            flg_node = self.client.get_node("ns=2;s=" + ".".join(flg_path))
            msg_node = self.client.get_node("ns=2;s=" + ".".join(msg_path))
            value_node = self.client.get_node("ns=2;s=" + ".".join(value_path))
            seq_node = self.client.get_node("ns=2;s=" + ".".join(seq_path))
            
            # Write all fields EXCEPT SEQ first (guaranteed ordering)
            ctr_node.set_value(ua.Variant(int(ctr) & 0xFFFFFFFF, ua.VariantType.UInt32))
            flg_node.set_value(ua.Variant(int(flg) & 0xFFFFFFFF, ua.VariantType.UInt32))
            msg_node.set_value(ua.Variant(int(msg) & 0xFFFFFFFF, ua.VariantType.UInt32))
            value_node.set_value(ua.Variant(int(value) & 0xFFFFFFFF, ua.VariantType.UInt32))
            
            # Ensure all previous writes are complete before writing SEQ
            # SEQ acts as the "commit" signal for the challenge
            time.sleep(0.001)  # Small delay to ensure write ordering
            seq_node.set_value(ua.Variant(int(seq), ua.VariantType.Int32))
            
            return {
                'CTR': ctr, 'FLG': flg, 'MSG': msg, 'VALUE': value, 'SEQ': seq
            }
            
        except Exception as e:
            raise Exception("Failed to write challenge data: {}".format(e))

    def _read_response_data(self) -> Dict[str, Any]:
        """Read response data from HIOCOut nodes"""
        try:
            # Build node paths
            ctr_path = ['HIOCOut', self.config.fid, 'FTS', 'CTR']
            flg_path = ['HIOCOut', self.config.fid, 'FTS', 'FLG']
            msg_path = ['HIOCOut', self.config.fid, 'FTS', 'MSG']
            value_path = ['HIOCOut', self.config.fid, 'FTS', 'VALUE']
            seq_path = ['HIOCOut', self.config.fid, 'FTS', 'SEQ']
            
            # Get nodes and read values
            ctr_node = self.client.get_node("ns=2;s=" + ".".join(ctr_path))
            flg_node = self.client.get_node("ns=2;s=" + ".".join(flg_path))
            msg_node = self.client.get_node("ns=2;s=" + ".".join(msg_path))
            value_node = self.client.get_node("ns=2;s=" + ".".join(value_path))
            seq_node = self.client.get_node("ns=2;s=" + ".".join(seq_path))
            
            return {
                'CTR': ctr_node.get_value(),
                'FLG': flg_node.get_value(),
                'MSG': msg_node.get_value(),
                'VALUE': value_node.get_value(),
                'SEQ': seq_node.get_value()
            }
            
        except Exception as e:
            raise Exception("Failed to read response data: {}".format(e))

    def _wait_for_response(self, expected_flag: int, timeout: float = None) -> Tuple[bool, Dict[str, Any]]:
        """Wait for expected response flag with timeout"""
        if timeout is None:
            timeout = self.config.timeout_seconds
            
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.abort_requested:
                return False, {}
                
            try:
                response = self._read_response_data()
                if response['FLG'] == expected_flag:
                    return True, response
                elif response['FLG'] == 9:  # Abort flag
                    return False, response
                    
            except Exception:
                pass
                
            time.sleep(0.1)  # 100ms polling
            
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
            
            # Wait for HTT response (flag 22)
            success, response_data = self._wait_for_response(22)
            
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
                value = 0
            elif step_num == 2:
                # Command step
                if self.config.operation_type == HIOCOperationType.THRESHOLD:
                    command_code = self.config.threshold_value
                else:
                    command_code = self.command_codes[self.config.operation_type]
                    
                msg_id = 3460000 + command_code  # CommandID format
                flag = self.flag_values['command'][self.config.operation_type]
                value = 0
            else:  # step_num == 3
                # Confirmation step
                if self.config.operation_type == HIOCOperationType.THRESHOLD:
                    command_code = self.config.threshold_value
                else:
                    command_code = self.command_codes[self.config.operation_type]
                    
                msg_id = 400000 + fid_num * 100 + command_code  # ConfirmationID format
                flag = self.flag_values['confirmation'][self.config.operation_type]
                value = 0
            
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=flag,
                msg=msg_id,
                value=value,
                seq=seq
            )
            
            self._log_step(challenge_step, True, challenge_data=challenge_data)
            
            # Wait for response
            success, response_data = self._wait_for_response(expected_response_flag)
            
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
                        }.get(response_data['MSG'], f"Unknown abort: {response_data['MSG']}")
                        
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
            
            # Step 0: Connect to server
            if not self._connect_to_server():
                return False
            
            # Auxiliary Step: HTT request for threshold operations
            if self.config.operation_type == HIOCOperationType.THRESHOLD:
                if not self._perform_htt_request():
                    return False
            
            # Step 1: Function validation
            if not self._perform_hioc_step(1, 2):  # Expect flag 2 response
                return False
            
            if self.abort_requested:
                self._log_step(HIOCStep.ABORTED, True, error_message="User abort requested")
                return False
            
            # Step 2: Command
            expected_flag = 4 if self.config.operation_type in [
                HIOCOperationType.THRESHOLD, HIOCOperationType.OVERRIDE_SET, HIOCOperationType.DISABLE
            ] else 14
            
            if not self._perform_hioc_step(2, expected_flag):
                return False
            
            if self.abort_requested:
                self._log_step(HIOCStep.ABORTED, True, error_message="User abort requested")
                return False
            
            # Step 3: Confirmation
            expected_flag = 6  # Success flag for all operations
            
            if not self._perform_hioc_step(3, expected_flag):
                return False
            
            # Operation completed successfully
            self._log_step(HIOCStep.COMPLETED, True)
            self._report_progress("✓ HIOC operation completed successfully")
            return True
            
        except Exception as e:
            self._log_step(HIOCStep.ABORTED, False, error_message=str(e))
            self._report_progress("✗ Operation failed: {}".format(e))
            return False
        finally:
            if self.client:
                try:
                    self.client.disconnect()
                except:
                    pass

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
        trace_lines.append(f"HIOC Operation Trace - {self.config.operation_type.value}")
        trace_lines.append(f"Server: {self.config.server_url}")
        trace_lines.append(f"Controller: {self.config.controller_id}")
        trace_lines.append(f"FID: {self.config.fid}")
        if self.config.threshold_value:
            trace_lines.append(f"Threshold: TH{self.config.threshold_value}")
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
        print(f"Progress: {message}")
    
    # Example configuration for threshold operation
    config = HIOCOperationConfig(
        server_url="opc.tcp://localhost:4840",
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
