"""
SUP Protocol Operator Class
Handles HIOCwSUP (HIOC with SUP extension) operations for structured parameters.
Inherits from HIOCOperator and adds SUP-specific functionality.
"""

import os
import zlib
import csv
from typing import List, Optional
from enum import Enum
from opcua import ua

# Import the base HIOCOperator
from hioc_operator import HIOCOperator, HIOCOperationConfig, HIOCStep, HIOCStepResult


class SUPStep(Enum):
    """Additional SUP protocol steps"""
    CAPABILITY_CHECK = "capability_check"
    CSV_PARSING = "csv_parsing"
    NONCE_REQUEST = "nonce_request"
    NONCE_RESPONSE = "nonce_response"
    CRC32_CALCULATION = "crc32_calculation"
    HIOC_UNLOCK_STEP1 = "hioc_unlock_step1"
    HIOC_UNLOCK_STEP2 = "hioc_unlock_step2"
    HIOC_UNLOCK_STEP3 = "hioc_unlock_step3"
    CTFSS_POPULATE = "ctfss_populate"
    HSUP_STEP1_CHALLENGE = "hsup_step1_challenge"
    HSUP_STEP1_RESPONSE = "hsup_step1_response"
    HSUP_STEP2_CHALLENGE = "hsup_step2_challenge"
    HSUP_STEP2_RESPONSE = "hsup_step2_response"
    HSUP_STEP3_CHALLENGE = "hsup_step3_challenge"
    HSUP_STEP3_RESPONSE = "hsup_step3_response"
    LOCK_PARAMS_RECOVERY = "lock_params_recovery"


class SUPOperationConfig(HIOCOperationConfig):
    """Configuration for SUP operation - extends HIOC config"""
    def __init__(self, server_url, controller_id, fid, operation_type, 
                 csv_file_path=None, timeout_seconds=10.0, progress_callback=None):
        super().__init__(server_url, controller_id, fid, operation_type, 
                        None, timeout_seconds, progress_callback)
        self.csv_file_path = csv_file_path


class SUPOperator(HIOCOperator):
    """
    Handles HIOCwSUP protocol operations for structured parameters.
    Inherits HIOC functionality and adds SUP-specific steps.
    """
    
    def __init__(self, config: SUPOperationConfig):
        # Initialize parent with modified config for HIOC unlock operation
        hioc_config = HIOCOperationConfig(
            server_url=config.server_url,
            controller_id=config.controller_id,
            fid=config.fid,
            operation_type=config.operation_type,
            timeout_seconds=config.timeout_seconds,
            progress_callback=config.progress_callback
        )
        
        super().__init__(hioc_config)
        
        self.sup_config = config
        self.structured_parameters: List[int] = []
        self.fidsize_value: int = 0
        self.nonce_value: Optional[int] = None
        self.crc32_value: Optional[int] = None
        self.is_sup_capable = False
        
        # Independent HSUP sequence management
        self.hsup_current_sequence = 1
        self.hsup_last_response_sequence = 0
        
        # Validate SUP configuration
        self._validate_sup_config()

    def _validate_sup_config(self):
        """Validate SUP-specific configuration"""
        if not self.sup_config.csv_file_path:
            raise ValueError("CSV file path is required for SUP operations")
        
        if not os.path.exists(self.sup_config.csv_file_path):
            raise ValueError(f"CSV file not found: {self.sup_config.csv_file_path}")

    def _get_next_hsup_sequence(self) -> int:
        """Get next HSUP challenge sequence number (independent from HIOC)"""
        if self.hsup_last_response_sequence == 0:
            return 1
        next_seq = self.hsup_last_response_sequence + 1
        return 1 if next_seq > 253 else next_seq

    def _update_hsup_sequence(self, response_seq: int):
        """Update HSUP sequence tracking"""
        self.hsup_current_sequence = self._get_next_hsup_sequence()
        self.hsup_last_response_sequence = response_seq

    def _log_sup_step(self, step: SUPStep, success: bool, challenge_data=None, 
                      response_data=None, error_message=None, timeout=False):
        """Log SUP step using parent's logging mechanism"""
        # Convert SUPStep to HIOCStep for logging compatibility
        hioc_step = HIOCStep(step.value) if hasattr(HIOCStep, step.value) else HIOCStep.CONNECTING
        self._log_step(hioc_step, success, challenge_data, response_data, error_message, timeout)

    def _check_sup_capability(self) -> bool:
        """Check if FID supports SUP by reading HTT FIDSize"""
        try:
            self._report_progress(f"Checking SUP capability for {self.config.fid}...")
            
            # Read FIDSize from HTT
            fid_size_path = ['HTT', f'FIDSize{self.config.fid}']
            fid_size_node = self.client.get_node("ns=2;s=" + ".".join(fid_size_path))
            fid_size = fid_size_node.get_value()
            
            self.is_sup_capable = fid_size > 1
            self.fidsize_value = fid_size
            
            self._log_sup_step(SUPStep.CAPABILITY_CHECK, True)
            self._report_progress(f"FID {self.config.fid} FIDSize: {fid_size}, SUP capable: {self.is_sup_capable}")
            
            return self.is_sup_capable
            
        except Exception as e:
            self._log_sup_step(SUPStep.CAPABILITY_CHECK, False, error_message=str(e))
            return False

    def _parse_csv_file(self) -> bool:
        """Parse CSV file with hex parameters"""
        try:
            self._report_progress(f"Parsing CSV file: {self.sup_config.csv_file_path}")
            
            with open(self.sup_config.csv_file_path, 'r') as file:
                # Read first line and strip whitespace/carriage returns
                line = file.readline().strip().replace('\r', '')
                
                # Split by comma and parse hex values
                hex_values = [val.strip() for val in line.split(',') if val.strip()]
                
                if not hex_values:
                    raise ValueError("CSV file is empty or invalid")
                
                # First value is FIDSize (in hex)
                fidsize_hex = hex_values[0]
                param_hex_values = hex_values[1:]
                
                # Convert hex FIDSize
                try:
                    csv_fidsize = int(fidsize_hex, 16)
                except ValueError:
                    raise ValueError(f"Invalid hex FIDSize: {fidsize_hex}")
                
                # Validate parameter count (FIDSize = parameter count + 1)
                expected_param_count = csv_fidsize - 1
                actual_param_count = len(param_hex_values)
                
                if actual_param_count != expected_param_count:
                    raise ValueError(
                        f"Parameter count mismatch: FIDSize {csv_fidsize} expects {expected_param_count} "
                        f"parameters, but found {actual_param_count}"
                    )
                
                # Validate against HTT FIDSize if available
                if self.fidsize_value > 0 and csv_fidsize != self.fidsize_value:
                    raise ValueError(
                        f"CSV FIDSize {csv_fidsize} doesn't match HTT FIDSize {self.fidsize_value}"
                    )
                
                # Convert hex parameters to uint32
                parameters = []
                for i, hex_param in enumerate(param_hex_values):
                    try:
                        param_value = int(hex_param, 16)
                        if param_value > 0xFFFFFFFF:
                            raise ValueError(f"Parameter {i+1} exceeds uint32 range: {hex_param}")
                        parameters.append(param_value)
                    except ValueError:
                        raise ValueError(f"Invalid hex parameter at position {i+1}: {hex_param}")
                
                # Validate parameter count limits
                if len(parameters) > 511:
                    raise ValueError(f"Too many parameters: {len(parameters)} (max 511)")
                
                self.structured_parameters = parameters
                
                self._log_sup_step(SUPStep.CSV_PARSING, True)
                self._report_progress(f"Parsed {len(parameters)} hex parameters from CSV")
                
                return True
                
        except Exception as e:
            self._log_sup_step(SUPStep.CSV_PARSING, False, error_message=str(e))
            return False

    def _perform_nonce_request(self) -> bool:
        """Perform nonce request for SUP CRC32 calculation"""
        try:
            fid_num = int(self.config.fid[1:])
            function_id = 2460000 + fid_num
            
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=11,  # Nonce request flag
                msg=function_id,
                value=0,
                seq=seq
            )
            
            self._log_sup_step(SUPStep.NONCE_REQUEST, True, challenge_data=challenge_data)
            
            # Wait for nonce response (flag 12)
            success, response_data = self._wait_for_response(12)
            
            if success:
                self.nonce_value = response_data['VALUE']
                self._update_sequence(response_data['SEQ'])
                self._log_sup_step(SUPStep.NONCE_RESPONSE, True, response_data=response_data)
                self._report_progress("Received nonce: {:08X}".format(self.nonce_value))
                return True
            else:
                self._log_sup_step(SUPStep.NONCE_RESPONSE, False,
                                 error_message="Nonce response timeout or abort", timeout=True)
                return False
                
        except Exception as e:
            self._log_sup_step(SUPStep.NONCE_REQUEST, False, error_message=str(e))
            return False

    def _calculate_crc32(self) -> bool:
        """Calculate CRC32 for SUP parameters + nonce"""
        try:
            if self.nonce_value is None:
                raise ValueError("Nonce value not available for CRC32 calculation")
            
            # Create buffer: [parameters + nonce]
            buffer = self.structured_parameters + [self.nonce_value]
            
            # Convert to little-endian bytes
            buffer_bytes = b''.join(val.to_bytes(4, byteorder='little') for val in buffer)
            
            # Calculate CRC32
            self.crc32_value = zlib.crc32(buffer_bytes) & 0xFFFFFFFF
            
            self._log_sup_step(SUPStep.CRC32_CALCULATION, True)
            self._report_progress("Calculated CRC32: {:08X} over {} words".format(
                self.crc32_value, len(buffer)))
            
            return True
            
        except Exception as e:
            self._log_sup_step(SUPStep.CRC32_CALCULATION, False, error_message=str(e))
            return False

    def _perform_hioc_unlock_sequence(self) -> bool:
        """Perform HIOC 3-step sequence with unlock command and CRC32"""
        try:
            self._report_progress("Starting HIOC unlock sequence...")
            
            # Step 1: Function validation
            if not self._perform_hioc_step(1, 2):  # Expect flag 2 response
                self._log_sup_step(SUPStep.HIOC_UNLOCK_STEP1, False, error_message="HIOC Step 1 failed")
                return False
            self._log_sup_step(SUPStep.HIOC_UNLOCK_STEP1, True)
            
            if self.abort_requested:
                return False
            
            # Step 2: Unlock command with CRC32
            # Override the command code and value for unlock
            fid_num = int(self.config.fid[1:])
            command_code = 50  # Unlock command
            
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=3,  # Command flag
                msg=3460000 + command_code,  # CommandID format
                value=self.crc32_value,  # Use CRC32 as value
                seq=seq
            )
            
            success, response_data = self._wait_for_response(4)  # Expect flag 4
            if not success:
                self._log_sup_step(SUPStep.HIOC_UNLOCK_STEP2, False, error_message="HIOC Step 2 failed")
                return False
            
            self._update_sequence(response_data['SEQ'])
            self._log_sup_step(SUPStep.HIOC_UNLOCK_STEP2, True, 
                              challenge_data=challenge_data, response_data=response_data)
            
            if self.abort_requested:
                return False
            
            # Step 3: Confirmation
            seq = self._get_next_sequence()
            confirmation_id = 400000 + fid_num * 100 + command_code
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=5,  # Confirmation flag
                msg=confirmation_id,
                value=0,
                seq=seq
            )
            
            success, response_data = self._wait_for_response(6)  # Expect success flag
            if success and response_data['MSG'] == 7500000:  # Success
                self._update_sequence(response_data['SEQ'])
                self._log_sup_step(SUPStep.HIOC_UNLOCK_STEP3, True, 
                                  challenge_data=challenge_data, response_data=response_data)
                self._report_progress("✓ HIOC unlock sequence completed successfully")
                return True
            else:
                self._log_sup_step(SUPStep.HIOC_UNLOCK_STEP3, False, 
                                  response_data=response_data, error_message="HIOC Step 3 failed")
                return False
                
        except Exception as e:
            self._log_sup_step(SUPStep.HIOC_UNLOCK_STEP3, False, error_message=str(e))
            return False

    def _populate_ctfss_buffer(self) -> bool:
        """Populate CTFSS buffer with structured parameters"""
        try:
            self._report_progress("Populating CTFSS buffer...")
            
            # CTFSS buffer paths
            ctfss_paths = {
                'CTR': ['CTFSS', 'CTR'],
                'FLG': ['CTFSS', 'FLG'],
                'MSG': ['CTFSS', 'MSG'],
                'VALUE': ['CTFSS', 'VALUE'],
                'DSIZE': ['CTFSS', 'DSIZE'],
                'DATA': ['CTFSS', 'DATA']
            }
            
            # Get nodes
            nodes = {}
            for key, path in ctfss_paths.items():
                nodes[key] = self.client.get_node("ns=2;s=" + ".".join(path))
            
            # Set metadata
            nodes['CTR'].set_value(ua.Variant(self.config.controller_id, ua.VariantType.UInt32))
            nodes['FLG'].set_value(ua.Variant(1, ua.VariantType.UInt32))
            nodes['MSG'].set_value(ua.Variant(0, ua.VariantType.UInt32))
            nodes['VALUE'].set_value(ua.Variant(0, ua.VariantType.UInt32))
            nodes['DSIZE'].set_value(ua.Variant(len(self.structured_parameters), ua.VariantType.UInt32))
            
            # Set parameter data as array
            data_variants = [ua.Variant(param, ua.VariantType.UInt32) for param in self.structured_parameters]
            nodes['DATA'].set_value(data_variants)
            
            self._log_sup_step(SUPStep.CTFSS_POPULATE, True)
            self._report_progress("CTFSS buffer populated with {} parameters".format(
                len(self.structured_parameters)))
            return True
            
        except Exception as e:
            self._log_sup_step(SUPStep.CTFSS_POPULATE, False, error_message=str(e))
            return False

    def _write_hsup_challenge_data(self, ctr: int, flg: int, msg: int, value: int, seq: int):
        """Write challenge data to HSUPIn nodes with guaranteed SEQ written last"""
        try:
            # Build HSUP node paths
            ctr_path = ['HSUPIn', self.config.fid, 'CTF', 'CTR']
            flg_path = ['HSUPIn', self.config.fid, 'CTF', 'FLG']
            msg_path = ['HSUPIn', self.config.fid, 'CTF', 'MSG']
            value_path = ['HSUPIn', self.config.fid, 'CTF', 'VALUE']
            seq_path = ['HSUPIn', self.config.fid, 'CTF', 'SEQ']
            
            # Get nodes
            ctr_node = self.client.get_node("ns=2;s=" + ".".join(ctr_path))
            flg_node = self.client.get_node("ns=2;s=" + ".".join(flg_path))
            msg_node = self.client.get_node("ns=2;s=" + ".".join(msg_path))
            value_node = self.client.get_node("ns=2;s=" + ".".join(value_path))
            seq_node = self.client.get_node("ns=2;s=" + ".".join(seq_path))
            
            # Write all fields EXCEPT SEQ first
            ctr_node.set_value(ua.Variant(int(ctr) & 0xFFFFFFFF, ua.VariantType.UInt32))
            flg_node.set_value(ua.Variant(int(flg) & 0xFFFFFFFF, ua.VariantType.UInt32))
            msg_node.set_value(ua.Variant(int(msg) & 0xFFFFFFFF, ua.VariantType.UInt32))
            value_node.set_value(ua.Variant(int(value) & 0xFFFFFFFF, ua.VariantType.UInt32))
            
            # Ensure ordering before writing SEQ
            import time
            time.sleep(0.001)
            seq_node.set_value(ua.Variant(int(seq), ua.VariantType.Int32))
            
            return {
                'CTR': ctr, 'FLG': flg, 'MSG': msg, 'VALUE': value, 'SEQ': seq
            }
            
        except Exception as e:
            raise Exception("Failed to write HSUP challenge data: {}".format(e))

    def _read_hsup_response_data(self) -> dict:
        """Read response data from HSUPOut nodes"""
        try:
            # Build HSUP response node paths
            ctr_path = ['HSUPOut', self.config.fid, 'FTC', 'CTR']
            flg_path = ['HSUPOut', self.config.fid, 'FTC', 'FLG']
            msg_path = ['HSUPOut', self.config.fid, 'FTC', 'MSG']
            value_path = ['HSUPOut', self.config.fid, 'FTC', 'VALUE']
            seq_path = ['HSUPOut', self.config.fid, 'FTC', 'SEQ']
            
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
            raise Exception("Failed to read HSUP response data: {}".format(e))

    def _wait_for_hsup_response(self, expected_flag: int, timeout: float = None):
        """Wait for expected HSUP response flag"""
        if timeout is None:
            timeout = self.config.timeout_seconds
            
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.abort_requested:
                return False, {}
                
            try:
                response = self._read_hsup_response_data()
                if response['FLG'] == expected_flag:
                    return True, response
                elif response['FLG'] == 9:  # Abort flag
                    return False, response
                    
            except Exception:
                pass
                
            time.sleep(0.1)  # 100ms polling
            
        return False, {}  # Timeout

    def _perform_hsup_step(self, step_num: int, expected_response_flag: int) -> bool:
        """Perform a single HSUP protocol step"""
        try:
            step_mapping = {
                1: (SUPStep.HSUP_STEP1_CHALLENGE, SUPStep.HSUP_STEP1_RESPONSE),
                2: (SUPStep.HSUP_STEP2_CHALLENGE, SUPStep.HSUP_STEP2_RESPONSE),
                3: (SUPStep.HSUP_STEP3_CHALLENGE, SUPStep.HSUP_STEP3_RESPONSE)
            }
            
            challenge_step, response_step = step_mapping[step_num]
            
            # Determine message ID and flag based on step
            fid_num = int(self.config.fid[1:])
            
            if step_num == 1:
                # Function validation
                msg_id = 2460000 + fid_num  # FunctionID
                flag = 1
                value = 0
            elif step_num == 2:
                # Command with confirmation ID
                msg_id = 400000 + fid_num * 100 + 50  # ConfirmationID format for unlock
                flag = 3
                value = 0
            else:  # step_num == 3
                # Final confirmation
                msg_id = 400000 + fid_num * 100 + 50  # ConfirmationID format
                flag = 5
                value = 0
            
            seq = self._get_next_hsup_sequence()
            challenge_data = self._write_hsup_challenge_data(
                ctr=self.config.controller_id,
                flg=flag,
                msg=msg_id,
                value=value,
                seq=seq
            )
            
            self._log_sup_step(challenge_step, True, challenge_data=challenge_data)
            
            # Wait for response
            success, response_data = self._wait_for_hsup_response(expected_response_flag)
            
            if success:
                self._update_hsup_sequence(response_data['SEQ'])
                
                # Check for success/abort in final step
                if step_num == 3:
                    if response_data['MSG'] == 7500000:  # Success
                        self._log_sup_step(response_step, True, response_data=response_data)
                        return True
                    else:  # Abort codes
                        abort_msg = {
                            9000000: "Controller abort",
                            9100000: "User abort", 
                            9300000: "Timeout abort"
                        }.get(response_data['MSG'], f"Unknown abort: {response_data['MSG']}")
                        
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

    def _perform_hsup_sequence(self) -> bool:
        """Perform complete HSUP 3-step sequence"""
        try:
            self._report_progress("Starting HSUP 3-step sequence...")
            
            # HSUP Step 1: Function validation
            if not self._perform_hsup_step(1, 2):  # Expect flag 2
                return False
            
            if self.abort_requested:
                return False
            
            # HSUP Step 2: Command
            if not self._perform_hsup_step(2, 4):  # Expect flag 4
                return False
            
            if self.abort_requested:
                return False
            
            # HSUP Step 3: Final confirmation
            if not self._perform_hsup_step(3, 6):  # Expect success flag
                return False
            
            self._report_progress("✓ HSUP sequence completed successfully")
            return True
            
        except Exception as e:
            self._report_progress(f"✗ HSUP sequence failed: {e}")
            return False

    def _perform_lock_parameters_recovery(self) -> bool:
        """Perform parameter lock (CC=55) for error recovery"""
        try:
            self._report_progress("Attempting parameter lock recovery...")
            
            fid_num = int(self.config.fid[1:])
            command_code = 55  # Lock command
            
            # Step 1: Function validation
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=1,
                msg=2460000 + fid_num,
                value=0,
                seq=seq
            )
            
            success, response_data = self._wait_for_response(2)
            if not success:
                return False
            self._update_sequence(response_data['SEQ'])
            
            # Step 2: Lock command
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=3,
                msg=3460000 + command_code,
                value=0,
                seq=seq
            )
            
            success, response_data = self._wait_for_response(4)
            if not success:
                return False
            self._update_sequence(response_data['SEQ'])
            
            # Step 3: Confirmation
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=5,
                msg=400000 + fid_num * 100 + command_code,
                value=0,
                seq=seq
            )
            
            success, response_data = self._wait_for_response(6)
            if success and response_data['MSG'] == 7500000:
                self._update_sequence(response_data['SEQ'])
                self._log_sup_step(SUPStep.LOCK_PARAMS_RECOVERY, True)
                self._report_progress("✓ Parameters locked successfully")
                return True
            else:
                self._log_sup_step(SUPStep.LOCK_PARAMS_RECOVERY, False)
                return False
                
        except Exception as e:
            self._log_sup_step(SUPStep.LOCK_PARAMS_RECOVERY, False, error_message=str(e))
            return False

    def execute_operation(self) -> bool:
        """Execute the complete SUP operation"""
        try:
            self.abort_requested = False
            self.operation_history.clear()
            
            # Step 0: Connect to server
            if not self._connect_to_server():
                return False
            
            # Step 1: Check SUP capability
            if not self._check_sup_capability():
                self._report_progress("✗ FID does not support SUP operations")
                return False
            
            # Step 2: Parse CSV file
            if not self._parse_csv_file():
                return False
            
            # Step 3: Nonce request
            if not self._perform_nonce_request():
                return False
            
            # Step 4: Calculate CRC32
            if not self._calculate_crc32():
                return False
            
            # Step 5: HIOC unlock sequence
            hioc_success = self._perform_hioc_unlock_sequence()
            if not hioc_success:
                return False
            
            # Step 6: Populate CTFSS buffer
            if not self._populate_ctfss_buffer():
                # HIOC succeeded but CTFSS failed - offer recovery
                self._report_progress("CTFSS population failed - offering parameter lock recovery")
                self._perform_lock_parameters_recovery()
                return False
            
            # Step 7: HSUP sequence
            hsup_success = self._perform_hsup_sequence()
            if not hsup_success:
                # HIOC succeeded but HSUP failed - offer recovery
                self._report_progress("HSUP sequence failed - offering parameter lock recovery")
                self._perform_lock_parameters_recovery()
                return False
            
            # Operation completed successfully
            self._log_step(HIOCStep.COMPLETED, True)
            self._report_progress("✓ SUP operation completed successfully")
            return True
            
        except Exception as e:
            self._log_step(HIOCStep.ABORTED, False, error_message=str(e))
            self._report_progress("✗ SUP operation failed: {}".format(e))
            return False
        finally:
            if self.client:
                try:
                    self.client.disconnect()
                except:
                    pass


# Example usage for GUI integration
def create_example_sup_operator():
    """Example of how to create and use SUPOperator"""
    
    def progress_callback(message: str):
        print(f"Progress: {message}")
    
    # Example configuration for SUP operation
    config = SUPOperationConfig(
        server_url="opc.tcp://localhost:4840",
        controller_id=1464099,  # CG1
        fid="F3",  # Must support SUP (FIDSize > 1)
        operation_type=HIOCOperationType.STRUCTURED_PARAMS,
        csv_file_path="parameters.csv",  # Contains: 0xB,0x64,0xC8,0x12C,0x190,0x1F4,0x258,0x2BC,0x320,0x384,0x3E8
        timeout_seconds=10.0,
        progress_callback=progress_callback
    )
    
    operator = SUPOperator(config)
    
    # Execute operation
    success = operator.execute_operation()
    
    if not success:
        print("\nAbort Analysis:")
        print(operator.get_abort_analysis())
    
    print("\nOperation Trace:")
    print(operator.get_operation_trace())
    
    return operator