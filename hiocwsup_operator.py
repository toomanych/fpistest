"""
HIOCwSUP Operator Class
Extends HIOCOperator to handle HIOCwSUP-specific HIOC operations (unlock/lock).
Uses the same HIOC protocol but with SUP-specific command codes (CC=50, CC=55).
"""

import time
from enum import Enum
from typing import Optional, Dict, Any
from opcua import Client

# Import the base HIOCOperator
from hioc_operator import HIOCOperator, HIOCOperationConfig, HIOCStep, HIOCStepResult, HIOCOperationType


class HIOCwSUPStep(Enum):
    """Additional HIOC steps specific to HIOCwSUP (unlock/lock operations)"""
    HIOC_UNLOCK_STEP1 = "hioc_unlock_step1"
    HIOC_UNLOCK_RESPONSE1 = "hioc_unlock_response1"
    HIOC_UNLOCK_STEP2 = "hioc_unlock_step2"
    HIOC_UNLOCK_RESPONSE2 = "hioc_unlock_response2"
    HIOC_UNLOCK_STEP3 = "hioc_unlock_step3"
    HIOC_UNLOCK_RESPONSE3 = "hioc_unlock_response3"
    HIOC_LOCK_STEP1 = "hioc_lock_step1"
    HIOC_LOCK_RESPONSE1 = "hioc_lock_response1"
    HIOC_LOCK_STEP2 = "hioc_lock_step2"
    HIOC_LOCK_RESPONSE2 = "hioc_lock_response2"
    HIOC_LOCK_STEP3 = "hioc_lock_step3"
    HIOC_LOCK_RESPONSE3 = "hioc_lock_response3"


class HIOCwSUPOperator(HIOCOperator):
    """
    Extends HIOCOperator to handle HIOCwSUP-specific HIOC operations (unlock/lock).
    Uses the same HIOC protocol but with SUP-specific command codes (CC=50, CC=55).
    """
    
    def __init__(self, config: HIOCOperationConfig):
        super().__init__(config)

    def _validate_config(self):
        """Override parent validation to allow SUP command codes (CC=50, CC=55)"""
        if not self.config.client:
            raise ValueError("Connected client is required")
            
        if self.config.operation_type == HIOCOperationType.THRESHOLD:
            if not self.config.threshold_command_code:
                raise ValueError("HIOCwSUP operations require threshold_command_code")
                
            # EXTENDED VALIDATION: Allow 1-15 (thresholds) + 50,55 (SUP commands)
            valid_codes = list(range(1, 16)) + [50, 55]
            if self.config.threshold_command_code not in valid_codes:
                raise ValueError("Command code must be 1-15 (thresholds) or 50/55 (SUP commands)")
                
            if self.config.threshold_value is None:
                raise ValueError("HIOCwSUP operations require threshold_value")
        
        # Validate FID (same as parent)
        valid_fids = ['F{}'.format(i) for i in range(32)]
        if not self.config.fid or self.config.fid not in valid_fids:
            raise ValueError("FID must be one of F0-F31")

    def _log_hiocwsup_step(self, step: HIOCwSUPStep, success: bool, challenge_data=None, 
                           response_data=None, error_message=None, timeout=False):
        """Log HIOCwSUP step using parent's logging mechanism"""
        # Convert to HIOCStep for compatibility
        hioc_step = HIOCStep(step.value) if hasattr(HIOCStep, step.value) else HIOCStep.CONNECTING
        self._log_step(hioc_step, success, challenge_data, response_data, error_message, timeout)

    def perform_unlock_sequence(self, crc32_value: int) -> bool:
        """
        Perform HIOC unlock sequence (CC=50) with CRC32 value.
        
        Flow:
        1. HIOC_UNLOCK_STEP1: FLG=1, MSG=FunctionID
        2. HIOC_UNLOCK_RESPONSE1: Expected FLG=2
        3. HIOC_UNLOCK_STEP2: FLG=3, MSG=3460050, VALUE=crc32_val
        4. HIOC_UNLOCK_RESPONSE2: Expected FLG=4
        5. HIOC_UNLOCK_STEP3: FLG=5, MSG=ConfirmationID(CC=50), VALUE=crc32_val
        6. HIOC_UNLOCK_RESPONSE3: Expected FLG=6, MSG=7500000 (success)
        """
        try:
            self._report_progress("Starting HIOC unlock sequence (CC=50)...")
            
            fid_num = int(self.config.fid[1:])
            unlock_command_code = self.config.threshold_command_code  # Should be 50
            crc32_val = self.config.threshold_value  # Should be crc32_value
            
            # Validate we have the right command code
            if unlock_command_code != 50:
                raise ValueError("Unlock sequence requires threshold_command_code=50, got {}".format(unlock_command_code))
            
            # Step 1: Function validation
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=1,  # Function validation flag
                msg=2460000 + fid_num,  # FunctionID
                value=0,
                seq=seq
            )
            
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_STEP1, True, challenge_data=challenge_data)
            
            success, response_data = self._wait_for_response(2, challenge_data)  # Expect flag 2
            if not success:
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_RESPONSE1, False, 
                                      error_message="HIOC unlock step 1 failed")
                return False
            
            self._update_sequence(response_data['SEQ'])
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_RESPONSE1, True, response_data=response_data)
            
            if self.abort_requested:
                return False
            
            # Step 2: Unlock command with CRC32 as value
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=3,  # Command flag
                msg=3460000 + unlock_command_code,  # CommandID: 3460050
                value=crc32_val,  # CRC32 as value for unlock
                seq=seq
            )
            
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_STEP2, True, challenge_data=challenge_data)
            
            success, response_data = self._wait_for_response(4, challenge_data)  # Expect flag 4
            if not success:
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_RESPONSE2, False, 
                                      error_message="HIOC unlock step 2 failed")
                return False
            
            self._update_sequence(response_data['SEQ'])
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_RESPONSE2, True, response_data=response_data)
            
            if self.abort_requested:
                return False
            
            # Step 3: Confirmation
            seq = self._get_next_sequence()
            confirmation_id = 4000000 + fid_num * 100 + unlock_command_code  # ConfirmationID with CC=50
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=5,  # Confirmation flag
                msg=confirmation_id,
                value=crc32_val,  # CRC32 as value for confirmation
                seq=seq
            )
            
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_STEP3, True, challenge_data=challenge_data)
            
            success, response_data = self._wait_for_response(6, challenge_data)  # Expect success flag
            if success and response_data['MSG'] == 7500000:  # SuccessID
                self._update_sequence(response_data['SEQ'])
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_RESPONSE3, True, response_data=response_data)
                self._report_progress("✓ HIOC unlock sequence completed successfully")
                return True
            else:
                # Check for abort codes
                abort_msg = {
                    9000000: "Controller abort",
                    9100000: "User abort", 
                    9300000: "Timeout abort"
                }.get(response_data.get('MSG', 0), "Unknown abort: {}".format(response_data.get('MSG', 'N/A')))
                
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_RESPONSE3, False, 
                                      response_data=response_data, error_message=abort_msg)
                return False
                
        except Exception as e:
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_UNLOCK_STEP3, False, error_message=str(e))
            return False

    def perform_lock_sequence(self) -> bool:
        """
        Perform HIOC lock sequence (CC=55) for parameter locking.
        Future implementation for error recovery.
        
        Flow would be similar to unlock but with CC=55:
        1. HIOC_LOCK_STEP1: FLG=1, MSG=FunctionID
        2. HIOC_LOCK_RESPONSE1: Expected FLG=2
        3. HIOC_LOCK_STEP2: FLG=3, MSG=3460055, VALUE=0
        4. HIOC_LOCK_RESPONSE2: Expected FLG=4
        5. HIOC_LOCK_STEP3: FLG=5, MSG=ConfirmationID(CC=55), VALUE=0
        6. HIOC_LOCK_RESPONSE3: Expected FLG=6, MSG=7500000 (success)
        """
        try:
            self._report_progress("Starting HIOC lock sequence (CC=55)...")
            
            fid_num = int(self.config.fid[1:])
            lock_command_code = self.config.threshold_command_code  # Should be 55
            
            # Validate we have the right command code
            if lock_command_code != 55:
                raise ValueError("Lock sequence requires threshold_command_code=55, got {}".format(lock_command_code))
            
            # Step 1: Function validation
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=1,  # Function validation flag
                msg=2460000 + fid_num,  # FunctionID
                value=0,
                seq=seq
            )
            
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_STEP1, True, challenge_data=challenge_data)
            
            success, response_data = self._wait_for_response(2, challenge_data)  # Expect flag 2
            if not success:
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_RESPONSE1, False, 
                                      error_message="HIOC lock step 1 failed")
                return False
            
            self._update_sequence(response_data['SEQ'])
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_RESPONSE1, True, response_data=response_data)
            
            if self.abort_requested:
                return False
            
            # Step 2: Lock command
            seq = self._get_next_sequence()
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=3,  # Command flag
                msg=3460000 + lock_command_code,  # CommandID: 3460055
                value=0,  # No value for lock
                seq=seq
            )
            
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_STEP2, True, challenge_data=challenge_data)
            
            success, response_data = self._wait_for_response(4, challenge_data)  # Expect flag 4
            if not success:
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_RESPONSE2, False, 
                                      error_message="HIOC lock step 2 failed")
                return False
            
            self._update_sequence(response_data['SEQ'])
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_RESPONSE2, True, response_data=response_data)
            
            if self.abort_requested:
                return False
            
            # Step 3: Confirmation
            seq = self._get_next_sequence()
            confirmation_id = 4000000 + fid_num * 100 + lock_command_code  # ConfirmationID with CC=55
            challenge_data = self._write_challenge_data(
                ctr=self.config.controller_id,
                flg=5,  # Confirmation flag
                msg=confirmation_id,
                value=0,  # No value for confirmation
                seq=seq
            )
            
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_STEP3, True, challenge_data=challenge_data)
            
            success, response_data = self._wait_for_response(6, challenge_data)  # Expect success flag
            if success and response_data['MSG'] == 7500000:  # SuccessID
                self._update_sequence(response_data['SEQ'])
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_RESPONSE3, True, response_data=response_data)
                self._report_progress("✓ HIOC lock sequence completed successfully")
                return True
            else:
                # Check for abort codes
                abort_msg = {
                    9000000: "Controller abort",
                    9100000: "User abort", 
                    9300000: "Timeout abort"
                }.get(response_data.get('MSG', 0), "Unknown abort: {}".format(response_data.get('MSG', 'N/A')))
                
                self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_RESPONSE3, False, 
                                      response_data=response_data, error_message=abort_msg)
                return False
                
        except Exception as e:
            self._log_hiocwsup_step(HIOCwSUPStep.HIOC_LOCK_STEP3, False, error_message=str(e))
            return False


# Example usage for integration
def create_example_hiocwsup_operator():
    """Example of how to create and use HIOCwSUPOperator"""
    
    def progress_callback(message: str):
        print("Progress: {}".format(message))
    
    # Note: In real usage, client would be provided from main_gui
    from opcua import Client
    client = Client("opc.tcp://localhost:4840")
    # client.connect()  # Connection managed by main_gui
    
    # Example configuration for unlock operation
    config = HIOCOperationConfig(
        client=client,
        controller_id=1464099,  # CG1
        fid="F3",
        operation_type=HIOCOperationType.THRESHOLD,  # Placeholder type
        threshold_command_code=50,  # Unlock command
        threshold_value=0x12345678,  # CRC32 value
        progress_callback=progress_callback
    )
    
    operator = HIOCwSUPOperator(config)
    
    # Execute unlock sequence
    success = operator.perform_unlock_sequence(0x12345678)
    
    if not success:
        print("\nAbort Analysis:")
        print(operator.get_abort_analysis())
    
    print("\nOperation Trace:")
    print(operator.get_operation_trace())
    
    return operator