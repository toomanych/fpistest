"""
HIOC SUP Validator
Updated to use HIOCOperator for HTT requests instead of duplicating functionality.
Provides validation for single and dual server operations with proper logging.
"""

from typing import Optional, Dict, Any, Callable, Tuple
from opcua import Client
import logging

# Import HIOCOperator for HTT requests
from hioc_operator import HIOCOperator, HIOCOperationConfig, HIOCOperationType

logger = logging.getLogger(__name__)


class HIOCSUPValidator:
    """
    Validates HIOC/SUP operations using HIOCOperator for HTT requests.
    Handles both single server and dual server validation scenarios.
    """
    
    def __init__(self, cg1_client: Client, cg2_client: Optional[Client] = None, 
                 progress_callback: Optional[Callable[[str], None]] = None,
                 cg1_controller_id: int = 1464099, cg2_controller_id: int = 1464098):
        """
        Initialize validator for single or dual server operations.
        
        Args:
            cg1_client: CG1 OPC-UA client
            cg2_client: CG2 OPC-UA client (None for single server validation)
            progress_callback: Progress callback function (same style as HIOCOperator)
            cg1_controller_id: CG1 controller ID (default: 1464099)
            cg2_controller_id: CG2 controller ID (default: 1464098)
        """
        self.cg1_client = cg1_client
        self.cg2_client = cg2_client
        self.progress_callback = progress_callback
        self.cg1_controller_id = cg1_controller_id
        self.cg2_controller_id = cg2_controller_id
        
        # Validation results - public attributes
        self.htt_match = False              # True if single server or both servers match
        self.fidsize = 0                   # 0=no match/error, 1=HIOC_TH, >1=HIOC_PS
        self.th_val_array = {}             # TH1-TH15 values dict {1: val1, 2: val2, ...}
        
        # Internal state
        self._is_dual_mode = cg2_client is not None
        
    def _report_progress(self, message: str):
        """Report progress to callback (same style as HIOCOperator)"""
        if self.progress_callback:
            self.progress_callback(message)
    
    def validate(self, fid: str) -> bool:
        """
        Perform validation for given FID on configured servers.
        
        Args:
            fid: Function ID (F0, F1, F2, F3, F4, F5)
            
        Returns:
            bool: True if validation successful, False otherwise
            
        Sets attributes:
            - htt_match: True if HTT validation passed
            - fidsize: FIDSize value (0 if error/mismatch)
            - th_val_array: HTT values dict
        """
        try:
            self._report_progress("Starting HTT validation for {}...".format(fid))
            
            if self._is_dual_mode:
                return self._validate_dual_servers(fid)
            else:
                return self._validate_single_server(fid)
                
        except Exception as e:
            self._report_progress("✗ HTT validation failed: {}".format(e))
            logger.error("HTT validation error for {}: {}".format(fid, e))
            self._reset_validation_state()
            return False
    
    def _validate_single_server(self, fid: str) -> bool:
        """Validate single server (CG1)"""
        self._report_progress("Requesting HTT from CG1...")
        
        # Request HTT from CG1 using HIOCOperator
        cg1_htt_success, cg1_fidsize, cg1_htt_values = self._request_htt_from_server(
            self.cg1_client, self.cg1_controller_id, fid, "CG1")
        
        if not cg1_htt_success:
            self._report_progress("✗ CG1 HTT request failed")
            self._reset_validation_state()
            return False
        
        # Single server - always considered a match
        self.htt_match = True
        self.fidsize = cg1_fidsize
        self.th_val_array = cg1_htt_values
        
        self._report_progress("✓ CG1 HTT validation successful")
        self._report_progress("  FIDSize: {}".format(self.fidsize))
        self._report_progress("  Operation type: {}".format(self._get_operation_type_string()))
        
        return True
    
    def _validate_dual_servers(self, fid: str) -> bool:
        """Validate dual servers (CG1 & CG2) with HTT comparison"""
        # Request HTT from both servers
        self._report_progress("Requesting HTT from CG1...")
        cg1_htt_success, cg1_fidsize, cg1_htt_values = self._request_htt_from_server(
            self.cg1_client, self.cg1_controller_id, fid, "CG1")
        
        if not cg1_htt_success:
            self._report_progress("✗ CG1 HTT request failed")
            self._reset_validation_state()
            return False
        
        self._report_progress("Requesting HTT from CG2...")
        cg2_htt_success, cg2_fidsize, cg2_htt_values = self._request_htt_from_server(
            self.cg2_client, self.cg2_controller_id, fid, "CG2")
        
        if not cg2_htt_success:
            self._report_progress("✗ CG2 HTT request failed")
            self._reset_validation_state()
            return False
        
        # Compare FIDSize values
        if cg1_fidsize != cg2_fidsize:
            self._report_progress("✗ FIDSize mismatch: CG1={}, CG2={}".format(cg1_fidsize, cg2_fidsize))
            self._reset_validation_state()
            return False
        
        # Compare HTT values
        htt_mismatches = []
        for i in range(1, 16):  # TH1-TH15
            cg1_val = cg1_htt_values.get(i)
            cg2_val = cg2_htt_values.get(i)
            
            if cg1_val != cg2_val:
                htt_mismatches.append("TH{}: CG1={}, CG2={}".format(i, cg1_val, cg2_val))
        
        if htt_mismatches:
            self._report_progress("✗ HTT value mismatches detected:")
            for mismatch in htt_mismatches[:3]:  # Show first 3 mismatches
                self._report_progress("    {}".format(mismatch))
            if len(htt_mismatches) > 3:
                self._report_progress("    ... and {} more mismatches".format(len(htt_mismatches) - 3))
            self._reset_validation_state()
            return False
        
        # All validations passed
        self.htt_match = True
        self.fidsize = cg1_fidsize  # Both are same due to validation
        self.th_val_array = cg1_htt_values  # Both are same due to validation
        
        self._report_progress("✓ Dual server HTT validation successful")
        self._report_progress("  FIDSize: {} (both servers)".format(self.fidsize))
        self._report_progress("  HTT values: All TH1-TH15 match between CG1 & CG2")
        self._report_progress("  Operation type: {}".format(self._get_operation_type_string()))
        
        return True
    
    def _request_htt_from_server(self, client: Client, controller_id: int, fid: str, 
                                server_name: str) -> Tuple[bool, int, Dict[int, Any]]:
        """
        Request HTT from a single server using HIOCOperator.
        
        Returns:
            tuple: (success, fidsize, htt_values_dict)
        """
        try:
            # Create HIOCOperator configuration for HTT request
            # Use THRESHOLD operation type as placeholder (only HTT request matters)
            config = HIOCOperationConfig(
                client=client,
                controller_id=controller_id,
                fid=fid,
                operation_type=HIOCOperationType.THRESHOLD,
                threshold_command_code=1,  # Dummy value for HTT request
                threshold_value=0,         # Dummy value for HTT request
                timeout_seconds=5.0,       # Shorter timeout for validation
                progress_callback=lambda msg: self._report_progress("{}: {}".format(server_name, msg))
            )
            
            # Create operator and perform HTT request only
            operator = HIOCOperator(config)
            htt_success = operator._perform_htt_request()
            
            if not htt_success:
                logger.warning("HTT request failed for {} on {}".format(fid, server_name))
                return False, 0, {}
            
            # Read FIDSize and HTT values from populated HTT registry
            fidsize = self._read_fidsize(client)
            htt_values = self._read_htt_values(client)
            
            if fidsize is None or not htt_values:
                logger.warning("Failed to read FIDSize or HTT values from {} after HTT request".format(server_name))
                return False, 0, {}
            
            self._report_progress("{}: HTT populated successfully (FIDSize={})".format(server_name, fidsize))
            
            return True, fidsize, htt_values
            
        except Exception as e:
            logger.error("HTT request failed for {} on {}: {}".format(fid, server_name, e))
            return False, 0, {}
    
    def _read_fidsize(self, client: Client) -> Optional[int]:
        """Read FIDSize from HTT registry"""
        try:
            objects = client.get_objects_node()
            fidsize_node = objects.get_child(["1:HTT", "1:FIDSize"])
            fidsize = fidsize_node.get_value()
            return fidsize
        except Exception as e:
            logger.error("Failed to read FIDSize: {}".format(e))
            return None
    
    def _read_htt_values(self, client: Client) -> Dict[int, Any]:
        """Read HTT threshold values (TH1-TH15) from HTT registry"""
        try:
            objects = client.get_objects_node()
            htt_values = {}
            
            for i in range(1, 16):  # TH1-TH15
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
            return {}
    
    def _reset_validation_state(self):
        """Reset validation state to failure/error state"""
        self.htt_match = False
        self.fidsize = 0
        self.th_val_array = {}
    
    def _get_operation_type_string(self) -> str:
        """Get human-readable operation type string"""
        if self.is_hioc_bo():
            return "HIOC_BO (Boolean operations)"
        elif self.is_hioc_th():
            return "HIOC_TH (Threshold operations)"
        elif self.is_hioc_ps():
            return "HIOC_PS (Parameter Set operations - HIOCwSUP)"
        else:
            return "Unknown/Error"
    
    # Helper methods for operation type detection
    def is_hioc_bo(self) -> bool:
        """Returns True if fidsize=0 (HIOC_BO - Boolean operations)"""
        return self.fidsize == 0
    
    def is_hioc_th(self) -> bool:
        """Returns True if fidsize=1 (HIOC_TH - Threshold operations)"""
        return self.fidsize == 1
    
    def is_hioc_ps(self) -> bool:
        """Returns True if fidsize>1 (HIOC_PS - Parameter Set operations)"""
        return self.fidsize > 1
    
    # Convenience methods for validation results
    def get_validation_summary(self) -> str:
        """Get human-readable validation summary"""
        if not self.htt_match:
            return "HTT validation failed - servers incompatible for dual operations"
        
        lines = []
        lines.append("HTT validation successful:")
        lines.append("  Servers: {}".format("CG1 & CG2" if self._is_dual_mode else "CG1"))
        lines.append("  FIDSize: {}".format(self.fidsize))
        lines.append("  Operation type: {}".format(self._get_operation_type_string()))
        
        if self.is_hioc_th():
            valid_thresholds = sum(1 for v in self.th_val_array.values() if v is not None)
            lines.append("  Valid thresholds: {}/15".format(valid_thresholds))
        
        return "\n".join(lines)
    
    def is_validation_successful(self) -> bool:
        """Check if validation was successful"""
        return self.htt_match and self.fidsize >= 0  # Allow fidsize=0 for HIOC_BO
    
    def supports_hiocwsup(self) -> bool:
        """Check if HIOCwSUP (parameter set) operations are supported"""
        return self.is_hioc_ps()


# Example usage for integration with hioc_module.py
def example_usage():
    """Example showing how hioc_module.py should use the updated validator"""
    
    # Mock clients
    from opcua import Client
    cg1_client = Client("opc.tcp://cg1:4840")
    cg2_client = Client("opc.tcp://cg2:4840")
    
    def progress_callback(message: str):
        print("Validation: {}".format(message))
    
    # Single server validation
    validator_single = HIOCSUPValidator(cg1_client, progress_callback=progress_callback)
    if validator_single.validate("F3"):
        print("Single server validation successful")
        print("FIDSize: {}".format(validator_single.fidsize))
        print("Supports HIOCwSUP: {}".format(validator_single.supports_hiocwsup()))
        
        # Use th_val_array directly in threshold selection listbox
        for i, value in validator_single.th_val_array.items():
            if value is not None:
                print("TH{}: {}".format(i, value))
    
    # Dual server validation
    validator_dual = HIOCSUPValidator(cg1_client, cg2_client, progress_callback=progress_callback)
    if validator_dual.validate("F3"):
        print("Dual server validation successful")
        print(validator_dual.get_validation_summary())
        
        # Can proceed with dual HIOCwSUP operation
        if validator_dual.supports_hiocwsup():
            print("Ready for dual HIOCwSUP operation")


# Integration notes for hioc_module.py:
#
# 1. Replace custom HTT request code with HIOCSUPValidator calls:
#    validator = HIOCSUPValidator(cg1_client, cg2_client, self.update_progress)
#    if validator.validate(fid):
#        # Use validator.fidsize, validator.th_val_array, validator.supports_hiocwsup()
#
# 2. Use in on_fid_change():
#    def check_fid_capabilities(self):
#        validator = HIOCSUPValidator(...)
#        if validator.validate(fid) and validator.supports_hiocwsup():
#            self.enable_parameter_set()
#        else:
#            self.disable_parameter_set("Reason from validator")
#
# 3. Use in start_operation():
#    validator = HIOCSUPValidator(...)
#    if not validator.validate(fid):
#        self.update_progress("Validation failed")
#        return
#    # Proceed with operation using validator.th_val_array for threshold selection
