"""
HIOC/SUP Validation Class
Handles HIOC and HIOCwSUP configuration validation between CG1 and CG2 systems.
Independent of COS/PSOS operational states.
"""

from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from opcua import Client
import logging

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Validation result types"""
    SUCCESS = "success"
    MISMATCH = "mismatch"
    ERROR = "error"
    MISSING_DATA = "missing_data"


class HTTComparisonResult:
    """Result of HTT threshold table comparison"""
    def __init__(self, result: ValidationResult, mismatches: List[str] = None, 
                 cg1_htt: Dict[int, Any] = None, cg2_htt: Dict[int, Any] = None, 
                 error_message: Optional[str] = None):
        self.result = result
        self.mismatches = mismatches
        self.cg1_htt = cg1_htt
        self.cg2_htt = cg2_htt
        self.error_message = error_message


class FIDSizeComparisonResult:
    """Result of FIDSize comparison for HIOCwSUP capability"""
    def __init__(self, result: ValidationResult, fid: str, cg1_fidsize: Optional[int] = None, 
                 cg2_fidsize: Optional[int] = None, both_support_sup: bool = False, 
                 error_message: Optional[str] = None):
        self.result = result
        self.fid = fid
        self.cg1_fidsize = cg1_fidsize
        self.cg2_fidsize = cg2_fidsize
        self.both_support_sup = both_support_sup
        self.error_message = error_message


class ControllerIDValidationResult:
    """Result of controller ID validation"""
    def __init__(self, result: ValidationResult, cg1_expected: int = 1464099, 
                 cg2_expected: int = 1464098, cg1_actual: Optional[int] = None, 
                 cg2_actual: Optional[int] = None, error_message: Optional[str] = None):
        self.result = result
        self.cg1_expected = cg1_expected
        self.cg2_expected = cg2_expected
        self.cg1_actual = cg1_actual
        self.cg2_actual = cg2_actual
        self.error_message = error_message


class HIOCSUPValidator:
    """
    Handles HIOC and HIOCwSUP configuration validation between CG1 and CG2 systems.
    Focuses on parameter configuration compatibility, independent of operational states.
    """
    
    def __init__(self, cg1_client: Optional[Client] = None, cg2_client: Optional[Client] = None):
        self.cg1_client = cg1_client
        self.cg2_client = cg2_client
        
        # Expected controller IDs
        self.expected_controller_ids = {
            'CG1': 1464099,
            'CG2': 1464098
        }

    def set_clients(self, cg1_client: Client, cg2_client: Client):
        """Set the OPC-UA clients for CG1 and CG2"""
        self.cg1_client = cg1_client
        self.cg2_client = cg2_client

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
                    logger.warning("Failed to read TH{}: {}".format(i, e))
                    htt_values[i] = None
            
            return htt_values
            
        except Exception as e:
            logger.error("Failed to read HTT values: {}".format(e))
            return None

    def read_fidsize(self, client: Client, fid: str) -> Optional[int]:
        """Read FIDSize for a given FID from common HTT registry (HTT must be populated first)"""
        try:
            objects = client.get_objects_node()
            # HTT is common registry populated after Flag=21→22 sequence
            fidsize_node = objects.get_child(["1:HTT", "1:FIDSize"])  # Common FIDSize
            fidsize = fidsize_node.get_value()
            return fidsize
            
        except Exception as e:
            logger.error("Failed to read FIDSize for {}: {}".format(fid, e))
            return None

    def compare_htt_tables(self) -> HTTComparisonResult:
        """Compare HTT threshold tables between CG1 and CG2"""
        if not self.cg1_client or not self.cg2_client:
            return HTTComparisonResult(
                result=ValidationResult.ERROR,
                error_message="CG1 or CG2 client not available"
            )
        
        try:
            # Read HTT values from both systems
            cg1_htt = self.read_htt_values(self.cg1_client)
            cg2_htt = self.read_htt_values(self.cg2_client)
            
            if not cg1_htt or not cg2_htt:
                return HTTComparisonResult(
                    result=ValidationResult.MISSING_DATA,
                    cg1_htt=cg1_htt,
                    cg2_htt=cg2_htt,
                    error_message="Failed to read HTT values from one or both systems"
                )
            
            # Compare threshold values
            mismatches = []
            for i in range(1, 16):
                cg1_val = cg1_htt.get(i)
                cg2_val = cg2_htt.get(i)
                
                if cg1_val != cg2_val:
                    mismatches.append("TH{}: CG1={}, CG2={}".format(i, cg1_val, cg2_val))
            
            if mismatches:
                logger.warning("HTT mismatches found: {}".format('; '.join(mismatches)))
                return HTTComparisonResult(
                    result=ValidationResult.MISMATCH,
                    mismatches=mismatches,
                    cg1_htt=cg1_htt,
                    cg2_htt=cg2_htt
                )
            
            logger.info("HTT values match between CG1 and CG2")
            return HTTComparisonResult(
                result=ValidationResult.SUCCESS,
                cg1_htt=cg1_htt,
                cg2_htt=cg2_htt
            )
            
        except Exception as e:
            return HTTComparisonResult(
                result=ValidationResult.ERROR,
                error_message="Error during HTT comparison: {}".format(e)
            )

    def compare_fidsize_capability(self, fid: str) -> FIDSizeComparisonResult:
        """Compare FIDSize for HIOCwSUP capability between CG1 and CG2"""
        if not self.cg1_client or not self.cg2_client:
            return FIDSizeComparisonResult(
                result=ValidationResult.ERROR,
                fid=fid,
                error_message="CG1 or CG2 client not available"
            )
        
        try:
            # Read FIDSize from both systems
            cg1_fidsize = self.read_fidsize(self.cg1_client, fid)
            cg2_fidsize = self.read_fidsize(self.cg2_client, fid)
            
            if cg1_fidsize is None or cg2_fidsize is None:
                return FIDSizeComparisonResult(
                    result=ValidationResult.MISSING_DATA,
                    fid=fid,
                    cg1_fidsize=cg1_fidsize,
                    cg2_fidsize=cg2_fidsize,
                    error_message="Failed to read FIDSize{} from one or both systems".format(fid)
                )
            
            # Check if both support SUP (FIDSize > 1)
            cg1_supports_sup = cg1_fidsize > 1
            cg2_supports_sup = cg2_fidsize > 1
            both_support_sup = cg1_supports_sup and cg2_supports_sup
            
            if cg1_fidsize != cg2_fidsize:
                return FIDSizeComparisonResult(
                    result=ValidationResult.MISMATCH,
                    fid=fid,
                    cg1_fidsize=cg1_fidsize,
                    cg2_fidsize=cg2_fidsize,
                    both_support_sup=both_support_sup
                )
            
            logger.info("FIDSize{} matches between CG1 and CG2: {}".format(fid, cg1_fidsize))
            return FIDSizeComparisonResult(
                result=ValidationResult.SUCCESS,
                fid=fid,
                cg1_fidsize=cg1_fidsize,
                cg2_fidsize=cg2_fidsize,
                both_support_sup=both_support_sup
            )
            
        except Exception as e:
            return FIDSizeComparisonResult(
                result=ValidationResult.ERROR,
                fid=fid,
                error_message="Error during FIDSize comparison: {}".format(e)
            )

    def validate_controller_ids(self) -> ControllerIDValidationResult:
        """Validate that we're connected to the correct controller IDs"""
        # Note: This would require reading the actual controller ID from the servers
        # The implementation depends on how controller IDs are exposed in OPC-UA
        # For now, this is a placeholder that could be implemented if the controller
        # ID is available as a readable node
        
        try:
            # This is a placeholder - actual implementation would read controller IDs
            # from OPC-UA nodes if they're exposed
            
            return ControllerIDValidationResult(
                result=ValidationResult.SUCCESS,
                cg1_actual=self.expected_controller_ids['CG1'],  # Placeholder
                cg2_actual=self.expected_controller_ids['CG2']   # Placeholder
            )
            
        except Exception as e:
            return ControllerIDValidationResult(
                result=ValidationResult.ERROR,
                error_message="Error during controller ID validation: {}".format(e)
            )

    def validate_for_dual_hioc_operation(self, fid: str = None) -> Dict[str, Any]:
        """Comprehensive validation for dual HIOC operations"""
        validation_results = {}
        
        # Always check HTT comparison for HIOC operations
        validation_results['htt_comparison'] = self.compare_htt_tables()
        
        # If FID specified, check FIDSize compatibility for potential SUP operations
        if fid:
            validation_results['fidsize_comparison'] = self.compare_fidsize_capability(fid)
        
        # Determine overall validation result
        all_successful = all(
            result.result == ValidationResult.SUCCESS 
            for result in validation_results.values()
        )
        
        validation_results['overall_success'] = all_successful
        
        return validation_results

    def get_htt_mismatch_summary(self, htt_result: HTTComparisonResult) -> str:
        """Get formatted summary of HTT mismatches for display"""
        if htt_result.result != ValidationResult.MISMATCH or not htt_result.mismatches:
            return "No HTT mismatches found"
        
        summary = "HTT threshold values don't match between CG1 and CG2:\n\n"
        summary += "\n".join(htt_result.mismatches)
        summary += "\n\nDual operations cannot proceed with mismatched thresholds."
        
        return summary

    def get_validation_summary(self, validation_results: Dict[str, Any]) -> str:
        """Get formatted summary of all validation results"""
        summary_lines = ["Dual Operation Validation Summary:", "=" * 40]
        
        for check_name, result in validation_results.items():
            if check_name == 'overall_success':
                continue
                
            if hasattr(result, 'result'):
                status = "✓" if result.result == ValidationResult.SUCCESS else "✗"
                summary_lines.append(f"{status} {check_name.replace('_', ' ').title()}: {result.result.value}")
                
                if result.result != ValidationResult.SUCCESS and hasattr(result, 'error_message') and result.error_message:
                    summary_lines.append(f"  Error: {result.error_message}")
        
        overall_status = "✓ PASSED" if validation_results.get('overall_success') else "✗ FAILED"
        summary_lines.append(f"\nOverall Result: {overall_status}")
        
        return "\n".join(summary_lines)


def create_example_validator(cg1_client: Client, cg2_client: Client):
    """Example of how to create and use HIOCSUPValidator"""
    
    validator = HIOCSUPValidator(cg1_client, cg2_client)
    
    # Check HTT compatibility before dual threshold operation
    htt_result = validator.compare_htt_tables()
    if htt_result.result != ValidationResult.SUCCESS:
        print("HTT validation failed:")
        print(validator.get_htt_mismatch_summary(htt_result))
        return False
    
    # Check if both systems support SUP for a specific FID
    fidsize_result = validator.compare_fidsize_capability('F3')
    if fidsize_result.both_support_sup:
        print(f"Both systems support HIOCwSUP for {fidsize_result.fid}")
    
    # Comprehensive validation for dual operation
    validation_results = validator.validate_for_dual_hioc_operation('F3')
    print(validator.get_validation_summary(validation_results))
    
    return validation_results['overall_success']
