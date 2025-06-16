# HIOC Protocol & GUI Implementation Documentation

## Overview

This document provides complete context for the **HIOC (ITER-specific application layer protocol)** and **HIOCwSUP (HIOC with SUP extension)** implementation, along with the comprehensive GUI control system for ITER's OPC-UA servers.

## Table of Contents

1. [HIOC Protocol Specifications](#hioc-protocol-specifications)
2. [HIOCwSUP Extension](#hiocsup-extension)
3. [GUI Implementation](#gui-implementation)
4. [Technical Details](#technical-details)
5. [Usage Examples](#usage-examples)
6. [Future Development](#future-development)

---

## HIOC Protocol Specifications

### Core Concept
HIOC is a three-step validation protocol for setting configuration parameters on ITER control systems (CG1, CG2, FPIS). It provides a robust challenge-response mechanism for safe parameter modification.

### Supported Systems
- **CG1**: Controller ID 1464099 (F0-F5 functions)
- **CG2**: Controller ID 1464098 (F0-F5 functions) 
- **FPIS**: Limited HIOC support

### Parameter Types
- **HIOC_BO**: Boolean parameters
- **HIOC_TH**: Threshold parameters
- **HIOC_PS**: Structured parameter sets (HIOCwSUP only)

### Browse Paths
- **Challenge**: `['HIOCIn', <fid>, 'STF', <variable>]`
- **Response**: `['HIOCOut', <fid>, 'FTS', <variable>]`
- **HTT Values**: `['HTT', 'TH1']` through `['HTT', 'TH15']`

Where:
- `<fid>`: F0, F1, F2, F3, F4, F5
- `<variable>`: CTR, FLG, MSG, VALUE, SEQ

### Data Types
- **CTR, FLG, MSG, VALUE**: uint32
- **SEQ**: int32 (sequence number)

### Sequence Number Logic
- **Challenge sequences**: Always odd (1, 3, 5, ..., 251, 253)
- **Response sequences**: Always even or 0 (0, 2, 4, ..., 252, 254)
- **Challenge overflow**: 253 → 1
- **Response overflow**: 254 → 0

### Message ID Formats
- **FunctionID**: 246NNNN (NNNN = fid number)
- **CommandID**: 34600CC (CC = command code)
- **ConfirmationID**: 4NNNNCC (NNNN = fid number, CC = command code)
- **AbortIDs**: 9000000 (Controller), 9100000 (User), 9300000 (Time)
- **SuccessID**: 7500000

### Command Codes (CC)
- **Thresholds**: 1-15
- **Override Set**: 20
- **Override Unset**: 25
- **Disable**: 30
- **Enable**: 35
- **Unlock Parameters**: 50 (HIOCwSUP)
- **Lock Parameters**: 55 (HIOCwSUP)

### Flag Values
- **Function validation**: 1 (threshold/override/disable), 11 (unset/enable)
- **Command**: 3 (threshold/override/disable), 13 (unset/enable)
- **Confirmation**: 5 (threshold/override/disable), 15 (unset/enable)
- **HTT request**: 21
- **HTT response**: 22
- **Abort**: 9
- **Success**: 6

### HIOC Protocol Flow

#### For Threshold Operations:
1. **Auxiliary Step**: Flag=21, MessageID=FunctionID → Response Flag=22 (HTT populated)
2. **User selects threshold** from HTT values (TH1-TH15)
3. **Step 1**: Flag=1, MessageID=FunctionID → Response Flag=2
4. **Step 2**: Flag=3, MessageID=CommandID → Response Flag=4
5. **Step 3**: Flag=5, MessageID=ConfirmationID → Response: SuccessID or AbortID

#### For Other Operations:
1. **Step 1**: Flag=1/11, MessageID=FunctionID → Response Flag=2/12
2. **Step 2**: Flag=3/13, MessageID=CommandID → Response Flag=4/14
3. **Step 3**: Flag=5/15, MessageID=ConfirmationID → Response: SuccessID or AbortID

---

## HIOCwSUP Extension

### Overview
HIOCwSUP extends HIOC to support structured parameter sets (HIOC_PS) with up to 2kB (512 words) of parameter data. Fully backwards compatible with standard HIOC.

### Supported Functions
- **CG1 & CG2**: F0, F3, F4, F5 only
- **Detection**: FIDSize > 1 indicates HIOCwSUP support

### Additional Browse Paths
- **HSUP Challenge**: `['HSUPIn', <fid>, 'CTF', <variable>]`
- **HSUP Response**: `['HSUPOut', <fid>, 'FTC', <variable>]`
- **Buffer Area**: `['CTFSS', <ctfssvar>]` where ctfssvar = CTR, FLG, MSG, VALUE, DSIZE, DATA

### File Format
CSV format: `FIDSize,param1,param2,...,paramN`
- **FIDSize**: Number of parameters (max 511)
- **Parameters**: uint32 values
- **Parsing**: Ignore carriage returns, handle empty values

### CRC32 Calculation
```python
import zlib
buffer = parameters + [nonce]  # Append nonce to parameters
buffer_bytes = b''.join(val.to_bytes(4, byteorder='little') for val in buffer)
crc_result = zlib.crc32(buffer_bytes) & 0xFFFFFFFF
```

### HIOCwSUP Protocol Flow
1. **Nonce Request**: Flag=11, MessageID=FunctionID → Response Flag=12, Value=nonce
2. **CRC32 Calculation**: Over [parameters + nonce] buffer
3. **HIOC 3-Step with Unlock**:
   - Step 1: Function validation
   - Step 2: Unlock (CC=50, Value=CRC32)
   - Step 3: Confirmation
4. **CTFSS Buffer Population**: Store parameters and metadata
5. **HSUP 3-Step Protocol**:
   - HSupStep-1: Function validation
   - HSupStep-2: Command with ConfirmationID
   - HSupStep-3: Final confirmation
6. **Error Recovery**: Lock parameters (CC=55) if HSUP fails after HIOC success

### Independent Sequence Management
HIOCwSUP uses separate sequence tracking for HSUP operations, independent from standard HIOC sequences.

---

## GUI Implementation

### Main Features
- **Multi-server support**: CG1, CG2, FPIS with independent connections
- **Real-time monitoring**: COS, PSOS, IOP status with color-coded displays
- **Dual operation support**: "CG1 & CG2" for synchronized operations
- **Complete HIOC/HIOCwSUP integration**: All protocol variants supported

### GUI Components

#### Server Connection Panel
- Connection status indicators (red/green)
- Toggle connect/disconnect buttons
- Editable server URLs
- Real-time connection monitoring

#### Command Panels
- **COS Commands**: gotoReady, gotoLocal, goNotReady, Initialise, Abort, Execute, PostCheck
- **IOP Commands**: In-Pulse, Out-of-Pulse (FPIS only)
- **HIOC Configuration**: Complete protocol interface

#### Status Monitoring
- **COS States**: OFF, NOT_READY, READY, INITIALISING, EXECUTING, etc. (color-coded)
- **PSOS States**: Real-time operational state display
- **IOP Status**: In-Pulse/Out-of-Pulse indicators
- **PCS WD Threshold**: Current threshold values

#### HIOC Dialog Features
- **Server Selection**: CG1, CG2, or "CG1 & CG2"
- **FID Selection**: F0-F5 with automatic HIOCwSUP detection
- **Operation Types**:
  - Threshold (with HTT value selection)
  - Override Set/Unset
  - Disable/Enable
  - Structured Parameters (HIOCwSUP)
- **File Browser**: CSV parameter file selection with validation
- **Progress Tracking**: Real-time operation status
- **Operation Log**: Detailed challenge/response history
- **Error Handling**: Comprehensive abort and recovery options

### Advanced Features

#### Dual Server Operations
- **HTT Comparison**: Automatic validation that CG1/CG2 have matching threshold tables
- **Sequential Execution**: CG1 first, then CG2 (fail-fast on CG1 errors)
- **Synchronized Confirmation**: Single user confirmation for both systems

#### HIOCwSUP Integration
- **Automatic Detection**: FIDSize-based capability checking
- **Dynamic UI**: Radio button enabled/disabled based on FID support
- **File Validation**: Real-time CSV parsing and error reporting
- **Recovery Options**: Automatic lock parameter offering on partial failures

#### Error Recovery
- **Timeout Handling**: 10-second timeouts with retry options
- **Abort Operations**: User or system-initiated abort with proper cleanup
- **Operation Logs**: Detailed trace for debugging and audit

---

## Technical Details

### Sequence Management
```python
# Per-server sequence tracking (fixed infinite loop issue)
current_sequences = {'CG1': 1, 'CG2': 1}
last_response_sequences = {'CG1': 0, 'CG2': 0}
hsup_current_sequences = {'CG1': 1, 'CG2': 1}  # Independent HSUP sequences
hsup_last_response_sequences = {'CG1': 0, 'CG2': 0}

# Sequence calculation
if last_response_sequence == 0:
    next_challenge = 1
else:
    next_challenge = last_response_sequence + 1
    if next_challenge > 253:
        next_challenge = 1
```

### OPC-UA Data Type Handling
```python
# Type conversions
controller_id = int(controller_id) & 0xFFFFFFFF  # uint32
flag = int(flag) & 0xFFFFFFFF  # uint32
message_id = int(message_id) & 0xFFFFFFFF  # uint32
value = int(value) & 0xFFFFFFFF  # uint32

# SEQ field (int32)
from opcua import ua
seq_variant = ua.Variant(seq, ua.VariantType.Int32)
seq_node.set_value(seq_variant)
```

### Threading Architecture
- **Main GUI Thread**: UI updates and user interaction
- **Background Monitoring**: 300ms polling for status updates
- **Operation Threads**: Separate threads for HIOC/HIOCwSUP operations
- **Thread Safety**: Proper use of `dialog.after()` for GUI updates

### Error Handling Patterns
```python
# Comprehensive error handling with user feedback
try:
    success = operation()
    if not success:
        update_progress("Operation failed")
        return
except Exception as e:
    update_progress(f"Error: {e}")
    logger.error(f"Detailed error: {e}")
finally:
    operation_in_progress = False
```

---

## Usage Examples

### Basic Threshold Operation
1. Connect to CG1
2. Open HIOC Configuration
3. Select F2, Threshold operation
4. Start operation → HTT request → threshold selection → 3-step HIOC
5. Monitor progress and confirm success

### HIOCwSUP Structured Parameters
1. Connect to CG1
2. Select F3 (HIOCwSUP supported)
3. Choose "Structured Parameters (HIOCwSUP)"
4. Browse and select CSV file (e.g., "5,100,200,300,400,500")
5. Execute: Nonce → CRC32 → HIOC unlock → CTFSS → HSUP 3-step

### Dual Server Operation
1. Connect to both CG1 and CG2
2. Select "CG1 & CG2" server option
3. Choose threshold operation
4. System compares HTT values → user selects threshold → sequential execution

---

## Future Development

### Potential Enhancements
1. **Extended HIOCwSUP Support**: Larger parameter sets, additional data types
2. **Batch Operations**: Multiple parameter changes in single transaction
3. **Configuration Templates**: Saved parameter configurations
4. **Audit Trail**: Comprehensive operation logging and reporting
5. **Additional Systems**: Extension to other ITER control systems
6. **Advanced Error Recovery**: Automatic retry mechanisms
7. **Performance Optimization**: Faster polling, connection pooling

### Known Limitations
1. **HIOCwSUP Dual Operations**: Not yet implemented (single server only)
2. **File Size**: Limited to 512 words (2kB) for structured parameters
3. **Concurrent Operations**: Only one HIOC operation at a time
4. **FID Restrictions**: HIOCwSUP limited to F0, F3, F4, F5

### Integration Points
- **ITER Central Control**: Integration with broader ITER control systems
- **Configuration Management**: Version control for parameter configurations
- **Real-time Monitoring**: Integration with ITER monitoring infrastructure
- **Security**: Enhanced authentication and authorization

---

## Implementation Files

### Core Files
1. **opcua_hioc_control.py**: Main implementation with HIOC/HIOCwSUP protocols
2. **fixed_hioc_script.py**: Per-server sequence management (reference implementation)

### Key Classes
- **HIOCProtocol**: Core protocol implementation
- **HIOCDialog**: GUI dialog for HIOC operations
- **OPCUAController**: Server connection and basic operations management
- **OPCUAControlGUI**: Main application GUI

### Dependencies
- **opcua**: OPC-UA client library
- **tkinter**: GUI framework
- **zlib**: CRC32 calculation
- **threading**: Background operations
- **logging**: Comprehensive logging system

---

## Conclusion

This implementation provides a complete, production-ready interface for ITER's HIOC protocol systems. The combination of robust protocol handling, comprehensive error recovery, and intuitive GUI design makes it suitable for operational use in ITER's control systems.

The modular architecture allows for easy extension and modification, while the comprehensive logging and error handling ensure reliable operation in critical environments.

**Ready for deployment and further development to support ITER's mission of advancing fusion energy research.**