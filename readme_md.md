# ITER OPC-UA Control System

Complete GUI application for ITER's OPC-UA control systems with HIOC/HIOCwSUP, COS/PSOS, and IOP support.

## Project Structure

```
iter-opcua-control/
├── main_gui.py              # Main GUI application (entry point)
├── hioc_module.py           # HIOC dialog and GUI integration
├── hioc_operator.py         # Core HIOC protocol operator
├── sup_operator.py          # HIOCwSUP (SUP) protocol operator
├── hioc_sup_validator.py    # Validation for dual CG1/CG2 operations
├── cos_operator.py          # COS/PSOS operations for CG systems
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Features

### COS/PSOS Operations
- **CG1/CG2 Control**: Send COS commands to individual or both systems
- **Real-time Monitoring**: 300ms polling of COS/PSOS states with color-coded display
- **FPIS Integration**: Direct IOP command support for FPIS server

### HIOC Protocol Support
- **Standard HIOC**: Threshold, Override, Disable/Enable operations
- **HIOCwSUP**: Structured parameter operations with CSV file support
- **Dual Operations**: Synchronized CG1 & CG2 operations with validation
- **Progress Tracking**: Real-time operation progress and abort analysis

### Key Capabilities
- **HTT Validation**: Automatic threshold table comparison between CG1/CG2
- **FIDSize Detection**: Automatic HIOCwSUP capability detection
- **Error Recovery**: Comprehensive abort tracing from Step1 to failure point
- **File Support**: Hex CSV parameter files for structured operations

## Installation

1. **Install Python 3.6+** (Compatible with Python 3.6)

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python main_gui.py
   ```

## Usage

### Server Connections
1. **Configure URLs**: Edit server URLs in connection panel (defaults provided)
2. **Connect**: Click Connect buttons for CG1, CG2, and/or FPIS
3. **Monitor Status**: Real-time status updates show connection state

### COS Commands
1. **Select Command**: Click any COS command button (gotoReady, Execute, etc.)
2. **Choose Servers**: Select which servers to send command to
3. **Confirm**: Review and confirm command execution

### HIOC Operations
1. **Open Dialog**: Click "Open HIOC Configuration"
2. **Select Server**: Choose CG1, CG2, or "CG1 & CG2" for dual operations
3. **Choose FID**: Select function ID (F0-F5)
4. **Select Operation**:
   - **Threshold**: HTT request → threshold selection → 3-step HIOC
   - **Override/Disable/Enable**: Direct 3-step HIOC
   - **Parameter Set**: File browser → HIOCwSUP operation (if FIDSize > 1)
5. **Monitor Progress**: Real-time progress and detailed logging
6. **Review Results**: Success confirmation or abort analysis

### Dual Operations
- **Automatic Validation**: HTT comparison and compatibility checks
- **Sequential Execution**: CG1 first, then CG2 if CG1 succeeds
- **Unified Interface**: Single threshold selection for both systems

## Configuration

### Server URLs (Default)
- **CG1**: `opc.tcp://4602tv-cpu-4201.codac.iter.org:4840`
- **CG2**: `opc.tcp://4602tv-cpu-4202.codac.iter.org:4840`  
- **FPIS**: `opc.tcp://4602tv-SRV-5101.codac.iter.org:4840`

### Controller IDs
- **CG1**: 1464099
- **CG2**: 1464098

### Parameter Files
For HIOCwSUP operations, create CSV files with hex values:
```csv
0xB,0x64,0xC8,0x12C,0x190,0x1F4,0x258,0x2BC,0x320,0x384,0x3E8
```
Format: `FIDSize,param1,param2,...,paramN` (all in hex)

## Architecture

### Module Responsibilities
- **main_gui.py**: Main application, server management, status monitoring
- **hioc_module.py**: HIOC dialog, user interface, operation coordination
- **hioc_operator.py**: Core HIOC protocol implementation (HIOC_BO, HIOC_TH)
- **sup_operator.py**: HIOCwSUP protocol implementation (inherits from HIOCOperator)
- **hioc_sup_validator.py**: Dual operation validation (HTT comparison, FIDSize checks)
- **cos_operator.py**: COS/PSOS operations for CG1/CG2 systems

### Key Design Patterns
- **Inheritance**: SUPOperator inherits from HIOCOperator
- **Composition**: HIOC dialog coordinates multiple operators
- **Observer**: Progress callbacks for real-time GUI updates
- **Strategy**: Different operators for different operation types
- **Python 3.6 Compatible**: Uses regular classes instead of dataclasses for maximum compatibility

## Troubleshooting

### Connection Issues
- Verify server URLs and network connectivity
- Check firewall settings for OPC-UA ports (4840)
- Ensure OPC-UA servers are running and accessible

### HIOC Operation Failures
- Review abort analysis in operation log
- Check sequence numbers and controller IDs
- Verify FID support for selected operations

### File Format Errors
- Ensure CSV files use hex format (0x prefix)
- Verify FIDSize matches parameter count + 1
- Check file encoding (UTF-8 recommended)

## Development

### Adding New Operations
1. **Extend HIOCOperationType** in hioc_operator.py
2. **Add command codes** and flag mappings
3. **Update dialog UI** in hioc_module.py
4. **Test thoroughly** with real hardware

### Debugging
- Enable detailed logging: `logging.basicConfig(level=logging.DEBUG)`
- Use operation trace: `operator.get_operation_trace()`
- Monitor OPC-UA traffic with external tools

## License

Developed for ITER Organization. Internal use only.

## Support

For technical support or questions about ITER control systems integration, contact the ITER CODAC team.
