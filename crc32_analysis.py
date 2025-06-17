"""
CRC32 Analysis and Comparison
This file extracts and compares different CRC32 calculation approaches to identify
why the current implementation produces different results from the system.
"""

import ctypes
import zlib


def int_to_bytes(value, length=4):
    """
    Working method from examples - converts integer to byte array.
    Extracts bytes using bit shifts in little-endian order.
    """
    return [(value >> (8 * i)) & 0xFF for i in range(length)]


def working_crc32_method(parameters, nonce):
    """
    CRC32 calculation method that matches the system (from working examples).
    Uses int_to_bytes() and ctypes buffer.
    """
    print("=== WORKING CRC32 METHOD ===")
    
    # Create data_bytes array
    data_bytes = []
    
    # Process each parameter using int_to_bytes
    for param in parameters:
        param_bytes = int_to_bytes(param)
        data_bytes.extend(param_bytes)
        print(f"Parameter 0x{param:08X} -> bytes: {[hex(b) for b in param_bytes]}")
    
    # Add nonce using int_to_bytes
    nonce_bytes = int_to_bytes(nonce)
    data_bytes.extend(nonce_bytes)
    print(f"Nonce 0x{nonce:08X} -> bytes: {[hex(b) for b in nonce_bytes]}")
    
    print(f"Total data_bytes length: {len(data_bytes)}")
    print(f"First 16 bytes: {[hex(b) for b in data_bytes[:16]]}")
    print(f"Last 8 bytes: {[hex(b) for b in data_bytes[-8:]]}")
    
    # Create ctypes buffer
    size = len(data_bytes)
    buffer = (ctypes.c_uint8 * size)(*data_bytes)
    
    # Calculate CRC32
    crc_result = zlib.crc32(buffer) & 0xFFFFFFFF
    
    print(f"CRC32 result: 0x{crc_result:08X} ({crc_result})")
    print()
    
    return crc_result


def current_crc32_method(parameters, nonce):
    """
    Current CRC32 calculation method from sup_operator.py.
    Uses Python's to_bytes() and Python bytes object.
    """
    print("=== CURRENT CRC32 METHOD ===")
    
    # Create buffer: [parameters + nonce]
    buffer = parameters + [nonce]
    print(f"Buffer (uint32 values): {[hex(val) for val in buffer]}")
    
    # Convert to little-endian bytes using Python's method
    buffer_bytes = b''.join(val.to_bytes(4, byteorder='little') for val in buffer)
    
    print(f"Buffer bytes length: {len(buffer_bytes)}")
    print(f"First 16 bytes: {[hex(b) for b in buffer_bytes[:16]]}")
    print(f"Last 8 bytes: {[hex(b) for b in buffer_bytes[-8:]]}")
    
    # Calculate CRC32 using Python bytes
    crc_result = zlib.crc32(buffer_bytes) & 0xFFFFFFFF
    
    print(f"CRC32 result: 0x{crc_result:08X} ({crc_result})")
    print()
    
    return crc_result


def python_bytes_with_ctypes_buffer(parameters, nonce):
    """
    Hybrid approach: Python to_bytes() but with ctypes buffer.
    Tests if the issue is the buffer type or the byte conversion.
    """
    print("=== HYBRID METHOD (Python bytes + ctypes buffer) ===")
    
    # Create buffer using Python's to_bytes
    buffer = parameters + [nonce]
    buffer_bytes = b''.join(val.to_bytes(4, byteorder='little') for val in buffer)
    
    # Convert to ctypes buffer
    data_bytes = list(buffer_bytes)
    size = len(data_bytes)
    ctypes_buffer = (ctypes.c_uint8 * size)(*data_bytes)
    
    print(f"Buffer length: {len(data_bytes)}")
    print(f"First 16 bytes: {[hex(b) for b in data_bytes[:16]]}")
    print(f"Last 8 bytes: {[hex(b) for b in data_bytes[-8:]]}")
    
    # Calculate CRC32 using ctypes buffer
    crc_result = zlib.crc32(ctypes_buffer) & 0xFFFFFFFF
    
    print(f"CRC32 result: 0x{crc_result:08X} ({crc_result})")
    print()
    
    return crc_result


def byte_order_analysis(value):
    """
    Analyze how different methods convert a single uint32 to bytes.
    """
    print(f"=== BYTE ORDER ANALYSIS for 0x{value:08X} ===")
    
    # Method 1: int_to_bytes (working method)
    method1 = int_to_bytes(value)
    print(f"int_to_bytes():        {[hex(b) for b in method1]}")
    
    # Method 2: Python to_bytes little-endian
    method2 = list(value.to_bytes(4, byteorder='little'))
    print(f"to_bytes('little'):    {[hex(b) for b in method2]}")
    
    # Method 3: Python to_bytes big-endian
    method3 = list(value.to_bytes(4, byteorder='big'))
    print(f"to_bytes('big'):       {[hex(b) for b in method3]}")
    
    # Check if they match
    print(f"int_to_bytes == little: {method1 == method2}")
    print(f"int_to_bytes == big:    {method1 == method3}")
    print()


def comprehensive_test():
    """
    Run comprehensive test with sample data to identify the differences.
    """
    print("CRC32 CALCULATION ANALYSIS")
    print("=" * 50)
    
    # Sample test data (similar to what would be used in HIOCwSUP)
    parameters = [0x64, 0xC8, 0x12C, 0x190, 0x1F4, 0x258, 0x2BC, 0x320, 0x384, 0x3E8]
    nonce = 0x12345678
    
    print(f"Test parameters: {[hex(p) for p in parameters]}")
    print(f"Test nonce: 0x{nonce:08X}")
    print()
    
    # Analyze byte order for a few values
    byte_order_analysis(parameters[0])
    byte_order_analysis(parameters[-1])
    byte_order_analysis(nonce)
    
    # Test all methods
    result1 = working_crc32_method(parameters, nonce)
    result2 = current_crc32_method(parameters, nonce)
    result3 = python_bytes_with_ctypes_buffer(parameters, nonce)
    
    print("=== COMPARISON RESULTS ===")
    print(f"Working method:      0x{result1:08X}")
    print(f"Current method:      0x{result2:08X}")
    print(f"Hybrid method:       0x{result3:08X}")
    print()
    
    print("=== ANALYSIS ===")
    if result1 == result2:
        print("✓ Working and current methods match - no issue")
    else:
        print("✗ Working and current methods differ")
        
    if result1 == result3:
        print("✓ Issue is NOT the buffer type (ctypes vs Python bytes)")
    else:
        print("✗ Issue IS the buffer type")
        
    if result2 == result3:
        print("✓ Python bytes and ctypes buffer produce same result")
    else:
        print("✗ Buffer type affects result")
    
    print()
    print("RECOMMENDATION:")
    if result1 != result2:
        if result1 == result3:
            print("- The issue is the byte conversion method, not buffer type")
            print("- Use int_to_bytes() instead of to_bytes()")
        else:
            print("- The issue is the buffer type")
            print("- Use ctypes buffer instead of Python bytes")


if __name__ == "__main__":
    comprehensive_test()
