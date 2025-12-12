#!/usr/bin/env python3
"""
Armor streaming tests for PGPy.
Tests streaming ASCII armor encoding/decoding with incremental CRC24.
"""

import os
import sys
import hashlib

# Add parent directory to path to import pgpy
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

import pgpy
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm, PubKeyAlgorithm, KeyFlags, HashAlgorithm
from pgpy.types import StreamingArmor


def test_crc24_accuracy():
    """Test that incremental CRC24 matches traditional CRC24."""
    print("\n=== Test 1: CRC24 Accuracy ===")
    
    test_data_sets = [
        b"Short test",
        b"A" * 1000,
        b"Test data " * 100,
        bytes(range(256)),  # All byte values
        b"\x00" * 500,  # All zeros
        b"\xff" * 500,  # All ones
    ]
    
    for i, test_data in enumerate(test_data_sets, 1):
        print(f"\nTest case {i}: {len(test_data)} bytes")
        
        # Traditional CRC24 (from Armorable)
        traditional_crc = pgpy.PGPMessage.crc24(test_data)
        
        # Streaming CRC24
        armor = StreamingArmor()
        armor._update_crc24(test_data)
        streaming_crc = armor.crc
        
        print(f"  Traditional CRC24: 0x{traditional_crc:06X}")
        print(f"  Streaming CRC24:   0x{streaming_crc:06X}")
        
        if traditional_crc == streaming_crc:
            print(f"  ✓ PASS")
        else:
            print(f"  ✗ FAIL - CRC24 mismatch!")
            return False
    
    print("\n✓ CRC24 accuracy test PASSED!")
    return True


def test_armor_encoding_format():
    """Test that armor encoding produces correct format."""
    print("\n=== Test 2: Armor Encoding Format ===")
    
    test_data = b"Test message content"
    
    # Create a simple message
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.Uncompressed)
    
    # Get armored output
    armored_lines = []
    for line in msg.to_armored_stream(chunk_size=1024):
        armored_lines.append(line)
    
    armored_text = ''.join(armored_lines)
    
    print(f"Armored output ({len(armored_text)} chars):")
    print(armored_text[:200] + "..." if len(armored_text) > 200 else armored_text)
    
    # Check format
    checks = [
        ("Has BEGIN header", armored_text.startswith("-----BEGIN PGP")),
        ("Has END footer", "-----END PGP" in armored_text),
        ("Has CRC24 line", "\n=" in armored_text),
        ("Has empty line after header", "\n\n" in armored_text),
    ]
    
    all_pass = True
    for check_name, result in checks:
        status = "✓" if result else "✗"
        print(f"  {status} {check_name}")
        if not result:
            all_pass = False
    
    # Check line lengths (should be ≤64 chars for body lines)
    body_started = False
    for line in armored_lines:
        line = line.rstrip('\n')
        if body_started and line and not line.startswith('=') and not line.startswith('-----'):
            if len(line) > 64:
                print(f"  ✗ Line too long: {len(line)} chars")
                all_pass = False
        if line == '':
            body_started = True
    
    if all_pass:
        print("\n✓ Armor encoding format test PASSED!")
    else:
        print("\n✗ Armor encoding format test FAILED!")
    
    return all_pass


def test_armor_round_trip():
    """Test armor encode → decode round trip."""
    print("\n=== Test 3: Armor Round Trip ===")
    
    test_data = b"Round trip test data " * 100
    passphrase = "test_armor"
    
    print(f"Original data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"Original hash: {original_hash[:16]}...")
    
    # Create and encrypt message
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.Uncompressed)
    encrypted = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    # Armor in streaming mode
    print("\nArmoring in streaming mode...")
    armored_lines = []
    for line in encrypted.to_armored_stream(chunk_size=1024):
        armored_lines.append(line)
    
    print(f"Armored: {len(armored_lines)} lines, {sum(len(l) for l in armored_lines)} chars")
    
    # Dearmor in streaming mode
    print("Dearmoring in streaming mode...")
    def line_iterator():
        for line in armored_lines:
            yield line
    
    try:
        dearmored_msg = pgpy.PGPMessage.from_armored_stream(line_iterator())
    except ValueError as e:
        print(f"  ✗ FAIL - Dearmoring failed: {e}")
        return False
    
    # Decrypt
    print("Decrypting...")
    decrypted = dearmored_msg.decrypt(passphrase)
    
    # Extract content
    if hasattr(decrypted.message, '_contents'):
        final_data = bytes(decrypted.message._contents)
    elif isinstance(decrypted.message, bytes):
        final_data = decrypted.message
    elif isinstance(decrypted.message, str):
        final_data = decrypted.message.encode('utf-8')
    else:
        final_data = bytes(decrypted.message)
    
    final_hash = hashlib.sha256(final_data).hexdigest()
    
    print(f"Final data: {len(final_data)} bytes")
    print(f"Final hash: {final_hash[:16]}...")
    
    if final_hash == original_hash and final_data == test_data:
        print("\n✓ Armor round trip test PASSED!")
        return True
    else:
        print("\n✗ Armor round trip test FAILED!")
        return False


def test_traditional_vs_streaming_armor():
    """Test that traditional and streaming armor produce compatible results."""
    print("\n=== Test 4: Traditional vs Streaming Armor ===")
    
    test_data = b"Compatibility test" * 50
    passphrase = "compat_test"
    
    print(f"Test data: {len(test_data)} bytes")
    
    # Create and encrypt message
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.Uncompressed)
    encrypted = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    # Traditional armor (using str())
    print("\nTraditional armor...")
    traditional_armored = str(encrypted)
    print(f"  {len(traditional_armored)} chars")
    
    # Streaming armor
    print("Streaming armor...")
    streaming_lines = []
    for line in encrypted.to_armored_stream(chunk_size=512):
        streaming_lines.append(line)
    streaming_armored = ''.join(streaming_lines)
    print(f"  {len(streaming_armored)} chars")
    
    # Both should decrypt successfully
    print("\nDecrypting traditional armor...")
    trad_result = pgpy.PGPMessage.from_blob(traditional_armored)
    trad_msg = trad_result[0] if isinstance(trad_result, tuple) else trad_result
    trad_decrypted = trad_msg.decrypt(passphrase)
    
    # Extract data safely
    if hasattr(trad_decrypted.message, '_contents'):
        trad_data = bytes(trad_decrypted.message._contents)
    elif isinstance(trad_decrypted.message, bytes):
        trad_data = trad_decrypted.message
    elif isinstance(trad_decrypted.message, str):
        trad_data = trad_decrypted.message.encode('utf-8')
    else:
        trad_data = bytes(str(trad_decrypted.message), 'utf-8')
    
    print("Decrypting streaming armor...")
    def line_iter():
        for line in streaming_lines:
            yield line
    stream_msg = pgpy.PGPMessage.from_armored_stream(line_iter())
    stream_decrypted = stream_msg.decrypt(passphrase)
    
    # Extract data safely
    if hasattr(stream_decrypted.message, '_contents'):
        stream_data = bytes(stream_decrypted.message._contents)
    elif isinstance(stream_decrypted.message, bytes):
        stream_data = stream_decrypted.message
    elif isinstance(stream_decrypted.message, str):
        stream_data = stream_decrypted.message.encode('utf-8')
    else:
        stream_data = bytes(str(stream_decrypted.message), 'utf-8')
    
    # Compare
    trad_hash = hashlib.sha256(trad_data).hexdigest()
    stream_hash = hashlib.sha256(stream_data).hexdigest()
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    print(f"\nOriginal hash:    {original_hash[:16]}...")
    print(f"Traditional hash: {trad_hash[:16]}...")
    print(f"Streaming hash:   {stream_hash[:16]}...")
    
    if original_hash == trad_hash == stream_hash:
        print("\n✓ Traditional vs streaming armor test PASSED!")
        return True
    else:
        print("\n✗ Traditional vs streaming armor test FAILED!")
        return False


def test_key_armor_streaming():
    """Test armor streaming with keys."""
    print("\n=== Test 5: Key Armor Streaming ===")
    
    # Generate key
    print("Generating RSA key pair...")
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new('Test User', email='test@example.com')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256])
    
    # Armor key in streaming mode
    print("\nArmoring key in streaming mode...")
    armored_lines = []
    for line in key.to_armored_stream(chunk_size=1024):
        armored_lines.append(line)
    
    print(f"Armored: {len(armored_lines)} lines")
    
    # Dearmor key in streaming mode
    print("Dearmoring key in streaming mode...")
    def line_iterator():
        for line in armored_lines:
            yield line
    
    try:
        dearmored_result = pgpy.PGPKey.from_armored_stream(line_iterator())
        dearmored_key = dearmored_result[0] if isinstance(dearmored_result, tuple) else dearmored_result
    except ValueError as e:
        print(f"  ✗ FAIL - Dearmoring failed: {e}")
        return False
    
    # Compare fingerprints
    original_fp = key.fingerprint
    dearmored_fp = dearmored_key.fingerprint
    
    print(f"\nOriginal fingerprint:  {original_fp}")
    print(f"Dearmored fingerprint: {dearmored_fp}")
    
    if original_fp == dearmored_fp:
        print("\n✓ Key armor streaming test PASSED!")
        return True
    else:
        print("\n✗ Key armor streaming test FAILED!")
        return False


def test_large_data_armor():
    """Test armor streaming with large data."""
    print("\n=== Test 6: Large Data Armor Streaming ===")
    
    # Generate 5MB of data
    data_size_mb = 5
    print(f"Generating {data_size_mb}MB of test data...")
    test_data = b"X" * (data_size_mb * 1024 * 1024)
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"Original hash: {original_hash[:16]}...")
    
    passphrase = "large_armor_test"
    
    # Encrypt
    print("Encrypting...")
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.ZIP)
    encrypted = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    # Armor in streaming mode
    print("Armoring in streaming mode...")
    armored_lines = []
    line_count = 0
    for line in encrypted.to_armored_stream(chunk_size=65536):
        armored_lines.append(line)
        line_count += 1
    
    print(f"  Generated {line_count} lines")
    
    # Dearmor in streaming mode
    print("Dearmoring in streaming mode...")
    def line_iterator():
        for line in armored_lines:
            yield line
    
    dearmored_msg = pgpy.PGPMessage.from_armored_stream(line_iterator())
    
    # Decrypt
    print("Decrypting...")
    decrypted = dearmored_msg.decrypt(passphrase)
    
    # Extract and verify
    if hasattr(decrypted.message, '_contents'):
        final_data = bytes(decrypted.message._contents)
    elif isinstance(decrypted.message, bytes):
        final_data = decrypted.message
    elif isinstance(decrypted.message, str):
        final_data = decrypted.message.encode('utf-8')
    else:
        final_data = bytes(str(decrypted.message), 'utf-8')
    
    final_hash = hashlib.sha256(final_data).hexdigest()
    
    print(f"Final hash: {final_hash[:16]}...")
    print(f"Data size: {len(final_data)} bytes")
    
    if final_hash == original_hash and len(final_data) == len(test_data):
        print(f"\n✓ {data_size_mb}MB armor streaming test PASSED!")
        return True
    else:
        print(f"\n✗ {data_size_mb}MB armor streaming test FAILED!")
        return False


def test_crc24_verification():
    """Test that CRC24 verification catches corruption."""
    print("\n=== Test 7: CRC24 Verification ===")
    
    test_data = b"CRC test data"
    
    # Create message
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.Uncompressed)
    
    # Armor
    armored_lines = []
    for line in msg.to_armored_stream():
        armored_lines.append(line)
    
    # Corrupt a data line (not the CRC line)
    for i, line in enumerate(armored_lines):
        if line and not line.startswith('-----') and not line.startswith('=') and line.strip():
            # Corrupt this line
            armored_lines[i] = line[:-2] + 'XX\n' if line.endswith('\n') else line[:-1] + 'X'
            print(f"Corrupted line {i}")
            break
    
    # Try to dearmor - should fail CRC24 check
    print("Attempting to dearmor corrupted data...")
    def line_iterator():
        for line in armored_lines:
            yield line
    
    try:
        pgpy.PGPMessage.from_armored_stream(line_iterator())
        print("  ✗ FAIL - Corruption not detected!")
        return False
    except ValueError as e:
        # Corruption can be detected either by CRC24 mismatch or base64 decode error
        if "CRC24" in str(e) or "base64" in str(e) or "Invalid" in str(e):
            print(f"  ✓ PASS - Corruption detected: {e}")
            return True
        else:
            print(f"  ✗ FAIL - Wrong error: {e}")
            return False


def main():
    """Run all armor streaming tests."""
    print("=" * 70)
    print("PGPy Armor Streaming Test Suite")
    print("Testing incremental CRC24 and streaming armor encode/decode")
    print("=" * 70)
    
    results = []
    
    try:
        results.append(("CRC24 Accuracy", test_crc24_accuracy()))
        results.append(("Armor Encoding Format", test_armor_encoding_format()))
        results.append(("Armor Round Trip", test_armor_round_trip()))
        results.append(("Traditional vs Streaming", test_traditional_vs_streaming_armor()))
        results.append(("Key Armor Streaming", test_key_armor_streaming()))
        results.append(("Large Data Armor", test_large_data_armor()))
        results.append(("CRC24 Verification", test_crc24_verification()))
        
    except Exception as e:
        print(f"\n✗ Test suite failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name:35s} {status}")
    
    all_passed = all(result[1] for result in results)
    
    print("=" * 70)
    if all_passed:
        print("All armor streaming tests PASSED! ✓")
        print("\nArmor streaming is fully functional!")
        print("- Incremental CRC24 computation works correctly")
        print("- Streaming encode/decode maintains data integrity")
        print("- Compatible with traditional armor methods")
        print("- Works with large files (constant memory)")
        return 0
    else:
        print("Some tests FAILED! ✗")
        return 1


if __name__ == '__main__':
    sys.exit(main())
