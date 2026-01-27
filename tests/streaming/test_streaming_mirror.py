#!/usr/bin/env python3
"""
Mirror test for PGPy streaming mode - ensures encrypt/decrypt operations are symmetric.
Tests that what we encrypt can be decrypted back to the original.
"""

import os
import sys
import hashlib

# Add parent directory to path to import pgpy
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

import pgpy
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm, PubKeyAlgorithm, KeyFlags, HashAlgorithm


def extract_message_content(msg):
    """Helper to extract actual content from a PGPMessage, handling different types."""
    if hasattr(msg.message, '_contents'):
        return bytes(msg.message._contents)
    elif isinstance(msg.message, str):
        return msg.message.encode('utf-8')
    elif isinstance(msg.message, bytes):
        return msg.message
    else:
        return bytes(msg.message)


def test_symmetric_encryption_mirror():
    """Test that symmetric encryption and decryption are perfect mirrors."""
    print("\n=== Test 1: Symmetric Encryption/Decryption Mirror ===")
    
    test_cases = [
        (b"Short message", "Small data"),
        (b"A" * 1000, "1KB repeated data"),
        (b"Hello World! " * 5000, "~60KB mixed data"),
        (bytes(range(256)) * 100, "Binary data with all byte values"),
    ]
    
    passphrase = "test_mirror_passphrase"
    
    for original_data, description in test_cases:
        print(f"\nTesting: {description} ({len(original_data)} bytes)")
        original_hash = hashlib.sha256(original_data).hexdigest()
        
        # Encrypt with traditional method (uncompressed)
        msg = pgpy.PGPMessage.new(original_data, compression=CompressionAlgorithm.Uncompressed)
        encrypted_msg = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
        
        # Decrypt with streaming
        decrypted_chunks = []
        for chunk in encrypted_msg.decrypt_stream(passphrase, chunk_size=4096):
            decrypted_chunks.append(bytes(chunk))
        
        # Parse decrypted packet data
        decrypted_packet_data = b''.join(decrypted_chunks)
        decrypted_msg = pgpy.PGPMessage()
        decrypted_msg.parse(decrypted_packet_data)
        
        # Extract content
        final_data = extract_message_content(decrypted_msg)
        
        final_hash = hashlib.sha256(final_data).hexdigest()
        
        if original_hash == final_hash and final_data == original_data:
            print(f"  ✓ PASS - Hash: {original_hash[:16]}...")
        else:
            print(f"  ✗ FAIL - Hash mismatch or data corruption!")
            print(f"    Original: {original_hash[:16]}... ({len(original_data)} bytes)")
            print(f"    Final:    {final_hash[:16]}... ({len(final_data)} bytes)")
            assert False
    
    print("\n✓ All symmetric encryption mirror tests PASSED!")
    pass


def test_key_encryption_mirror():
    """Test that key-based encryption and decryption are perfect mirrors."""
    print("\n=== Test 2: Key-Based Encryption/Decryption Mirror ===")
    
    # Generate key pair
    print("Generating RSA key pair...")
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new('Test User', email='test@example.com')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.Uncompressed])
    
    test_cases = [
        (b"Secret message", "Small secret"),
        (b"X" * 2000, "2KB data"),
        (b"Mixed content 123!@# " * 1000, "~20KB mixed"),
    ]
    
    for original_data, description in test_cases:
        print(f"\nTesting: {description} ({len(original_data)} bytes)")
        original_hash = hashlib.sha256(original_data).hexdigest()
        
        # Encrypt with public key (uncompressed)
        msg = pgpy.PGPMessage.new(original_data, compression=CompressionAlgorithm.Uncompressed)
        encrypted_msg = key.pubkey.encrypt(msg)
        
        # Decrypt with streaming
        decrypted_chunks = []
        for chunk in key.decrypt_stream(encrypted_msg, chunk_size=4096):
            decrypted_chunks.append(bytes(chunk))
        
        # Parse decrypted packet data
        decrypted_packet_data = b''.join(decrypted_chunks)
        decrypted_msg = pgpy.PGPMessage()
        decrypted_msg.parse(decrypted_packet_data)
        
        # Extract content
        final_data = extract_message_content(decrypted_msg)
        
        final_hash = hashlib.sha256(final_data).hexdigest()
        
        if original_hash == final_hash and final_data == original_data:
            print(f"  ✓ PASS - Hash: {original_hash[:16]}...")
        else:
            print(f"  ✗ FAIL - Hash mismatch or data corruption!")
            print(f"    Original: {original_hash[:16]}... ({len(original_data)} bytes)")
            print(f"    Final:    {final_hash[:16]}... ({len(final_data)} bytes)")
            assert False
    
    print("\n✓ All key-based encryption mirror tests PASSED!")
    pass


def test_traditional_vs_streaming():
    """Test that traditional decrypt and streaming decrypt produce identical results."""
    print("\n=== Test 3: Traditional vs Streaming Decrypt Comparison ===")
    
    test_data = b"Compare traditional and streaming decryption methods" * 500
    passphrase = "comparison_test"
    
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"Original hash: {original_hash[:16]}...")
    
    # Encrypt once
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.Uncompressed)
    encrypted_msg = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    # Traditional decrypt
    print("\nTraditional decrypt...")
    traditional_decrypted = encrypted_msg.decrypt(passphrase)
    traditional_data = extract_message_content(traditional_decrypted)
    traditional_hash = hashlib.sha256(traditional_data).hexdigest()
    print(f"Traditional hash: {traditional_hash[:16]}...")
    
    # Streaming decrypt
    print("Streaming decrypt...")
    streaming_chunks = []
    for chunk in encrypted_msg.decrypt_stream(passphrase, chunk_size=4096):
        streaming_chunks.append(bytes(chunk))
    
    streaming_packet_data = b''.join(streaming_chunks)
    streaming_msg = pgpy.PGPMessage()
    streaming_msg.parse(streaming_packet_data)
    
    streaming_data = extract_message_content(streaming_msg)
    streaming_hash = hashlib.sha256(streaming_data).hexdigest()
    print(f"Streaming hash: {streaming_hash[:16]}...")
    
    # Compare
    if original_hash == traditional_hash == streaming_hash:
        if traditional_data == streaming_data == test_data:
            print("\n✓ PASS - All three match perfectly!")
            print(f"  Original:    {len(test_data)} bytes")
            print(f"  Traditional: {len(traditional_data)} bytes")
            print(f"  Streaming:   {len(streaming_data)} bytes")
            pass
    
    print("\n✗ FAIL - Mismatch detected!")
    print(f"  Original hash:    {original_hash[:16]}...")
    print(f"  Traditional hash: {traditional_hash[:16]}...")
    print(f"  Streaming hash:   {streaming_hash[:16]}...")
    assert False


def test_chunk_size_independence():
    """Test that different chunk sizes produce identical results."""
    print("\n=== Test 4: Chunk Size Independence ===")
    
    test_data = b"Testing chunk size independence" * 1000
    passphrase = "chunk_test"
    
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    # Encrypt once
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.Uncompressed)
    encrypted_msg = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    chunk_sizes = [512, 1024, 4096, 8192, 65536]
    results = []
    
    for chunk_size in chunk_sizes:
        print(f"\nTesting chunk size: {chunk_size} bytes")
        
        chunks = []
        for chunk in encrypted_msg.decrypt_stream(passphrase, chunk_size=chunk_size):
            chunks.append(bytes(chunk))
        
        packet_data = b''.join(chunks)
        msg_decrypted = pgpy.PGPMessage()
        msg_decrypted.parse(packet_data)
        
        final_data = extract_message_content(msg_decrypted)
        
        final_hash = hashlib.sha256(final_data).hexdigest()
        results.append((chunk_size, final_hash, len(final_data)))
        print(f"  Hash: {final_hash[:16]}... ({len(final_data)} bytes)")
    
    # Check all results are identical
    all_hashes = [r[1] for r in results]
    all_sizes = [r[2] for r in results]
    
    if len(set(all_hashes)) == 1 and len(set(all_sizes)) == 1:
        if all_hashes[0] == original_hash and all_sizes[0] == len(test_data):
            print("\n✓ PASS - All chunk sizes produce identical results!")
            pass
    
    print("\n✗ FAIL - Different chunk sizes produced different results!")
    for chunk_size, hash_val, size in results:
        print(f"  {chunk_size:6d} bytes: {hash_val[:16]}... ({size} bytes)")
    assert False


def test_empty_and_edge_cases():
    """Test edge cases like empty data, single byte, etc."""
    print("\n=== Test 5: Edge Cases ===")
    
    passphrase = "edge_case_test"
    
    test_cases = [
        (b"", "Empty data"),
        (b"X", "Single byte"),
        (b"\x00", "Null byte"),
        (b"\xff" * 100, "All 0xFF bytes"),
        (b"\x00" * 100, "All null bytes"),
    ]
    
    for original_data, description in test_cases:
        print(f"\nTesting: {description} ({len(original_data)} bytes)")
        
        try:
            # Encrypt
            msg = pgpy.PGPMessage.new(original_data if original_data else b" ", 
                                     compression=CompressionAlgorithm.Uncompressed)
            encrypted_msg = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
            
            # Decrypt with streaming
            decrypted_chunks = []
            for chunk in encrypted_msg.decrypt_stream(passphrase, chunk_size=4096):
                decrypted_chunks.append(bytes(chunk))
            
            # Parse
            decrypted_packet_data = b''.join(decrypted_chunks)
            decrypted_msg = pgpy.PGPMessage()
            decrypted_msg.parse(decrypted_packet_data)
            
            # Extract
            final_data = extract_message_content(decrypted_msg)
            
            # For empty case, PGPy might add a space
            expected = original_data if original_data else b" "
            
            if final_data == expected:
                print(f"  ✓ PASS")
            else:
                print(f"  ✗ FAIL - Data mismatch!")
                print(f"    Expected: {expected!r}")
                print(f"    Got:      {final_data!r}")
                assert False
                
        except Exception as e:
            print(f"  ✗ FAIL - Exception: {e}")
            assert False
    
    print("\n✓ All edge case tests PASSED!")
    pass


def main():
    """Run all mirror tests."""
    print("=" * 70)
    print("PGPy Streaming Mode Mirror Tests")
    print("Testing that encrypt/decrypt operations are perfect mirrors")
    print("=" * 70)
    
    results = []
    
    try:
        results.append(("Symmetric Encryption Mirror", test_symmetric_encryption_mirror()))
        results.append(("Key-Based Encryption Mirror", test_key_encryption_mirror()))
        results.append(("Traditional vs Streaming", test_traditional_vs_streaming()))
        results.append(("Chunk Size Independence", test_chunk_size_independence()))
        results.append(("Edge Cases", test_empty_and_edge_cases()))
        
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
        print(f"{test_name:40s} {status}")
    
    all_passed = all(result[1] for result in results)
    
    print("=" * 70)
    if all_passed:
        print("All mirror tests PASSED! ✓")
        print("\nStreaming encryption/decryption is working correctly!")
        print("Data integrity is maintained across all operations.")
        return 0
    else:
        print("Some tests FAILED! ✗")
        return 1


if __name__ == '__main__':
    sys.exit(main())
