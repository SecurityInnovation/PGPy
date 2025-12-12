#!/usr/bin/env python3
"""
Complete streaming test - tests compression, decompression, and high-level API.
"""

import os
import sys
import hashlib

# Add parent directory to path to import pgpy
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

import pgpy
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm, PubKeyAlgorithm, KeyFlags, HashAlgorithm


def test_compression_streaming():
    """Test streaming compression and decompression."""
    print("\n=== Test 1: Streaming Compression/Decompression ===")
    
    test_data = b"Compress this data! " * 5000  # ~100KB
    print(f"Original data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    compression_algos = [
        (CompressionAlgorithm.ZIP, "ZIP"),
        (CompressionAlgorithm.ZLIB, "ZLIB"),
        (CompressionAlgorithm.BZ2, "BZ2"),
        (CompressionAlgorithm.Uncompressed, "Uncompressed"),
    ]
    
    for algo, name in compression_algos:
        print(f"\nTesting {name} compression...")
        
        # Compress in streaming mode
        def data_iterator():
            for i in range(0, len(test_data), 8192):
                yield test_data[i:i+8192]
        
        compressed_chunks = []
        for chunk in algo.compress_stream(data_iterator()):
            compressed_chunks.append(chunk)
        
        compressed_data = b''.join(compressed_chunks)
        print(f"  Compressed: {len(compressed_data)} bytes ({len(compressed_data)/len(test_data)*100:.1f}%)")
        
        # Decompress in streaming mode
        def compressed_iterator():
            for i in range(0, len(compressed_data), 4096):
                yield compressed_data[i:i+4096]
        
        decompressed_chunks = []
        for chunk in algo.decompress_stream(compressed_iterator()):
            decompressed_chunks.append(chunk)
        
        decompressed_data = b''.join(decompressed_chunks)
        decompressed_hash = hashlib.sha256(decompressed_data).hexdigest()
        
        if decompressed_hash == original_hash and decompressed_data == test_data:
            print(f"  ✓ PASS - Perfect round-trip")
        else:
            print(f"  ✗ FAIL - Data corruption!")
            return False
    
    print("\n✓ All compression streaming tests PASSED!")
    return True


def test_high_level_api_uncompressed():
    """Test high-level decrypt_to_plaintext_stream with uncompressed data."""
    print("\n=== Test 2: High-Level API (Uncompressed) ===")
    
    test_data = b"High-level streaming API test" * 2000
    passphrase = "highlevel_test"
    
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"Original hash: {original_hash[:16]}...")
    
    # Encrypt (uncompressed)
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.Uncompressed)
    encrypted_msg = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    # Decrypt using high-level API
    print("Decrypting with high-level API...")
    plaintext_chunks = []
    for chunk in encrypted_msg.decrypt_to_plaintext_stream(passphrase, chunk_size=8192):
        plaintext_chunks.append(bytes(chunk))
    
    final_data = b''.join(plaintext_chunks)
    final_hash = hashlib.sha256(final_data).hexdigest()
    
    print(f"Final data: {len(final_data)} bytes")
    print(f"Final hash: {final_hash[:16]}...")
    
    if final_hash == original_hash and final_data == test_data:
        print("✓ PASS - High-level API works perfectly!")
        return True
    else:
        print("✗ FAIL - Data mismatch!")
        print(f"  Expected: {len(test_data)} bytes")
        print(f"  Got: {len(final_data)} bytes")
        return False


def test_high_level_api_compressed():
    """Test high-level decrypt_to_plaintext_stream with compressed data."""
    print("\n=== Test 3: High-Level API (Compressed) ===")
    
    test_data = b"Compressed streaming test! " * 3000
    passphrase = "compressed_test"
    
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"Original hash: {original_hash[:16]}...")
    
    compression_algos = [
        (CompressionAlgorithm.ZIP, "ZIP"),
        (CompressionAlgorithm.ZLIB, "ZLIB"),
        (CompressionAlgorithm.BZ2, "BZ2"),
    ]
    
    for algo, name in compression_algos:
        print(f"\nTesting with {name} compression...")
        
        # Encrypt with compression
        msg = pgpy.PGPMessage.new(test_data, compression=algo)
        encrypted_msg = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
        
        # Decrypt using high-level API (should handle decompression automatically)
        plaintext_chunks = []
        for chunk in encrypted_msg.decrypt_to_plaintext_stream(passphrase, chunk_size=8192):
            plaintext_chunks.append(bytes(chunk))
        
        final_data = b''.join(plaintext_chunks)
        final_hash = hashlib.sha256(final_data).hexdigest()
        
        if final_hash == original_hash and final_data == test_data:
            print(f"  ✓ PASS - {name} decompression works!")
        else:
            print(f"  ✗ FAIL - {name} decompression failed!")
            print(f"    Expected: {len(test_data)} bytes, hash {original_hash[:16]}...")
            print(f"    Got: {len(final_data)} bytes, hash {final_hash[:16]}...")
            return False
    
    print("\n✓ All compressed high-level API tests PASSED!")
    return True


def test_key_based_high_level():
    """Test high-level API with key-based encryption."""
    print("\n=== Test 4: Key-Based High-Level API ===")
    
    # Generate key
    print("Generating RSA key pair...")
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new('Test User', email='test@example.com')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    
    test_data = b"Key-based high-level streaming" * 1000
    print(f"\nTest data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    # Test with both compressed and uncompressed
    for algo, name in [(CompressionAlgorithm.Uncompressed, "Uncompressed"), 
                       (CompressionAlgorithm.ZIP, "ZIP")]:
        print(f"\nTesting with {name}...")
        
        # Encrypt
        msg = pgpy.PGPMessage.new(test_data, compression=algo)
        encrypted_msg = key.pubkey.encrypt(msg)
        
        # Decrypt using high-level API
        plaintext_chunks = []
        for chunk in key.decrypt_to_plaintext_stream(encrypted_msg, chunk_size=8192):
            plaintext_chunks.append(bytes(chunk))
        
        final_data = b''.join(plaintext_chunks)
        final_hash = hashlib.sha256(final_data).hexdigest()
        
        if final_hash == original_hash and final_data == test_data:
            print(f"  ✓ PASS - {name} works!")
        else:
            print(f"  ✗ FAIL - {name} failed!")
            return False
    
    print("\n✓ Key-based high-level API tests PASSED!")
    return True


def test_large_data_streaming():
    """Test with larger data to demonstrate memory efficiency."""
    print("\n=== Test 5: Large Data Streaming ===")
    
    # Generate 10MB of data
    data_size_mb = 10
    print(f"Generating {data_size_mb}MB of test data...")
    test_data = b"X" * (data_size_mb * 1024 * 1024)
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"Original hash: {original_hash[:16]}...")
    
    passphrase = "large_data_test"
    
    # Encrypt with compression
    print("Encrypting with ZIP compression...")
    msg = pgpy.PGPMessage.new(test_data, compression=CompressionAlgorithm.ZIP)
    encrypted_msg = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    # Decrypt using high-level streaming API
    print("Decrypting in streaming mode...")
    hasher = hashlib.sha256()
    chunk_count = 0
    total_bytes = 0
    
    for chunk in encrypted_msg.decrypt_to_plaintext_stream(passphrase, chunk_size=65536):
        hasher.update(bytes(chunk))
        chunk_count += 1
        total_bytes += len(chunk)
    
    final_hash = hasher.hexdigest()
    
    print(f"Processed {chunk_count} chunks, {total_bytes} bytes total")
    print(f"Final hash: {final_hash[:16]}...")
    
    if final_hash == original_hash and total_bytes == len(test_data):
        print(f"✓ PASS - {data_size_mb}MB processed successfully in streaming mode!")
        return True
    else:
        print("✗ FAIL - Hash or size mismatch!")
        return False


def main():
    """Run all tests."""
    print("=" * 70)
    print("PGPy Complete Streaming Test Suite")
    print("Testing compression, decompression, and high-level API")
    print("=" * 70)
    
    results = []
    
    try:
        results.append(("Compression Streaming", test_compression_streaming()))
        results.append(("High-Level API (Uncompressed)", test_high_level_api_uncompressed()))
        results.append(("High-Level API (Compressed)", test_high_level_api_compressed()))
        results.append(("Key-Based High-Level API", test_key_based_high_level()))
        results.append(("Large Data Streaming", test_large_data_streaming()))
        
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
        print(f"{test_name:45s} {status}")
    
    all_passed = all(result[1] for result in results)
    
    print("=" * 70)
    if all_passed:
        print("All tests PASSED! ✓")
        print("\nComplete streaming mode is fully functional!")
        print("- Compression/decompression works in streaming mode")
        print("- High-level API handles everything automatically")
        print("- Works with both passphrase and key-based encryption")
        return 0
    else:
        print("Some tests FAILED! ✗")
        return 1


if __name__ == '__main__':
    sys.exit(main())
