#!/usr/bin/env python3
"""
Cross-compatibility tests for PGPy streaming mode.
Tests that traditional and streaming methods work together in all combinations.
"""

import os
import sys
import hashlib

# Add parent directory to path to import pgpy
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

import pgpy
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm, PubKeyAlgorithm, KeyFlags, HashAlgorithm


def extract_message_content(msg):
    """Helper to extract actual content from a PGPMessage."""
    if hasattr(msg.message, '_contents'):
        return bytes(msg.message._contents)
    elif isinstance(msg.message, str):
        return msg.message.encode('utf-8')
    elif isinstance(msg.message, bytes):
        return msg.message
    else:
        return bytes(msg.message)


def test_traditional_encrypt_stream_decrypt():
    """Test: Traditional encrypt → Streaming decrypt"""
    print("\n=== Test 1: Traditional Encrypt → Streaming Decrypt ===")
    
    test_data = b"Traditional encrypt, streaming decrypt" * 1000
    passphrase = "test_pass"
    
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    # Test with different compression algorithms
    compression_algos = [
        (CompressionAlgorithm.Uncompressed, "Uncompressed"),
        (CompressionAlgorithm.ZIP, "ZIP"),
        (CompressionAlgorithm.ZLIB, "ZLIB"),
        (CompressionAlgorithm.BZ2, "BZ2"),
    ]
    
    for algo, name in compression_algos:
        print(f"\nTesting with {name}...")
        
        # Traditional encrypt
        msg = pgpy.PGPMessage.new(test_data, compression=algo)
        encrypted = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
        
        # Streaming decrypt (low-level)
        decrypted_chunks = []
        for chunk in encrypted.decrypt_stream(passphrase):
            decrypted_chunks.append(bytes(chunk))
        
        packet_data = b''.join(decrypted_chunks)
        decrypted_msg = pgpy.PGPMessage()
        decrypted_msg.parse(packet_data)
        
        final_data = extract_message_content(decrypted_msg)
        final_hash = hashlib.sha256(final_data).hexdigest()
        
        if final_hash == original_hash and final_data == test_data:
            print(f"  ✓ PASS - {name}")
        else:
            print(f"  ✗ FAIL - {name}")
            return False
    
    print("\n✓ Traditional encrypt → Streaming decrypt works!")
    return True


def test_traditional_encrypt_high_level_stream_decrypt():
    """Test: Traditional encrypt → High-level streaming decrypt"""
    print("\n=== Test 2: Traditional Encrypt → High-Level Stream Decrypt ===")
    
    test_data = b"Traditional encrypt, high-level stream decrypt" * 1000
    passphrase = "test_pass2"
    
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    compression_algos = [
        (CompressionAlgorithm.Uncompressed, "Uncompressed"),
        (CompressionAlgorithm.ZIP, "ZIP"),
        (CompressionAlgorithm.ZLIB, "ZLIB"),
        (CompressionAlgorithm.BZ2, "BZ2"),
    ]
    
    for algo, name in compression_algos:
        print(f"\nTesting with {name}...")
        
        # Traditional encrypt
        msg = pgpy.PGPMessage.new(test_data, compression=algo)
        encrypted = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
        
        # High-level streaming decrypt
        plaintext_chunks = []
        for chunk in encrypted.decrypt_to_plaintext_stream(passphrase):
            plaintext_chunks.append(bytes(chunk))
        
        final_data = b''.join(plaintext_chunks)
        final_hash = hashlib.sha256(final_data).hexdigest()
        
        if final_hash == original_hash and final_data == test_data:
            print(f"  ✓ PASS - {name}")
        else:
            print(f"  ✗ FAIL - {name}")
            return False
    
    print("\n✓ Traditional encrypt → High-level stream decrypt works!")
    return True


def test_stream_decrypt_traditional_decrypt():
    """Test: Same message decrypted both ways produces identical results"""
    print("\n=== Test 3: Stream Decrypt vs Traditional Decrypt ===")
    
    test_data = b"Compare streaming and traditional decrypt" * 1000
    passphrase = "test_pass3"
    
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    compression_algos = [
        (CompressionAlgorithm.Uncompressed, "Uncompressed"),
        (CompressionAlgorithm.ZIP, "ZIP"),
        (CompressionAlgorithm.ZLIB, "ZLIB"),
        (CompressionAlgorithm.BZ2, "BZ2"),
    ]
    
    for algo, name in compression_algos:
        print(f"\nTesting with {name}...")
        
        # Encrypt once
        msg = pgpy.PGPMessage.new(test_data, compression=algo)
        encrypted = msg.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
        
        # Traditional decrypt
        traditional_decrypted = encrypted.decrypt(passphrase)
        traditional_data = extract_message_content(traditional_decrypted)
        traditional_hash = hashlib.sha256(traditional_data).hexdigest()
        
        # Streaming decrypt (high-level)
        streaming_chunks = []
        for chunk in encrypted.decrypt_to_plaintext_stream(passphrase):
            streaming_chunks.append(bytes(chunk))
        streaming_data = b''.join(streaming_chunks)
        streaming_hash = hashlib.sha256(streaming_data).hexdigest()
        
        # Low-level streaming decrypt
        lowlevel_chunks = []
        for chunk in encrypted.decrypt_stream(passphrase):
            lowlevel_chunks.append(bytes(chunk))
        lowlevel_packet = b''.join(lowlevel_chunks)
        lowlevel_msg = pgpy.PGPMessage()
        lowlevel_msg.parse(lowlevel_packet)
        lowlevel_data = extract_message_content(lowlevel_msg)
        lowlevel_hash = hashlib.sha256(lowlevel_data).hexdigest()
        
        # All three should match
        if original_hash == traditional_hash == streaming_hash == lowlevel_hash:
            if traditional_data == streaming_data == lowlevel_data == test_data:
                print(f"  ✓ PASS - {name} (all 3 methods match)")
            else:
                print(f"  ✗ FAIL - {name} (hashes match but data differs)")
                return False
        else:
            print(f"  ✗ FAIL - {name} (hash mismatch)")
            print(f"    Original:    {original_hash[:16]}...")
            print(f"    Traditional: {traditional_hash[:16]}...")
            print(f"    Streaming:   {streaming_hash[:16]}...")
            print(f"    Low-level:   {lowlevel_hash[:16]}...")
            return False
    
    print("\n✓ All decrypt methods produce identical results!")
    return True


def test_key_based_cross_compat():
    """Test: Key-based encryption cross-compatibility"""
    print("\n=== Test 4: Key-Based Cross-Compatibility ===")
    
    # Generate key
    print("Generating RSA key pair...")
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new('Test User', email='test@example.com')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    
    test_data = b"Key-based cross-compatibility test" * 500
    print(f"\nTest data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    compression_algos = [
        (CompressionAlgorithm.Uncompressed, "Uncompressed"),
        (CompressionAlgorithm.ZIP, "ZIP"),
    ]
    
    for algo, name in compression_algos:
        print(f"\nTesting with {name}...")
        
        # Traditional encrypt
        msg = pgpy.PGPMessage.new(test_data, compression=algo)
        encrypted = key.pubkey.encrypt(msg)
        
        # Traditional decrypt
        traditional_decrypted = key.decrypt(encrypted)
        traditional_data = extract_message_content(traditional_decrypted)
        traditional_hash = hashlib.sha256(traditional_data).hexdigest()
        
        # Streaming decrypt (low-level)
        streaming_chunks = []
        for chunk in key.decrypt_stream(encrypted):
            streaming_chunks.append(bytes(chunk))
        streaming_packet = b''.join(streaming_chunks)
        streaming_msg = pgpy.PGPMessage()
        streaming_msg.parse(streaming_packet)
        streaming_data = extract_message_content(streaming_msg)
        streaming_hash = hashlib.sha256(streaming_data).hexdigest()
        
        # High-level streaming decrypt
        highlevel_chunks = []
        for chunk in key.decrypt_to_plaintext_stream(encrypted):
            highlevel_chunks.append(bytes(chunk))
        highlevel_data = b''.join(highlevel_chunks)
        highlevel_hash = hashlib.sha256(highlevel_data).hexdigest()
        
        # All should match
        if original_hash == traditional_hash == streaming_hash == highlevel_hash:
            if traditional_data == streaming_data == highlevel_data == test_data:
                print(f"  ✓ PASS - {name} (all 3 methods match)")
            else:
                print(f"  ✗ FAIL - {name} (data mismatch)")
                return False
        else:
            print(f"  ✗ FAIL - {name} (hash mismatch)")
            return False
    
    print("\n✓ Key-based cross-compatibility works!")
    return True


def test_compression_cross_compat():
    """Test: Compression streaming cross-compatibility"""
    print("\n=== Test 5: Compression Cross-Compatibility ===")
    
    test_data = b"Compression test data " * 5000
    print(f"Test data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    compression_algos = [
        (CompressionAlgorithm.ZIP, "ZIP"),
        (CompressionAlgorithm.ZLIB, "ZLIB"),
        (CompressionAlgorithm.BZ2, "BZ2"),
    ]
    
    for algo, name in compression_algos:
        print(f"\nTesting {name}...")
        
        # Traditional compress
        compressed_traditional = algo.compress(test_data)
        
        # Streaming compress
        def data_iterator():
            for i in range(0, len(test_data), 8192):
                yield test_data[i:i+8192]
        
        compressed_streaming_chunks = []
        for chunk in algo.compress_stream(data_iterator()):
            compressed_streaming_chunks.append(chunk)
        compressed_streaming = b''.join(compressed_streaming_chunks)
        
        # Both compressed versions should decompress to same data
        # Traditional decompress of traditional compress
        decompressed_trad_trad = algo.decompress(compressed_traditional)
        
        # Traditional decompress of streaming compress
        decompressed_trad_stream = algo.decompress(compressed_streaming)
        
        # Streaming decompress of traditional compress
        def trad_iterator():
            for i in range(0, len(compressed_traditional), 4096):
                yield compressed_traditional[i:i+4096]
        
        decompressed_stream_trad_chunks = []
        for chunk in algo.decompress_stream(trad_iterator()):
            decompressed_stream_trad_chunks.append(chunk)
        decompressed_stream_trad = b''.join(decompressed_stream_trad_chunks)
        
        # Streaming decompress of streaming compress
        def stream_iterator():
            for i in range(0, len(compressed_streaming), 4096):
                yield compressed_streaming[i:i+4096]
        
        decompressed_stream_stream_chunks = []
        for chunk in algo.decompress_stream(stream_iterator()):
            decompressed_stream_stream_chunks.append(chunk)
        decompressed_stream_stream = b''.join(decompressed_stream_stream_chunks)
        
        # All should match original
        hash1 = hashlib.sha256(decompressed_trad_trad).hexdigest()
        hash2 = hashlib.sha256(decompressed_trad_stream).hexdigest()
        hash3 = hashlib.sha256(decompressed_stream_trad).hexdigest()
        hash4 = hashlib.sha256(decompressed_stream_stream).hexdigest()
        
        if original_hash == hash1 == hash2 == hash3 == hash4:
            print(f"  ✓ PASS - {name} (all 4 combinations work)")
            print(f"    Trad→Trad:     {len(decompressed_trad_trad)} bytes")
            print(f"    Trad→Stream:   {len(decompressed_trad_stream)} bytes")
            print(f"    Stream→Trad:   {len(decompressed_stream_trad)} bytes")
            print(f"    Stream→Stream: {len(decompressed_stream_stream)} bytes")
        else:
            print(f"  ✗ FAIL - {name}")
            print(f"    Original:      {original_hash[:16]}...")
            print(f"    Trad→Trad:     {hash1[:16]}...")
            print(f"    Trad→Stream:   {hash2[:16]}...")
            print(f"    Stream→Trad:   {hash3[:16]}...")
            print(f"    Stream→Stream: {hash4[:16]}...")
            return False
    
    print("\n✓ Compression cross-compatibility works!")
    return True


def test_multiple_round_trips():
    """Test: Multiple encrypt/decrypt round trips"""
    print("\n=== Test 6: Multiple Round Trips ===")
    
    test_data = b"Round trip test" * 1000
    passphrase = "roundtrip"
    
    print(f"Original data: {len(test_data)} bytes")
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"Original hash: {original_hash[:16]}...")
    
    current_data = test_data
    
    # Round trip 1: Traditional encrypt → Streaming decrypt
    print("\nRound 1: Traditional encrypt → Streaming decrypt")
    msg1 = pgpy.PGPMessage.new(current_data, compression=CompressionAlgorithm.ZIP)
    enc1 = msg1.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    chunks1 = []
    for chunk in enc1.decrypt_to_plaintext_stream(passphrase):
        chunks1.append(bytes(chunk))
    current_data = b''.join(chunks1)
    hash1 = hashlib.sha256(current_data).hexdigest()
    print(f"  Hash: {hash1[:16]}... ({'✓' if hash1 == original_hash else '✗'})")
    
    # Round trip 2: Traditional encrypt → Traditional decrypt
    print("\nRound 2: Traditional encrypt → Traditional decrypt")
    msg2 = pgpy.PGPMessage.new(current_data, compression=CompressionAlgorithm.ZLIB)
    enc2 = msg2.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    dec2 = enc2.decrypt(passphrase)
    current_data = extract_message_content(dec2)
    hash2 = hashlib.sha256(current_data).hexdigest()
    print(f"  Hash: {hash2[:16]}... ({'✓' if hash2 == original_hash else '✗'})")
    
    # Round trip 3: Traditional encrypt → Low-level streaming decrypt
    print("\nRound 3: Traditional encrypt → Low-level streaming decrypt")
    msg3 = pgpy.PGPMessage.new(current_data, compression=CompressionAlgorithm.BZ2)
    enc3 = msg3.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES256)
    
    chunks3 = []
    for chunk in enc3.decrypt_stream(passphrase):
        chunks3.append(bytes(chunk))
    packet3 = b''.join(chunks3)
    msg3_dec = pgpy.PGPMessage()
    msg3_dec.parse(packet3)
    current_data = extract_message_content(msg3_dec)
    hash3 = hashlib.sha256(current_data).hexdigest()
    print(f"  Hash: {hash3[:16]}... ({'✓' if hash3 == original_hash else '✗'})")
    
    if original_hash == hash1 == hash2 == hash3:
        print("\n✓ PASS - Multiple round trips preserve data perfectly!")
        return True
    else:
        print("\n✗ FAIL - Data corruption in round trips!")
        return False


def main():
    """Run all cross-compatibility tests."""
    print("=" * 70)
    print("PGPy Streaming Cross-Compatibility Test Suite")
    print("Testing traditional ↔ streaming interoperability")
    print("=" * 70)
    
    results = []
    
    try:
        results.append(("Traditional Encrypt → Stream Decrypt", test_traditional_encrypt_stream_decrypt()))
        results.append(("Traditional Encrypt → High-Level Stream", test_traditional_encrypt_high_level_stream_decrypt()))
        results.append(("Stream vs Traditional Decrypt", test_stream_decrypt_traditional_decrypt()))
        results.append(("Key-Based Cross-Compatibility", test_key_based_cross_compat()))
        results.append(("Compression Cross-Compatibility", test_compression_cross_compat()))
        results.append(("Multiple Round Trips", test_multiple_round_trips()))
        
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
        print("All cross-compatibility tests PASSED! ✓")
        print("\nTraditional and streaming methods are fully compatible!")
        print("You can mix and match encrypt/decrypt methods freely.")
        return 0
    else:
        print("Some tests FAILED! ✗")
        return 1


if __name__ == '__main__':
    sys.exit(main())
