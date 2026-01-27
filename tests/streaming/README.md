# PGPy Streaming Mode Tests
This directory contains comprehensive tests for PGPy's streaming mode implementation.

## Test Files

### 1. `test_streaming_mirror.py`
Tests that encrypt/decrypt operations are perfect mirrors - what you encrypt can be decrypted back to the original.

**Test Categories:**
- Symmetric Encryption Mirror (4 test cases)
- Key-Based Encryption Mirror (3 test cases)
- Traditional vs Streaming Decrypt Comparison
- Chunk Size Independence (5 chunk sizes)
- Edge Cases (empty data, single byte, null bytes, etc.)

**Run:** `python test_streaming_mirror.py`

### 2. `test_streaming_complete.py`
Tests complete streaming functionality including compression and high-level API.
{{ ... }}
- Compression Cross-Compatibility (all 4 combinations)
- Multiple Round Trips

**Run:** `python test_streaming_cross_compat.py`

### 4. `test_armor_streaming.py`
Tests ASCII armor streaming with incremental CRC24 computation.

**Test Categories:**
- CRC24 Accuracy (6 test cases)
- Armor Encoding Format
- Armor Round Trip
- Traditional vs Streaming Armor
- Key Armor Streaming
- Large Data Armor (5MB file)
- CRC24 Verification (corruption detection)

**Run:** `python test_armor_streaming.py`

## Running All Tests

```bash
# From repository root
cd tests/streaming

# Run all tests
python test_streaming_mirror.py
python test_streaming_complete.py
python test_streaming_cross_compat.py
python test_armor_streaming.py
```

## Test Results

All tests should pass with 100% success rate:

```
✓ test_streaming_mirror.py       - 5/5 categories pass
✓ test_streaming_complete.py     - 5/5 categories pass
✓ test_streaming_cross_compat.py - 6/6 categories pass
✓ test_armor_streaming.py        - 7/7 categories pass
```

**Total: 23 test categories, all passing!**
