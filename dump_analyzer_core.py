"""
Core functionalities for the PLC Dump Analyzer.
This module will contain functions for loading dump data and searching patterns.
"""

def load_dump_from_file(filepath: str) -> bytes:
    """
    Loads raw binary data from a specified file.

    Args:
        filepath: The path to the file to be loaded.

    Returns:
        A bytes object containing the file's content.
        Returns an empty bytes object if the file is empty.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        IOError: If any other I/O error occurs.
    """
    try:
        with open(filepath, "rb") as f:
            return f.read()
    except FileNotFoundError:
        # Re-raise FileNotFoundError to be explicit about what went wrong.
        raise
    except IOError as e:
        # Catch other potential I/O errors (e.g., permission issues).
        # Consider logging this error in a real application.
        print(f"An I/O error occurred: {e}")
        raise


def load_dump_from_bytes(data: bytes) -> bytes:
    """
    "Loads" dump data from an existing bytes object.

    Essentially, this function serves as a constructor or validator
    for using bytes data directly with the analyzer. Currently, it
    just returns the data as is, but could be expanded for validation
    or copying if needed.

    Args:
        data: A bytes object.

    Returns:
        The same bytes object.
    """
    if not isinstance(data, bytes):
        raise TypeError("Input data must be a bytes object.")
    return data

if __name__ == '__main__':
    # Example Usage (for testing purposes)
    # Create a dummy file for testing load_dump_from_file
    dummy_file_name = "dummy_dump.bin"
    dummy_content = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    with open(dummy_file_name, "wb") as f:
        f.write(dummy_content)

    print(f"Testing load_dump_from_file with '{dummy_file_name}':")
    try:
        file_data = load_dump_from_file(dummy_file_name)
        print(f"Successfully loaded {len(file_data)} bytes.")
        print(f"Data: {file_data.hex()}")
    except Exception as e:
        print(f"Error loading file: {e}")

    print(f"\nTesting load_dump_from_file with a non-existent file:")
    try:
        file_data_error = load_dump_from_file("non_existent_file.bin")
    except FileNotFoundError:
        print("Successfully caught FileNotFoundError for non_existent_file.bin")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


    print("\nTesting load_dump_from_bytes:")
    byte_data_input = b"\xDE\xAD\xBE\xEF"
    loaded_byte_data = load_dump_from_bytes(byte_data_input)
    print(f"Successfully loaded bytes data: {loaded_byte_data.hex()}")

    print("\nTesting load_dump_from_bytes with incorrect type:")
    try:
        load_dump_from_bytes("this is not bytes") # type: ignore
    except TypeError as e:
        print(f"Successfully caught TypeError: {e}")

    # Clean up the dummy file
    import os
    try:
        os.remove(dummy_file_name)
        print(f"\nCleaned up {dummy_file_name}")
    except OSError as e:
        print(f"Error removing dummy file {dummy_file_name}: {e}")


def find_sha1_pattern(dump_data: bytes, sha1_hex_pattern: str) -> list[int]:
    """
    Finds all occurrences of a given SHA1 hex pattern within the dump data.
    The pattern can be partial (less than 20 bytes / 40 hex chars).

    Args:
        dump_data: The bytes object representing the memory dump.
        sha1_hex_pattern: The SHA1 pattern to search for, as a hexadecimal string.
                          It can be a full SHA1 (40 hex chars) or a partial one.

    Returns:
        A list of integer offsets where the pattern starts.
        Returns an empty list if the pattern is not found or if inputs are invalid.

    Raises:
        ValueError: If sha1_hex_pattern contains non-hexadecimal characters,
                    or has an odd number of characters.
    """
    if not dump_data:
        return []
    if not sha1_hex_pattern:
        # Or raise ValueError("Pattern cannot be empty") - depends on desired behavior
        # For now, returning empty list as no specific "empty pattern" is found.
        return []

    # Validate hex pattern
    if not all(c in "0123456789abcdefABCDEF" for c in sha1_hex_pattern):
        raise ValueError("Pattern contains non-hexadecimal characters.")
    if len(sha1_hex_pattern) % 2 != 0:
        raise ValueError("Hex pattern must have an even number of characters.")

    # Max length for a SHA1 is 20 bytes (40 hex characters)
    # We allow partial searches, so pattern length can be less.
    if len(sha1_hex_pattern) > 40:
        # Or one could truncate, but raising error seems safer to avoid user confusion.
        raise ValueError("SHA1 hex pattern should not exceed 40 characters (20 bytes).")

    try:
        target_pattern = bytes.fromhex(sha1_hex_pattern)
    except ValueError as e:
        # This might catch issues like odd length again, or other unexpected fromhex errors.
        # The previous checks should prevent most of these.
        raise ValueError(f"Invalid hex string for pattern: {e}")


    if not target_pattern: # Should be caught by "not sha1_hex_pattern" but good as a safeguard
        return []

    found_offsets = []
    pattern_len = len(target_pattern)
    data_len = len(dump_data)

    if pattern_len > data_len:
        return [] # Pattern is longer than data, cannot be found.

    for i in range(data_len - pattern_len + 1):
        if dump_data[i:i+pattern_len] == target_pattern:
            found_offsets.append(i)

    return found_offsets


if __name__ == '__main__':
    # Example Usage (for testing purposes)
    # Create a dummy file for testing load_dump_from_file
    dummy_file_name = "dummy_dump.bin"
    # SHA1 of "test": a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
    # SHA1 of empty string: da39a3ee5e6b4b0d3255bfef95601890afd80709
    dummy_content = (
        b"HEADER_STUFF" +
        bytes.fromhex("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3") + # "test" sha1 at offset 12
        b"MIDDLE_STUFF" +
        bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709") + # "" sha1 at offset 12 + 20 + 12 = 44
        b"DA39A3PARTIAL" + # Partial match for "" sha1 at offset 44 + 20 + 13 = 77
        b"END_STUFF"
    )
    # Expected offsets:
    # "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" -> 12
    # "da39a3ee5e6b4b0d3255bfef95601890afd80709" -> 44
    # "da39a3" (partial) -> 44, 77

    with open(dummy_file_name, "wb") as f:
        f.write(dummy_content)

    print(f"Testing load_dump_from_file with '{dummy_file_name}':")
    try:
        file_data = load_dump_from_file(dummy_file_name)
        print(f"Successfully loaded {len(file_data)} bytes.")
        # print(f"Data: {file_data.hex()}") # Can be noisy
    except Exception as e:
        print(f"Error loading file: {e}")
        file_data = b"" # Ensure file_data is defined for later tests

    print(f"\nTesting load_dump_from_file with a non-existent file:")
    try:
        file_data_error = load_dump_from_file("non_existent_file.bin")
    except FileNotFoundError:
        print("Successfully caught FileNotFoundError for non_existent_file.bin")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


    print("\nTesting load_dump_from_bytes:")
    byte_data_input = b"\xDE\xAD\xBE\xEF"
    loaded_byte_data = load_dump_from_bytes(byte_data_input)
    print(f"Successfully loaded bytes data: {loaded_byte_data.hex()}")

    print("\nTesting load_dump_from_bytes with incorrect type:")
    try:
        load_dump_from_bytes("this is not bytes") # type: ignore
    except TypeError as e:
        print(f"Successfully caught TypeError: {e}")

    # --- Test find_sha1_pattern ---
    print("\n--- Testing find_sha1_pattern ---")
    if file_data:
        # Test 1: Full SHA1 ("test")
        pattern1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        offsets1 = find_sha1_pattern(file_data, pattern1)
        print(f"Pattern '{pattern1[:10]}...' found at offsets: {offsets1} (Expected: [12])")

        # Test 2: Full SHA1 ("")
        pattern2 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        offsets2 = find_sha1_pattern(file_data, pattern2)
        print(f"Pattern '{pattern2[:10]}...' found at offsets: {offsets2} (Expected: [44])")

        # Test 3: Partial SHA1 ("da39a3")
        pattern3 = "da39a3"
        offsets3 = find_sha1_pattern(file_data, pattern3)
        print(f"Pattern '{pattern3}' found at offsets: {offsets3} (Expected: [44, 77])")

        # Test 4: Pattern not present
        pattern4 = "001122334455"
        offsets4 = find_sha1_pattern(file_data, pattern4)
        print(f"Pattern '{pattern4}' found at offsets: {offsets4} (Expected: [])")

        # Test 5: Empty pattern string
        pattern5 = ""
        offsets5 = find_sha1_pattern(file_data, pattern5)
        print(f"Pattern '{pattern5}' (empty) found at offsets: {offsets5} (Expected: [])")

        # Test 6: Pattern longer than data
        pattern6 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" * 2 # 40 bytes
        offsets6 = find_sha1_pattern(file_data, pattern6)
        print(f"Pattern '{pattern6[:10]}...' (long) found at offsets: {offsets6} (Expected: [])")

    # Test 7: Invalid hex pattern (non-hex chars)
    print("\nTesting invalid patterns:")
    try:
        find_sha1_pattern(file_data, "ggHhIi")
    except ValueError as e:
        print(f"Successfully caught ValueError for non-hex pattern: {e}")

    # Test 8: Invalid hex pattern (odd length)
    try:
        find_sha1_pattern(file_data, "12345")
    except ValueError as e:
        print(f"Successfully caught ValueError for odd-length pattern: {e}")

    # Test 9: Invalid hex pattern (too long)
    try:
        find_sha1_pattern(file_data, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" + "00") # 42 chars
    except ValueError as e:
        print(f"Successfully caught ValueError for too long pattern: {e}")

    # Test 10: Empty dump data
    offsets_empty_dump = find_sha1_pattern(b"", "da39a3")
    print(f"Pattern 'da39a3' in empty dump found at offsets: {offsets_empty_dump} (Expected: [])")


    # Clean up the dummy file
    import os
    try:
        os.remove(dummy_file_name)
        print(f"\nCleaned up {dummy_file_name}")
    except OSError as e:
        print(f"Error removing dummy file {dummy_file_name}: {e}")
