def main():
    file_content_parts = [
        b"START_OF_FILE_",                                                  # 14 bytes
        bytes.fromhex("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"),          # 20 bytes (SHA1("test"))
        b"_MIDDLE_BYTES_",                                                  # 14 bytes
        bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709"),          # 20 bytes (SHA1(""))
        b"_END_OF_FILE",                                                    # 12 bytes
        bytes.fromhex("da39a3")                                             # 3 bytes (Partial "da39a3")
    ]

    expected_len = 14 + 20 + 14 + 20 + 12 + 3 # = 83 bytes

    binary_data = b"".join(file_content_parts)

    if len(binary_data) != expected_len:
        print(f"Error: Generated binary data length {len(binary_data)} does not match expected {expected_len}")
        return

    try:
        with open("sample_dump.bin", "wb") as f:
            f.write(binary_data)
        print(f"Successfully wrote {len(binary_data)} bytes to sample_dump.bin")
    except IOError as e:
        print(f"Error writing sample_dump.bin: {e}")

if __name__ == "__main__":
    main()
