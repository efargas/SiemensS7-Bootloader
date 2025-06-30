import argparse
from dump_analyzer_core import load_dump_from_file, find_sha1_pattern

def main():
    parser = argparse.ArgumentParser(
        description="Basic CLI to find SHA1 patterns in a binary dump file."
    )
    parser.add_argument(
        "dump_file",
        help="Path to the binary dump file."
    )
    parser.add_argument(
        "sha1_pattern",
        help="SHA1 hex pattern to search for (e.g., da39a3ee or a full SHA1)."
    )

    args = parser.parse_args()

    print(f"Attempting to load dump file: {args.dump_file}")
    try:
        dump_data = load_dump_from_file(args.dump_file)
        print(f"Successfully loaded {len(dump_data)} bytes from '{args.dump_file}'.")
    except FileNotFoundError:
        print(f"Error: Dump file '{args.dump_file}' not found.")
        return
    except IOError as e:
        print(f"Error: Could not read dump file '{args.dump_file}': {e}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while loading the dump file: {e}")
        return

    print(f"Searching for SHA1 pattern: {args.sha1_pattern}")
    try:
        offsets = find_sha1_pattern(dump_data, args.sha1_pattern)
        if offsets:
            print(f"Pattern '{args.sha1_pattern}' found at the following offsets (decimal):")
            for offset in offsets:
                print(f"  - {offset} (0x{offset:08x})")
        else:
            print(f"Pattern '{args.sha1_pattern}' not found in the dump file.")
    except ValueError as e:
        print(f"Error in pattern search: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during the search: {e}")

if __name__ == "__main__":
    main()
