namespace S7.Net
{
    /// <summary>
    /// Contains constants related to payload management.
    /// </summary>
    public static class PayloadConstants
    {
        /// <summary>
        /// Common file patterns for discovering payloads.
        /// </summary>
        public static readonly string[] PAYLOAD_PATTERNS =
        {
            "*.bin",
            "stager*",
            "dump_mem*",
            "hello_*",
            "tic_tac_toe*"
        };

        // Payload type names
        public const string TYPE_STAGER = "Stager";
        public const string TYPE_DUMP_MEM = "Memory Dumper";
        public const string TYPE_HELLO = "Hello World";
        public const string TYPE_TIC_TAC_TOE = "Tic Tac Toe";
        public const string TYPE_BINARY = "Binary";
        public const string TYPE_UNKNOWN = "Unknown";

        // Payload file names
        public static readonly string[] STAGER_NAMES = { "stager.bin", "stager" };
        public static readonly string[] DUMP_MEM_NAMES = { "dump_mem.bin", "dump_mem" };
    }
}