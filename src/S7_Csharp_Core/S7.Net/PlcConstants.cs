namespace S7.Net
{
    /// <summary>
    /// Contains constants used throughout the application.
    /// </summary>
    public static class PlcConstants
    {
        /// <summary>
        /// The maximum length of a message that can be sent to the PLC via the stager.
        /// </summary>
        public const int MAX_STAGER_MSG_LEN = 192 - 2;

        /// <summary>
        /// The maximum size of the data field in a standard protocol packet.
        /// </summary>
        public const int MAX_PACKET_SIZE = 254;

        /// <summary>
        /// The safety delay to wait before sending a packet.
        /// </summary>
        public const int SEND_PACKET_DELAY_MS = 10;

        /// <summary>
        /// The starting address of the stager in IRAM.
        /// </summary>
        public const uint IRAM_STAGER_START = 0x10030100;
        /// <summary>
        /// The starting address of the additional hook table.
        /// </summary>
        public const uint ADD_HOOK_TABLE_START = 0x1003ABA0;
        /// <summary>
        /// The default index for the stager's additional hook.
        /// </summary>
        public const int DEFAULT_STAGER_ADDHOOK_IND = 0x20;
        /// <summary>
        /// The default index for the second additional hook.
        /// </summary>
        public const int DEFAULT_SECOND_ADD_HOOK_IND = 0x1a;
        /// <summary>
        /// The location of the dumper payload.
        /// </summary>
        public const uint DUMPER_PAYLOAD_LOCATION = 0x10010100;

        /// <summary>
        /// The success response for entering a subprotocol.
        /// </summary>
        public static readonly byte[] ANSW_ENTER_SUBPROTO_SUCCESS = { 0x80, 0x00 };
        /// <summary>
        /// The magic numbers for entering subprotocol modes.
        /// </summary>
        public static readonly ushort[] SUBPROT_80_MODE_MAGICS = { 0, 0x3BC2, 0x9d26, 0xe17a, 0xc54f };
        /// <summary>
        /// The subprotocol mode for IRAM.
        /// </summary>
        public const int SUBPROT_80_MODE_IRAM = 1;

        // Handshake constants
        public const string HANDSHAKE_MAGIC = "MFGT1";
        public const string HANDSHAKE_PADDING = "AAAA";
        public const int HANDSHAKE_TIMEOUT_MS = 300;
        public const int HANDSHAKE_POLL_DELAY_MS = 50;
        public const int HANDSHAKE_RETRY_DELAY_MS = 10;
        public const string HANDSHAKE_SUCCESS_SIGNATURE = "-CPU";

        // Primary Handler Indices
        public const byte HANDLER_GET_VERSION = 0x00;
        public const byte HANDLER_ENTER_SUBPROTOCOL = 0x80;
        public const byte HANDLER_INVOKE_ADD_HOOK = 0x1C;

        // Subprotocol Commands
        public static readonly byte[] CMD_LEAVE_SUBPROTOCOL = { 0x81, 0xD0, 0x67 };
        public static readonly byte[] CMD_RAW_WRITE_PREFIX = { 0x84, 0x5a, 0x2e };

        // Memory and Addressing
        public const uint IRAM_ADDRESS_OFFSET = 0x10000000;
        public const int IRAM_WRITE_CHUNK_SIZE = 16;

        // Stager and Hooks
        public const byte STAGER_HOOK_VAR_LEN_ARG_1 = 0x00;
        public const byte STAGER_HOOK_VAR_LEN_ARG_2 = 0xFF;
        public const byte STAGER_INTERRUPT_ACK = 0xFF;

        // Memory Dumper
        public const byte DUMP_COMMAND_START_BYTE = (byte)'A';
    }
}
