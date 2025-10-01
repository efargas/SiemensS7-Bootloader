namespace S7.Net
{
    /// <summary>
    /// Contains constants used throughout the application.
    /// </summary>
    public static class PlcConstants
    {
        /// <summary>
        /// The maximum length of a message that can be sent to the PLC.
        /// </summary>
        public const int MAX_MSG_LEN = 192 - 2;

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
    }
}
