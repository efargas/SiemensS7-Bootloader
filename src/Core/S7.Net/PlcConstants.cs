namespace S7.Net
{
    public static class PlcConstants
    {
        // Constants from PlcCommunicator
        public const int MAX_MSG_LEN = 192 - 2;

        // Addresses ported from client.py
        public const uint IRAM_STAGER_START = 0x10030100;
        public const uint ADD_HOOK_TABLE_START = 0x1003ABA0;
        public const int DEFAULT_STAGER_ADDHOOK_IND = 0x20;
        public const int DEFAULT_SECOND_ADD_HOOK_IND = 0x1a;
        public const uint DUMPER_PAYLOAD_LOCATION = 0x10010100;

        // Protocol constants
        public static readonly byte[] ANSW_ENTER_SUBPROTO_SUCCESS = { 0x80, 0x00 };
        public static readonly ushort[] SUBPROT_80_MODE_MAGICS = { 0, 0x3BC2, 0x9d26, 0xe17a, 0xc54f };
        public const int SUBPROT_80_MODE_IRAM = 1;
    }
}
