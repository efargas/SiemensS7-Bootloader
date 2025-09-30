using System;

namespace S7.Net.Exceptions
{
    /// <summary>
    /// Represents an error that occurs when the PLC handshake fails.
    /// </summary>
    public class PlcHandshakeFailedException : PlcCommunicationException
    {
        public PlcHandshakeFailedException()
            : base("The handshake with the PLC failed after multiple attempts.")
        {
        }

        public PlcHandshakeFailedException(string message)
            : base(message)
        {
        }

        public PlcHandshakeFailedException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}