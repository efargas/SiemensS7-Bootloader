using System;

namespace S7.Net.Exceptions
{
    /// <summary>
    /// Represents an error that occurs during a PLC protocol operation.
    /// </summary>
    public class PlcProtocolException : PlcCommunicationException
    {
        public PlcProtocolException()
        {
        }

        public PlcProtocolException(string message)
            : base(message)
        {
        }

        public PlcProtocolException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}