using System;

namespace S7.Net.Exceptions
{
    /// <summary>
    /// Represents an error that occurs while scanning for payloads.
    /// </summary>
    public class PayloadScanException : Exception
    {
        public PayloadScanException()
        {
        }

        public PayloadScanException(string message)
            : base(message)
        {
        }

        public PayloadScanException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}