using System;

namespace S7.Net.Exceptions
{
    /// <summary>
    /// Represents errors that occur during PLC communication.
    /// </summary>
    public class PlcCommunicationException : Exception
    {
        public PlcCommunicationException()
        {
        }

        public PlcCommunicationException(string message)
            : base(message)
        {
        }

        public PlcCommunicationException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}