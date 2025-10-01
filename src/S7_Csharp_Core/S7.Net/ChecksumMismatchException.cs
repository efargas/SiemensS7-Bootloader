using System;

namespace S7.Net
{
    public class ChecksumMismatchException : Exception
    {
        public ChecksumMismatchException() : base("The received packet has an invalid checksum.")
        {
        }

        public ChecksumMismatchException(string message) : base(message)
        {
        }

        public ChecksumMismatchException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
