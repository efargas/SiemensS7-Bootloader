using S7_Csharp_Utility.Interfaces;
using System.Collections.Generic;
using System.IO.Ports;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// A service for interacting with the system's serial ports.
    /// </summary>
    public class SerialPortService : ISerialPortService
    {
        /// <inheritdoc />
        public Task<IEnumerable<string>> GetAvailablePortNamesAsync()
        {
            // This is a synchronous I/O call, so we wrap it in Task.Run
            // to make it awaitable and not block the UI thread if it were slow.
            return Task.Run(() => (IEnumerable<string>)SerialPort.GetPortNames());
        }
    }
}