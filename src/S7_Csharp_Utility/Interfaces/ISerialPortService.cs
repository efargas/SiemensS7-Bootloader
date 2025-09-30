using System.Collections.Generic;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for interacting with the system's serial ports.
    /// </summary>
    public interface ISerialPortService
    {
        /// <summary>
        /// Gets a list of available serial port names on the system.
        /// </summary>
        /// <returns>A collection of serial port names.</returns>
        Task<IEnumerable<string>> GetAvailablePortNamesAsync();
    }
}