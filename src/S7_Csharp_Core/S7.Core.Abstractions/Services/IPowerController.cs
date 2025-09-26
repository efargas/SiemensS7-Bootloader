using System;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Interface for power controller operations using Modbus protocol.
    /// </summary>
    public interface IPowerController
    {
        /// <summary>
        /// Gets a value indicating whether the power controller is connected.
        /// </summary>
        bool IsConnected { get; }

        /// <summary>
        /// Connects to the Modbus power controller.
        /// </summary>
        /// <param name="host">The Modbus host address.</param>
        /// <param name="port">The Modbus port.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task ConnectAsync(string host, int port);

        /// <summary>
        /// Disconnects from the Modbus power controller.
        /// </summary>
        void Disconnect();

        /// <summary>
        /// Sets the power state of the specified coil.
        /// </summary>
        /// <param name="coil">The coil address.</param>
        /// <param name="powerOn">True to turn on, false to turn off.</param>
        /// <param name="slaveId">The Modbus slave ID.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task SetPowerAsync(ushort coil, bool powerOn, byte slaveId);
    }
}