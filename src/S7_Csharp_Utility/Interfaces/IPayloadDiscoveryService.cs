using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using S7_Csharp_Utility.Models;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines the contract for a service that discovers and manages payload files.
    /// </summary>
    public interface IPayloadDiscoveryService : INotifyPropertyChanged
    {
        /// <summary>
        /// Gets a value indicating whether a payload scan is currently in progress.
        /// </summary>
        bool IsScanning { get; }

        /// <summary>
        /// Gets the collection of discovered payloads.
        /// </summary>
        ObservableCollection<PayloadInfo> DiscoveredPayloads { get; }

        /// <summary>
        /// Starts an asynchronous scan for payloads.
        /// </summary>
        Task ScanPayloadsAsync();

        /// <summary>
        /// Cancels the ongoing payload scan.
        /// </summary>
        void CancelScan();
    }
}