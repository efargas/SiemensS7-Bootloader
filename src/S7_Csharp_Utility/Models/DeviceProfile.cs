using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// Represents a memory region.
    /// </summary>
    public class MemoryRegion
    {
        /// <summary>
        /// The name of the memory region.
        /// </summary>
        public string Name { get; set; } = "";
        /// <summary>
        /// The starting address of the memory region.
        /// </summary>
        public string Address { get; set; } = "0x0";
        /// <summary>
        /// The size of the memory region.
        /// </summary>
        public uint Size { get; set; } = 0;

        /// <summary>
        /// The calculated end address of the memory region.
        /// </summary>
        public string EndAddress
        {
            get
            {
                try
                {
                    if (Address.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    {
                        var addressValue = Convert.ToUInt32(Address.Substring(2), 16);
                        var endAddress = addressValue + Size;
                        return $"0x{endAddress:X}";
                    }
                    else
                    {
                        return "Invalid Address";
                    }
                }
                catch (Exception)
                {
                    return "Invalid Address";
                }
            }
        }
    }

    /// <summary>
    /// Represents a device profile.
    /// </summary>
    public class DeviceProfile
    {
        [JsonIgnore]
        public string FilePath { get; set; } = "";
        /// <summary>
        /// The model name of the device.
        /// </summary>
        public string ModelName { get; set; } = "New Profile";
        /// <summary>
        /// The firmware version of the device.
        /// </summary>
        public string FirmwareVersion { get; set; } = string.Empty;
        /// <summary>
        /// A list of memory regions in the device.
        /// </summary>
        public ObservableCollection<MemoryRegion> Regions { get; set; } = new ObservableCollection<MemoryRegion>();
    }
}
