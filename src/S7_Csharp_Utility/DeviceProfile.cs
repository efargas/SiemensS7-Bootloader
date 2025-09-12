using System.Collections.Generic;

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
    }

    /// <summary>
    /// Represents a device profile.
    /// </summary>
    public class DeviceProfile
    {
        /// <summary>
        /// The model name of the device.
        /// </summary>
        public string ModelName { get; set; } = "New Profile";
        /// <summary>
        /// A list of memory regions in the device.
        /// </summary>
        public List<MemoryRegion> Regions { get; set; } = new List<MemoryRegion>();
    }
}
