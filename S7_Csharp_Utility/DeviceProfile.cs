using System.Collections.Generic;

namespace S7_Csharp_Utility
{
    public class MemoryRegion
    {
        public string Name { get; set; } = "";
        public string Address { get; set; } = "0x0";
        public uint Size { get; set; } = 0;
    }

    public class DeviceProfile
    {
        public string ModelName { get; set; } = "New Profile";
        public List<MemoryRegion> Regions { get; set; } = new List<MemoryRegion>();
    }
}
