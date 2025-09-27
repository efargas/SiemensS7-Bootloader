using System;

namespace S7_Csharp_Utility.Models
{
    public class PayloadInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string RelativePath { get; set; } = string.Empty;
        public long Size { get; set; }
        public DateTime LastModified { get; set; }
        public string Description { get; set; } = string.Empty;
    }
}