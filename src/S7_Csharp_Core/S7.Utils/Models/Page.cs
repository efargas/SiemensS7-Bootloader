using System;

namespace S7.Utils.Models
{
    public record Page(long PageIndex, ReadOnlyMemory<byte> Data, int Length);
}
