namespace S7_Csharp_Utility.Models
{
    public class SearchResult
    {
        public int FileIndex { get; }
        public long Offset { get; }

        public SearchResult(int fileIndex, long offset)
        {
            FileIndex = fileIndex;
            Offset = offset;
        }

        public override string ToString()
        {
            return $"File {FileIndex}, Offset: 0x{Offset:X8}";
        }
    }
}
