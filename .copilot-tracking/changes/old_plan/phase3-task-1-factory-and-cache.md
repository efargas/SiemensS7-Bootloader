### VirtualFileReaderFactory and PageCache Integration

- **Modified `VirtualFileReaderFactory`:** Updated the factory to select between `MemoryMappedFileVirtualReader` and `FileStreamVirtualReader` based on the file size (threshold: 100MB). This ensures that large files are handled more efficiently using memory-mapped files, while smaller files are read using a simple file stream.
- **Integrated `PageCache` in `HexViewerViewModel`:** Modified the `HexViewerViewModel` to wrap the `IVirtualFileReader` instance (obtained from the factory) in a `PageCache`. This adds a caching layer that improves performance by reducing redundant reads from the underlying file.
