### Precomputed Hex String Optimization

- **Optimized `HexRow`:** Modified the `HexRow` class to store a precomputed hex string for the entire row, instead of an array of strings for each byte. This significantly reduces the number of string allocations, improving performance and reducing memory usage.
- **Updated `VirtualizingHexList`:** The `VirtualizingHexList` has been updated to precompute the hex string for each row and populate the new `HexString` property in the `HexRow` objects.
- **Simplified UI:** The `HexViewerControl.axaml` has been updated to use a single `TextBlock` bound to the new `HexString` property, instead of an `ItemsControl`. This simplifies the UI and improves rendering performance.
- **Removed Unused Converters:** The `SearchResultHighlightConverter`, `SelectionHighlightConverter`, and `OffsetHighlightConverter` are no longer used and have been removed from the project.
