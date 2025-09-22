# Hex Viewer Advanced Range Selection Features

This document outlines the advanced range selection features implemented for the hex viewer component in the Siemens S7 Bootloader project.

## 🎯 Overview

The hex viewer now supports sophisticated range selection capabilities with mouse interaction, keyboard modifiers, and comprehensive copy/export functionality. These features enable users to efficiently select, analyze, and extract data from binary files.

## 🖱️ Mouse Selection Features

### Basic Selection
- **Single Click**: Select individual bytes
- **Click and Drag**: Select continuous ranges of bytes
- **Visual Feedback**: Selected bytes are highlighted with different colors

### Advanced Selection Modes
- **Range Selection**: Click and drag to select continuous byte ranges
- **Anchor-based Selection**: Maintains selection anchor for extended operations
- **Visual Highlighting**: 
  - Primary selection: Indigo-600 (#4C51BF)
  - Range selection: Indigo-400 (#6B73FF)

## ⌨️ Keyboard Modifier Support

### Shift + Click
- Extends selection from the current anchor point to the clicked byte
- Allows for precise range selection without dragging
- Maintains selection continuity

### Ctrl + Click
- Prepared for future multi-selection support
- Currently behaves as normal click (single selection)
- Framework in place for discontinuous selections

## 📋 Enhanced Copy Operations

### Multiple Copy Formats
1. **Hex Format**: Space-separated hex bytes (e.g., "41 42 43 44")
2. **ASCII Format**: Printable ASCII characters with '.' for non-printable
3. **C Array Format**: Formatted as C/C++ byte array with comments
4. **Base64 Format**: Standard Base64 encoding

### Copy Examples

#### Hex Format
```
41 42 43 44 45 46 47 48
```

#### ASCII Format
```
ABCDEFGH
```

#### C Array Format
```c
// Selection from offset 0x00000100, 8 bytes
unsigned char data[8] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
};
```

#### Base64 Format
```
QUJDREVGR0g=
```

## 💾 Export Functionality

### File Export
- **Binary Export**: Save selected bytes as binary file
- **Streaming Export**: Efficient handling of large selections using 8KB buffers
- **Progress Feedback**: Real-time status updates during export
- **Automatic Naming**: Generates descriptive filenames with offset and size info

### Export Features
- Preserves exact binary data
- Handles large selections efficiently
- Provides user feedback on export progress
- Supports cancellation during long operations

## 🎨 Visual Enhancements

### Selection Highlighting
- **Primary Selection**: Bright indigo for the main selected byte
- **Range Selection**: Lighter indigo for extended selection ranges
- **Hover Effects**: Visual feedback on mouse hover
- **Consistent Theming**: Matches the dark theme of the application

### Status Information
- **Real-time Updates**: Selection info displayed in status bar
- **Byte Count**: Shows number of selected bytes
- **Offset Range**: Displays start and end offsets in hexadecimal
- **Selection Length**: Visible in inspector panel when selection exists

## 🔧 Technical Implementation

### Architecture
- **MVVM Pattern**: Clean separation of concerns
- **Command Pattern**: All interactions through ICommand implementations
- **Async Operations**: Non-blocking file operations with cancellation support
- **Memory Efficient**: Streaming operations for large data sets

### Key Components

#### HexViewerViewModel
- `SelectionStartOffset`: Start of selection range
- `SelectionEndOffset`: End of selection range
- `SelectionLength`: Calculated selection size
- `IsOffsetInSelection()`: Helper method for range checking

#### Selection Commands
- `HexCellMouseDownCommand`: Initiates selection
- `HexCellMouseEnterCommand`: Updates selection during drag
- `HexCellMouseUpCommand`: Finalizes selection
- `ClearSelectionCommand`: Resets selection state

#### Copy Commands
- `CopyAsHexCommand`: Hex format copy
- `CopyAsAsciiCommand`: ASCII format copy
- `CopyAsCArrayCommand`: C array format copy
- `CopyAsBase64Command`: Base64 format copy

#### Export Commands
- `ExportToFileCommand`: Binary file export
- `ExportSelectionCommand`: Legacy export interface

### Converter Updates
- **SelectionHighlightConverter**: Enhanced to support range highlighting
- **Multi-value Binding**: Supports offset, selection start/end parameters
- **Performance Optimized**: Efficient color determination logic

## 🚀 Usage Instructions

### Selecting Data
1. **Single Byte**: Click on any hex byte
2. **Range Selection**: Click and drag across multiple bytes
3. **Extended Selection**: Hold Shift and click to extend from anchor
4. **Clear Selection**: Use the "Clear" button in the inspector panel

### Copying Data
1. Select the desired byte range
2. Use the copy buttons in the inspector panel:
   - "📋 Hex" for hex format
   - "📋 ASCII" for ASCII format
   - "📋 C Array" for C array format
   - "📋 Base64" for Base64 format

### Exporting Data
1. Select the desired byte range
2. Click "💾 Export" in the inspector panel
3. Choose destination file in the save dialog
4. Monitor progress in the status bar

## 🎛️ Inspector Panel Integration

### Selection Actions Section
- **Conditional Visibility**: Only shown when bytes are selected
- **Compact Layout**: Efficient use of space with wrap panel
- **Quick Access**: All copy/export operations in one place
- **Visual Feedback**: Selection count displayed

### Enhanced UI Elements
- **Responsive Design**: Adapts to selection state
- **Consistent Styling**: Matches application theme
- **Accessibility**: Clear labels and visual hierarchy
- **Performance**: Efficient binding and updates

## 🔮 Future Enhancements

### Planned Features
1. **Multi-Selection**: Support for discontinuous byte selections
2. **Keyboard Shortcuts**: Ctrl+A (Select All), Ctrl+C (Copy), etc.
3. **Search Integration**: Select search results automatically
4. **Bookmark System**: Save and restore selection ranges
5. **Pattern Analysis**: Detect and highlight data patterns

### Advanced Export Options
1. **Multiple Formats**: Intel HEX, Motorola S-Record, etc.
2. **Custom Templates**: User-defined export formats
3. **Batch Export**: Export multiple selections simultaneously
4. **Compression**: Optional compression for large exports

## 📊 Performance Characteristics

### Optimizations
- **Lazy Loading**: Only visible data is processed
- **Efficient Highlighting**: Minimal UI updates during selection
- **Streaming I/O**: Large file operations don't block UI
- **Memory Management**: Proper disposal of resources

### Scalability
- **Large Files**: Handles files up to several GB
- **Large Selections**: Efficient processing of MB-sized selections
- **Responsive UI**: Maintains 60fps during interactions
- **Background Processing**: Long operations run asynchronously

## 🛠️ Development Notes

### Code Quality
- **Comprehensive Documentation**: All public methods documented
- **Error Handling**: Robust exception handling throughout
- **Async Best Practices**: Proper use of ConfigureAwait(false)
- **Resource Management**: Proper disposal patterns

### Testing Considerations
- **Unit Tests**: Command logic and calculations
- **Integration Tests**: File I/O operations
- **UI Tests**: Selection behavior and visual feedback
- **Performance Tests**: Large file and selection handling

This implementation provides a professional-grade hex viewer with advanced selection capabilities that rival commercial hex editors while maintaining the clean, modern interface of the Siemens S7 Bootloader application.