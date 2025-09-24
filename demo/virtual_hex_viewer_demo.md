# Virtualized Hex Viewer Demonstration

This document provides instructions on how to demonstrate the performance of the new virtualized hex viewer using a large, synthetically generated file.

## Step 1: Generate the Synthetic File

First, you need to generate a large file to test with. A shell script is provided for this purpose.

Run the following command from the root of the repository:

```sh
bash demo/generate_synthetic_file.sh
```

This will create a 256 MB file named `synthetic_large_file.bin` in the root directory.

## Step 2: Build and Run the Application

Ensure the application is built with the latest changes. Run the following command from the root of the repository:

```sh
dotnet build src/SiemensS7-Bootloader.sln
```

Then, run the application:

```sh
./src/S7_Csharp_Utility/bin/Debug/net8.0/S7_CS_Utility
```

## Step 3: Load the File in the Hex Viewer

1.  In the main application window, click the "Tools" menu and select "Hex File Viewer".
2.  In the Hex Viewer window, click the "Load File 1" button.
3.  Select the `synthetic_large_file.bin` file you generated in Step 1.

## Step 4: Observe Performance

The file should load almost instantly, as the data is read on-demand.

-   **Scrolling**: Use the scrollbar to navigate through the file. Scrolling should be smooth and responsive, even with a large file. The UI should not freeze or stutter. This is because the `VirtualizingHexList` only loads the visible rows, and the underlying `PageCache` fetches the required data in pages, caching them for future use.
-   **Memory Usage**: Observe the memory usage of the application. It should remain relatively low and stable, regardless of the file size, because the entire file is not loaded into memory.

This demonstrates the effectiveness of the new virtualization layer.
