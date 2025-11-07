<p align="center">
  <img src="pics/x-ray.gif" alt="Siemens S7-1200 3D X-Ray"/>
</p>

# Siemens S7 PLCs Bootloader Utility (C# Version)

This repository contains a C# cross-platform utility for gaining non-invasive arbitrary code execution on Siemens S7 PLCs by using an undocumented bootloader protocol over UART. This is a C# rewrite and enhancement of the original Python-based tool.

The vulnerability is tracked as SSA-686531 (CVE-2019-13945). Affected devices are Siemens S7-1200 (all variants including SIPLUS) and S7-200 Smart.

## Building and Running the C# Utility

This is a .NET 8 application built with the Avalonia UI framework, allowing it to run on both Windows and Linux.

### 1. Prerequisites
You need to have the [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) installed on your system.

### 2. Building the Application
Open a terminal or command prompt, navigate to the root of the repository, and run the following command:
```sh
dotnet build src/S7_Csharp_Utility/S7_Csharp_Utility.csproj --configuration Release
```
This will compile the application. The output will be placed in the `src/S7_Csharp_Utility/bin/Release/net8.0` directory.

### 3. Running the Application
After building, you can run the application from its output directory.

**On Windows:**
```sh
.\\S7_CS_Utility.exe
```

**On Linux:**
```sh
./S7_CS_Utility
```

## Application Guide

The main window of the application is divided into several sections.

### Setup Environment

#### UART Wiring
To utilize this utility you need to connect to a UART interface of the PLC. For the pins on the side of the PLC (next to the RUN/STOP LEDs), populate the top row like the following:

![PLC RX-TX pinout](./pics/txrxgnd.png).

One can use any TTL 3.3V device. Obviously you should connect TX pin of the TTL adapter to the RX port of the PLC and RX port of the TTL adapter to the TX port of the PLC.

#### Serial-to-TCP Proxy
The application connects to the PLC's serial port via a TCP socket. You must use a utility like `socat` to forward the serial device to a TCP port. For example, on Linux:
```sh
socat TCP-LISTEN:10001,fork,reuseaddr /dev/ttyUSB0,raw,echo=0
```
Then, in the application, use `localhost` and `10001` in the "PLC Connection" section.

#### Power Supply
This tool requires the ability to power-cycle the PLC to catch the bootloader at the right moment. The original tool used a specific ALLNET device. This C# version has been upgraded to use a standard **Modbus/TCP** controlled power supply (e.g., a smart relay or PDU).

### Using the Application

1.  **Configuration:**
    *   **PLC Connection:** Enter the host and port for your `socat` or other serial-to-TCP proxy.
    *   **Modbus Power Supply:** Enter the IP Address, Port, and Coil Address for your Modbus-controlled power supply. The "Power-On Delay" is the number of seconds the application will wait after turning the power off before turning it back on.

2.  **Upload Stager:**
    *   This is the first primary action. Click the "Upload Stager" button.
    *   The application will power-cycle the PLC and attempt to connect during the bootloader window.
    *   If successful, it will install the initial `stager.bin` payload. The log window will show "Stager is installed and ready."

3.  **Profile Management:**
    *   This feature allows you to manage memory layouts for different devices.
    *   **Create/Edit a Profile:** You can manually add rows to the data grid. Each row represents a memory region with a Name, Address (hex), and Size (bytes). You can also give the profile a model name.
    *   **Save Profile:** Click "Save Profile" to save the current model name and memory regions to a `.json` file.
    *   **Load Profile:** Click "Load Profile" to load a previously saved `.json` file. The model name, data grid, and the "Select Region" dropdown will be populated.

4.  **Memory Dump:**
    *   The stager must be installed before you can dump memory.
    *   **Select a Region:** If you have a profile loaded, you can select a named region from the "Select Region" dropdown to automatically fill the Address and Length fields.
    *   **Manual Entry:** You can also manually type a hex address and a byte length.
    *   **Dump Memory:** Click "Dump Memory". The application will upload the `dump_mem.bin` payload and begin the dump.
    *   Progress is shown in real-time. The dumped file will be saved in the application's root directory (e.g., `mem_dump_10000000_10000400.bin`).

5.  **UART Speed Optimization (Optional):**
    *   For faster memory dumps, you can reconfigure the PLC's UART to a higher baud rate.
    *   **Default Speed:** 38400 baud
    *   **Recommended Speed:** 115200 baud (3x faster)
    *   **Alternative Speeds:** 230400 baud (6x faster) or 460800 baud (12x faster, experimental)
    *   The application will upload the `set_uart_speed.bin` payload to reconfigure the UART.
    *   After successful reconfiguration, you must also update your `socat` command to match the new baud rate:
    ```sh
    # Example for 115200 baud
    socat TCP-LISTEN:10001,fork,reuseaddr /dev/ttyUSB0,raw,echo=0,b115200
    ```
    *   **Note:** UART speed returns to default (38400) after PLC power cycle.

6.  **Dump Comparison:**
    *   This utility helps find identical dump files.
    *   Click "Select Folder & Compare Dumps" and choose the directory containing your `.bin` dump files.
    *   The application will calculate the MD5 hash of each file and display groups of identical files in the results box.
    *   You can also compare two files directly using the "Compare Two Files" section. This will open a new window showing the differences between the two files.

---

## Target Device Overview

In this section we will provide quick overview about the device.

### Hardware
We used an S71200, CPU 1212C DC/DC/DC [6ES7 212-1AE40-0XB0](https://mall.industry.siemens.com/mall/en/WW/Catalog/Product/6ES7212-1AE40-0XB0) for our research.
The SoC in the our device was an A5E30235063 relabelled as Siemens SoC. However, the SoC decapsulation reveals that the SoC is based on Renesas 811005 (model 2010) as illustrated in the figure below:

![PLC SoC Decap](pics/decap3.png)

### Instruction Set
The exact version of the ARM instruction set running on the PLC was queried using the following ARM instruction:
```asm
mrc p15, 0, r0, c0, c0, 0
```
We got a response with value 0x411fc143 (0b1000001000111111100000101000011), meaning that it is a ARM Cortex R4 Revision 3, ARMv7 R, Thumb 2 Real-Time profile SoC with Protected Memory System Architecture (PMSA), based on a Memory Protection Unit (MPU).

### NAND Flash Spec
The S7-1200 DC/DC/DC v2018 is using Micron Technologies NQ281 (FBGA code) 1Gbit (128MB) flash. Using Micron FBGA decoder we could get the part number of the flash. The part number is MT29F1G16ABBDAHC-IT:D. Note that in mid 2019, Siemens updated the NAND Flash to NW812 (MT29F1G08ABBFAH4-ITE:F).

### RAM
Siemens S7-1212C v4 is using a 1GB Winbond W94AD2KB or 256MB W948D2FBJX6E high-speed LPDDR1 SDRAM or a Micron Technologies MT46H32M32LFB5-5 IT (FBGA code D9LRB) in a 90-Ball VFBGA form. The RAM is running at 100Mhz.

## Bootloader UART Protocol Overview

An interesting observation we made when looking at the firmware more deeply to investigate non-invasive access techniques is a protocol over UART during the very early boot stage implemented by the bootloader (v4.2.1). During startup, the bootloader waits for half a second, listening on the serial input to receive a magic sequence of bytes. Upon receiving those bytes in the given timeframe the bootloader enters a special protocol offering a large variety of functionality over serial.

### Initial Handshake

In the bootloader at address `0x0368` is called to wait for a magic string "MFGT1" within half a second. If such a string is encountered, it will answer with the string "-CPU" and return 1 to indicate that the protocol handler is getting executed. The return value of this function is checked at `0x0EDF0` and the protocol handler at `0xF3D0` is entered if the initial handshake has been performed.

### Packet/Message Format
Whenever contents are sent by one party, the following structure is expected by the protocol:
```
<length_byte><contents><checksum_byte>
```
The length is a single byte value field describing the length of `contents`+1. The checksum is a byte that completes the sum of all input bytes (including the length byte) to `0 mod 0x100`.

## Public Talks: 

We presented our research at multiple venues. Here is the list of them: 

 * Special Access Features on PLC’s, Ali Abbasi, Tobias Scharnowski, SCADA Security Scientific Symposium (S4), Jan 2020, Miami, USA.

 * [A Deep Dive Into Unconstrained Code Execution on Siemens S7 PLCs](https://media.ccc.de/v/36c3-10709-a_deep_dive_into_unconstrained_code_execution_on_siemens_s7_plcs), Ali Abbasi, Tobias Scharnowski, Chaos Communication Congress (36C3), December 2019, Leipzig, Germany.

 * [Doors of Durin: The Veiled Gate to Siemens S7 Silicon](https://i.blackhat.com/eu-19/Wednesday/eu-19-Abbasi-Doors-Of-Durin-The-Veiled-Gate-To-Siemens-S7-Silicon.pdf), Ali Abbasi, Tobias Scharnowski, Thorsten Holz, Black Hat Europe, December 2019, London, United Kingdom.
