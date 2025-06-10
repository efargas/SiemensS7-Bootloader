# Mitsubishi FX3U Modbus TCP Server Configuration Guide

This guide provides general steps for configuring a Mitsubishi FX3U series PLC to act as a Modbus TCP server, allowing an external client (like the `switch_power.py` script) to read/write PLC data. This guide assumes you are using GX Works 2.

## 1. Prerequisites

*   **Mitsubishi FX3U Series PLC**: Ensure your PLC CPU supports Ethernet communication. This might be via a built-in Ethernet port (e.g., FX3GE) or an add-on Ethernet module (e.g., FX3U-ENET, FX3U-ENET-L).
*   **GX Works 2 Software**: Used for PLC programming and parameter configuration.
*   **Ethernet Cable**: For connecting the PLC to your network.

## 2. PLC Parameter Configuration (GX Works 2)

### 2.1. Navigate to PLC Parameters
    a. Open your project in GX Works 2.
    b. In the project tree, find "PLC Parameter" and double-click to open the settings.

### 2.2. Configure Ethernet Port Settings
    a. In the PLC Parameter window, look for a tab or section related to "Ethernet Port Settings," "Built-in Ethernet Port Setting," or the specific Ethernet module you are using (e.g., "FX3U-ENET-L").
    b. **Set the following IP parameters**:
        *   **IP Address**: Assign a unique static IP address to your PLC (e.g., `192.168.1.10`).
        *   **Subnet Mask**: Set the appropriate subnet mask for your network (e.g., `255.255.255.0`).
        *   **Default Gateway Address**: Configure if your PLC needs to communicate outside its local subnet (e.g., `192.168.1.1`).
        *   Ensure other settings like "Operation Setting" enable the port for communication.
    c. Apply these settings.

### 2.3. Configure Modbus TCP Connection (Open Settings)
    a. Within the Ethernet settings (or sometimes a dedicated "Exchange Ssettings" or "External Device Configuration" area), you need to configure a TCP connection that will listen for Modbus requests.
    b. **Create a new connection or configure an existing one**:
        *   **Protocol**: Select `TCP`.
        *   **Open System / Host (Side) Communication Port Number**: Set to `502`. This is the standard port for Modbus TCP.
        *   **PLC side Port Number / Self Port Number**: Also set to `502`.
        *   **Open Mode / Mode**: Set to `TCP Passive` or `Server` (or sometimes "MC Protocol" if Modbus is tunneled or a sub-function). Some modules might require using an "Unpassive" or "Active" setting if they are initiating connections, but for a server, it should be passive/listening.
        *   **Target Device IP Address / Host IP Address**: Usually set to `0.0.0.0` or `255.255.255.255` to accept connections from any client, or a specific client IP if desired.
    c. **Note on specific modules**:
        *   Some older Ethernet modules might not have an explicit "Modbus TCP" option. Enabling TCP communication on port 502 often implicitly activates the Modbus TCP server functionality.
        *   Modules like the FX3U-ENET-ADP have a dedicated "MODBUS TCP/IP Setting Tool" or specific parameters within GX Works 2 for enabling Modbus. Consult your module's manual.
    d. Apply these settings. You will likely need to write these parameters to the PLC and reboot it.

## 3. PLC Programming

### 3.1. Implement Control Logic
    a. You need a PLC program to act on the data written by the Modbus client and to control your desired outputs.
    b. A sample Structured Text (ST) program is provided in this directory: `modbus_control.st`. This program uses an internal coil `M8000` (intended to be Modbus-accessible) to control a physical output `Y0`.
    c. In GX Works 2, create a new Program Block (POU), select "Structured Text" as the language, and copy the contents of `modbus_control.st` into it.
    d. Ensure this program block is called by a PLC task (e.g., the main scan task).

### 3.2. Download Program and Parameters
    a. After configuring parameters and writing/adding your PLC program, download both to the PLC.
    b. The PLC usually needs to be restarted for new Ethernet parameters to take effect.

## 4. Modbus Address Mapping

Modbus clients access PLC data using Modbus addresses, which are mapped to the PLC's internal devices.

*   **Coils (Read/Write Bits - Modbus Function Codes 01, 05, 15)**:
    *   Typically map to PLC M-coils (auxiliary relays) or Y-outputs.
    *   Example: Modbus coil `00001` might map to `M0` or `Y0`. The `modbus_control.st` example uses `M8000`. You need to determine its corresponding Modbus coil address.
*   **Discrete Inputs (Read-Only Bits - Modbus Function Code 02)**:
    *   Typically map to PLC X-inputs.
*   **Holding Registers (Read/Write 16-bit Words - Modbus Function Codes 03, 06, 16)**:
    *   Typically map to PLC D-registers (data registers).
    *   Example: Modbus holding register `40001` might map to `D0`.
*   **Input Registers (Read-Only 16-bit Words - Modbus Function Code 04)**:
    *   Typically map to PLC D-registers (read-only) or special registers (SD).

**Crucial**: The exact mapping (e.g., if Modbus coil 1 is M0 or M8000) **varies depending on the specific Mitsubishi Ethernet module and its configuration**. You MUST consult the manual for your Ethernet module (e.g., FX3U-ENET-L Communication User's Manual) to find the correct device mapping table. Some modules allow configuring these maps. For the `modbus_control.st` example, if you use `M8000`, find out what Modbus coil address it corresponds to and configure `switch_power.py` to use that address for `--fx3u-output`.

## 5. Important Considerations

*   **Adapt to Your Setup**: The IP addresses, PLC device numbers (M8000, Y0), and Modbus addresses mentioned here are examples. Adjust them to match your specific hardware, network, and application requirements.
*   **Manuals are Key**: This is a general guide. **Always refer to the official Mitsubishi manuals** for your specific PLC CPU and Ethernet module model for detailed and authoritative instructions.
*   **Testing**: Thoroughly test the Modbus communication and your PLC logic to ensure it behaves as expected before deploying in a critical application.
*   **GX Works 2 Variations**: Menu names and parameter locations might vary slightly depending on your GX Works 2 version and the specific PLC/module firmware.

Good luck!
```
