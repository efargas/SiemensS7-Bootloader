<p align="center">
  <img src="pics/x-ray.gif" alt="Siemens S7-1200 3D X-Ray"/>
</p>

# Siemens S7 PLCs Bootloader Arbitrary Code Execution Utility (GUI Edition)

This repository contains a modernized, GUI-based tool for interacting with the Siemens S7 PLC bootloader to achieve non-invasive arbitrary code execution over UART. This work is based on the vulnerability SSA-686531 (CVE-2019-13945).

This version has been updated to Python 3 and features a PyQt5 graphical user interface for ease of use.

## Target Device Overview

(The hardware and technical details of the target device remain the same as the original research.)

... (Keeping the original sections for Target Device Overview, Bootloader UART Protocol Overview, etc.) ...

## Non-Invasive Arbitrary Code Execution

Using a combination of the functionality provided by the bootloader, we were able to gain arbitrary code execution on the device using the UART protocol. The core logic is implemented in `src/logic/plc_client.py`.

The idea behind the implementation is as follows:
- Use the subprotocol handler's memory RAM update component to inject a custom shellcode payload to IRAM.
- Use the subprotocol handler's memory RAM update component to create a function pointer to the custom shellcode above by injecting an additional hook address into the additional hook table in IRAM.
- Use the handler `0x1c` to call the custom shellcode.

## Setup and Usage

### 1. Hardware Setup

The hardware setup is the same as in the original project. You need to connect to the UART interface of the PLC.

#### UART Wiring
To be able to utilize this utility you need to connect to a UART interface of the PLC. For the pins on the side of the PLC (next to the RUN/STOP LEDs), populate the top row like the following: 

![PLC RX-TX pinout](./pics/txrxgnd.png).

One can use any TTL 3.3V device. Obviously you should connect TX pin of the TTL adapter to the RX port of the PLC and RX port of the TTL adapter to the TX port of the PLC. 

### 2. Software Setup

The original command-line tool has been replaced with a Python 3 based GUI application.

#### Dependencies
First, install the required Python libraries.
```bash
pip install -r requirements.txt
```
You also still need the `arm-none-eabi` compiler to build the payloads from source.

#### Compiling Payloads
The payloads are located in the `payloads/` directory. Most of them are written in C and need to be compiled.
```bash
cd payloads/dump_mem
make
```
Repeat this for other payloads like `hello_loop` and `tic_tac_toe`.

#### Forwarding UART to TCP
The client utility connects to a TCP socket. You need to forward the serial device (e.g., `/dev/ttyUSB0`) to a local TCP port. The `start.sh` script can be used for this. Make sure to edit it if your serial device is not `/dev/ttyUSB0`.
```bash
sh start.sh
```
This will start `socat` to listen on port 9999 and forward data to/from the serial device. Keep this running in a separate terminal.

### 3. Running the GUI Application

With the setup complete, you can run the main application:
```bash
python3 main.py
```

This will open the GUI, which allows you to:
- **Connect** to the PLC (with an option to cycle the power supply).
- **Dump Memory**: Specify an address and length, and save the memory dump to a file.
- **Run Test Payload**: Upload and execute a test payload.
- **Play Tic-Tac-Toe**: Run the Tic-Tac-Toe payload and interact with it through the GUI.

All actions and logs are displayed in the application window.

## Public Talks

(This section remains the same)
...
