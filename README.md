<p align="center">
  <img src="pics/x-ray.gif" alt="Siemens S7-1200 3D X-Ray"/>
</p>


# Siemens S7 PLCs Bootloader Arbitrary Code Execution Utility

This repository describes the way we get non-invasive arbitrary code execution on the Siemens S7 PLC by using an undocumented bootloader protocol over UART. Siemens assigned SSA-686531 (CVE-2019-13945) for this vulnerability. Affected devices are Siemens S7-1200 (all variants including SIPLUS) and S7-200 Smart. The list of the content are as follows:






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

An interesting observation we made when looking at the firmware more deeply to investigate non-invasive access techniques is a protocol over UART during the very early boot stage implemented by the bootloader (v4.2.1). During startup, the bootloader waits for half a second, listening on the serial input to receive a magic sequence of bytes. Upon receiving those bytes in the given timeframe the bootloader enters a special protocol offering a large variety of functionality over serial. A client for the UART protocol containing functionality to execute payloads on the PLC from within early boot is implemented in [this utility](client.py).


### Initial Handshake

In the bootloader at address `0x0368` is called to wait for a magic string "MFGT1" within half a second. If such a string is encountered, it will answer with the string "-CPU" and return 1 to indicate that the protocol handler is getting executed. The return value of this function is checked at `0x0EDF0` and the protocol handler at `0xF3D0` is entered if the initial handshake has been performed.




### Handler Types
The UART protocol handler exposes a list of low level functions. There are multiple layers of handlers present in the system:
1. Primary Handlers: A primary list of handlers that can be invoked directly from the first protocol stage. They are stored in a table inside the bootloader starting at address `0x014D98` with 128 entries.
2. Additional Hooks: The first stage handler residing at address `0x00011180` with the assigned handler index `0x1c` allows calling hooks from a second list starting at `0x00015280`. 
3. Subprotocol: A Primary Handler 0x80 at `0x0000D1F0` (handler index `0x80`) enters an additional menu loop exposing what seems to be a setup/read/write triple of operations for different kinds of devices/components in the system such as flash, IRAM and an unknown device type.


### Packet/Message Format
Whenever contents are sent by one party, the following structure is expected by the protocol:
```
<length_byte><contents><checksum_byte>
```
The length is a single byte value field describing the length of `contents`+1. The checksum is a byte that completes the sum of all input bytes (including the length byte) to `0 mod 0x100`.



### Handler Type Implementations

#### 1. Primary Handler
The Primary Handler function is located at `0x0000EE48`. Commands are accepted in the form of single packets/messages as described above. After a correctly checksum packet is received, the first byte of the packet is interpreted as the command number.

For command number `0x80`, the Subprotocol handler is invoked in a mode based on the next two bytes of the incoming message (`0x3BC2`: mode 1, `0x9D26`: mode 2, `0xE17A`: mode 3, `0xC54F`: mode 4).
Command number `0xA2` represents the exit command. Command `0xA0` allows some configuration of the UART protocol. The semantics are not yet exactly determined.

For command numbers lower or equal `0xB0`, the respective Primary Hook inside the handler table starting at `0x00014D98` is invoked.



#### 2. Additional Hooks
A second layer of handlers is accessible via the first stage handler residing at address `0x00011180` with the assigned handler index `0x1c`. It relays invocations to a second layer of functions based on the arguments provided inside the packets sent by the other side of the protocol. The list of this secondary handler is initially stored in a table starting at `0x00015280` inside the bootloader. Before actual usage the table is then copied over to `0x1003ABA0` and then the copy in RAM is accessed rather than contents in the bootloader. This is important as overriding the actually used function pointers does not involve modifying bootloader memory (which may expected to be read-only and may trigger detection mechanisms and failing checksum tests).

The table containing the additional hooks has 33 entries. The index of this hook is checked against the boundaries `0<=index<=32`. Also, each table entry contains information about the length of the input expected by the particular additional hook:
- `0`: The handler is disabled
- `1-0xfe`: The input length has to match the given value exactly
- `0xff`: Variable input length


A list of the Additional hooks can be retrieved from the list inside the bootloader starting at `0x15280` . The reversing maturity of those handlers is not very advanced so a list is not generated here. Looking at the actual functions should be the best option to understand the range of functionality should the need arise. By default most handlers are disabled from being executed directly.






##### Subprotocol (Primary Handler `0x80`) Details
This handler seems to be responsible for performing updates of different components over UART. To enter this protocol in one of four modes, handler `0x80` has to be invoked with a 2-byte argument describing the mode used by the sub handler. Every mode corresponds to one component to be updated:

| Mode Number | Component |
| ----------- | --------- |
| 1 | Hardware device mapped to memory around region `0x10000000`. This seems to match IRAM memory |
| 2 | SPI1 / IOC mappings are used here, exact component so far unknown |
| 3 | Firmware flash memory |
| 4 | NOP |

For each component, three to four types of functions are supported. The rough semantics are: Preparation/Setup, (Metadata) Read, (Update) Write, Cleanup.

When the subprotocol handler is entered, another loop handling commands sent via UART is performed. At least one argument byte is expected from here which - together with the overall input length - acts as a switch for the function to be used.

The handler that is the most important for getting code execution is handler number 1 (writes internal memory such as ITCM and IRAM).
A way to update flash contents is sub-handler number 3. 




## Non-Invasive Arbitrary Code Execution
Using a combination of the functionality provided above we were able to gain arbitrary code execution on the device using the UART protocol. The client implementing this is located at [client.py](client.py).

The idea behind the implementation is as follows:
- Use the subprotocol handler's memory RAM update component to inject a custom shellcode payload to IRAM. This is implemented as the first step in the function `_exploit_install_add_hook` in [client.py](client.py)
- Use the subprotocol handler's memory RAM update component to create a function pointer to the custom shellcode above by injecting an additional hook address into the additional hook table in IRAM at `0x1003ABA0`. This is implemented as the second step in the function `_exploit_install_add_hook` in [client.py](client.py)
- Use the handler `0x1c` to call the custom shellcode. This is implemented in the function `invoke_add_hook` in [client.py](client.py)




#### RCE in older PLCs
We spotted similar functionality in 2014 models of S7-1212C Siemens PLCs (6ES7212-1BE31-0XB0). The bootloader functionality was spotted at offset 0xE664 of older PLC bootloader (S7-1200v3).

## Setup Environment

To use this utility, you'll need to set up a specific hardware and software environment.

### Hardware Requirements

*   An affected Siemens S7-1200 PLC (e.g., CPU 1212C DC/DC/DC [6ES7 212-1AE40-0XB0]).
*   A TTL 3.3V USB to Serial adapter (e.g., FTDI FT232RL).
*   **Power Supply for PLC:** A method to power cycle the PLC. This can be:
    *   A network-controlled power socket (e.g., ALLNET ALL3075V3, controlled via HTTP as detailed below). If used, ensure it's configured to a known IP address (e.g., `192.168.0.100`).
    *   A Mitsubishi FX3U PLC (or compatible) controlling the S7 PLC's power, accessible via Modbus TCP.

### Software Requirements and Setup Instructions

We recommend using **Ubuntu 20.04 LTS (Focal Fossa)** for the most straightforward setup, as this project relies on Python 2 and specific versions of build tools.

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```
    *(Replace `<repository_url>` and `<repository_name>` with the actual URL and cloned directory name)*

2.  **Install system dependencies:**
    This includes Python 2, tools to get pip for Python 2, build essentials, Clang (used for compiling payloads), the ARM cross-compiler toolchain, socat (for UART communication), make, and git.
    ```bash
    sudo apt-get update
    sudo apt-get install -y python2 python-is-python2 curl git build-essential clang gcc-arm-none-eabi socat make
    ```
    *Note: `python-is-python2` makes the `python` command point to `python2`. The scripts use `#!/usr/bin/env python2` so this is for convenience if you invoke them manually with `python`.*

3.  **Install pip for Python 2:**
    ```bash
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
    sudo python2 get-pip.py
    rm get-pip.py
    ```

4.  **Install required Python 2 libraries:**
    The client scripts and power supply control script require `pwntools`, `requests` (for HTTP power control), and `pymodbus` (for Modbus power control).
    ```bash
    sudo pip2 install pwntools requests pymodbus
    ```

### UART Wiring
To be able to utilize this utility you need to connect to a UART interface of the PLC. For the pins on the side of the PLC (next to the RUN/STOP LEDs), populate the top row like the following: 

![PLC RX-TX pinout](./pics/txrxgnd.png).

Connect your TTL 3.3V adapter as follows:
*   Adapter TX pin to PLC RX pin.
*   Adapter RX pin to PLC TX pin.
*   Adapter GND pin to PLC GND pin.

## Using our tool

Once your environment is set up and hardware connected:

1.  **Identify your TTYUSB adapter:**
    Connect your USB to TTL adapter. It will typically appear as `/dev/ttyUSB0` on a Linux machine. This path is hardcoded in `start.sh` but can be changed if needed.

2.  **Configure and Control Power Supply (if used for automated power cycling):**
    The `client.py` script can automate power cycling of the target S7 PLC using the `tools/powersupply/switch_power.py` script. This script supports different types of power control mechanisms.

    **Using `tools/powersupply/switch_power.py` directly:**
    This script can be used manually or invoked by other scripts (like `client.py`).

    Common arguments:
    *   `mode`: `on` or `off` (positional argument, required)
    *   `--ps-type`: Specifies the type of power supply. Choices: `http` (default), `mitsubishi_modbus`.

    **HTTP Power Supply (e.g., ALLNET ALL3075V3):**
    This is the default type.
    *   `--host <ip_address>`: IP address or hostname of the HTTP power supply (default: `powersupply`).
    *   `--port <port_number>`: Port of the HTTP power supply (default: `80`).
    Example:
    ```bash
    python tools/powersupply/switch_power.py --ps-type http --host 192.168.0.100 --port 80 on
    ```

    **Mitsubishi FX3U Modbus TCP Power Supply:**
    Uses a Mitsubishi FX3U PLC (or compatible) to control power to the S7 PLC via a Modbus TCP command to a coil.
    *   `--modbus-host <ip_address>`: IP address of the Mitsubishi PLC. (Required if `ps-type` is `mitsubishi_modbus`)
    *   `--modbus-port <port_number>`: Modbus TCP port of the PLC (default: `502`).
    *   `--modbus-coil <coil_address>`: Modbus coil address (0-indexed) to write to (default: `0`). This coil on the Mitsubishi PLC should be wired to control the S7 PLC's power.
    Example:
    ```bash
    python tools/powersupply/switch_power.py --ps-type mitsubishi_modbus --modbus-host 192.168.1.10 --modbus-coil 0 on
    ```

    **Integration with `client.py`:**
    When using `client.py` with the `--switch-power` option, `client.py` itself needs to be configured to pass the correct parameters to `tools/powersupply/switch_power.py`. The original `client.sh` and `client.py` are set up for the HTTP power supply. To use the Mitsubishi Modbus method with `client.py`, you would need to modify `client.py` to accept and pass through the Modbus-specific arguments (like `--ps-type mitsubishi_modbus`, `--ps-modbus-host`, etc.) to `switch_power.py`. Refer to the `Conceptual Changes` section of the development log for how `client.py` might be adapted. The `client.sh` script would also need to be updated to pass these new arguments to `client.py`.

3.  **Compile Payloads:**
    The C payloads need to be compiled for the ARM Cortex-R4 CPU. Navigate to the specific payload directory and use `make`. For example, for `hello_loop`:
    ```bash
    cd payloads/hello_loop/
    make
    cd ../..  # Go back to the main directory (e.g., uart_rce)
    ```
    Similarly for other C-based payloads like `dump_mem` or `tic_tac_toe`.
    Some assembly payloads (like `hello_world` or `stager`) have a `build.sh` script:
    ```bash
    cd payloads/hello_world/
    sh build.sh
    cd ../..
    ```

4.  **Start UART to TCP Forwarding:**
    The `start.sh` script (typically found in the `uart_rce` folder if you've structured the project that way, or the root of this repository) uses `socat` to forward the serial data from `/dev/ttyUSB0` to a local TCP port. This allows the Python client to communicate with the PLC. Open a terminal and run:
    ```bash
    # Example: sh start.sh (assuming start.sh is in the current path)
    # This script usually needs to keep running in its own terminal.
    ```
    *(Ensure `start.sh` is executable and correctly configured for your TTY device and desired TCP port if you modify it from the original project structure.)*

The original README mentioned going to `uart_rce` folder. If your main scripts like `client.sh`, `start.sh`, `client.py` are in the root of this repository, adjust paths accordingly or operate from the directory where these scripts are located.

The `README.md` previously mentioned: "Once you copied our repo go to uart_rce folder." and "To actually compile the payload go to `uart_rce/payloads` folder."
If the project structure implies a `uart_rce` subfolder, users should `cd uart_rce` after cloning. The instructions above assume operations from the root of *this* repository for clarity on paths like `payloads/hello_loop/`. Adjust if your scripts are in a `uart_rce` subdirectory.


To actually compile the payload go to `payloads` folder (relative to where `client.sh` is run, or `uart_rce/payloads` if such a structure exists). There are various payloads available. For C-based payloads with a Makefile (like `dump_mem`, `hello_loop`, `tic_tac_toe`):
```bash
cd payloads/<payload_name>/
make
cd ../.. # Adjust path to return to where client.sh is
```
For example, to compile the `hello_world` assembly payload (which uses `build.sh`):
```console
cd payloads/hello_world/
sh build.sh
cd ../.. # Adjust path
```

Once we are done compiling the payloads for Cortex-R4 CPU, we can open the channel for forwarding our UART serial data to a TCP port which will be used by our client utility. This console window should show you raw UART traffic between PLC and client utility:

```console
# Assuming start.sh is in the current directory or your PATH
sh start.sh
```
Make sure `start.sh` correctly points to your `/dev/ttyUSB0` (or equivalent) and uses the TCP port expected by `client.py` (default is 4444, but `client.py` takes it as an argument).

### DEMO 1: Upload and executing stager and test payloads

Now, we can use our client utility. Open a new console window (without closing the console which runs `start.sh`), and type the following command for uploading the stager and test payload to the UART:


```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce/payloads/hello_world/$ sh build.sh
```

Once we are done compiling the payloads for Cortex-R4 CPU, we can open the channel for forwarding our UART serial data to a TCP port which will be used by our client utility. This console window should show you raw UART traffic between PLC and client utility:

```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce$ sh start.sh
```

### DEMO 1: Upload and executing stager and test payloads 

Now, we can use our client utility. Open a new console window (without closing the console which runs `start.sh`), and type the following command for uploading the stager and test payload to the UART: 

```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce$ sh client.sh --switch-power --powersupply-delay=1 test
```

The `--powersupply-delay` is provided for Cold-boot style firmware dumping (we do not use it at this stage but providing this item is required). The argument `test` uses the payload in `payloads/hello_world/hello_world.bin` file. This payload literraly just run inside the PLC and send string `TEST` back to the client, thus client knows the code successfully executed inside the PLC.  






### DEMO 2: Upload and execution Tic-tac-toe inside the S7 PLC


In this demo we decided to upload the Tic-tac-toe game to the PLC. The goal of this demo is to demonstrate running more complex form of programs inside the PLC. To upload the game, you need to first compile it: 



```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce/payloads/tic_tac_toe$ make
cc tic_tac_toe.c
cc ../lib/stdlib.c
cc ../lib/print.c
cc ../lib/string.c
cc ../lib/read.c
ld tic_tac_toe.sym
strip tic_tac_toe
objcopy tic_tac_toe.ihex
objcopy tic_tac_toe.bin
```

Now we must use the tictactoe mode of our script utility as it allows us to interact with the PLC and have stream of input/output:


```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce$ sh client.sh --switch-power --powersupply-delay=1 tictactoe --payload=payloads/tictactoe/build/tictactoe.bin
```

Note that the tictactoe mode, allow us to use alternative payloads using `--payload` argument. So we are not bounded to only use the tictactoe.bin payload. 


### DEMO 3: Running the Greetings From PLC in an infinite loop

We have alternate version of `hello_world` which the PLC instead of sending a single string `TEST` back to the client utility, it will send string `Gretings from PLC` in an infinite loop to the client utility.  This payload is located inside `uart_rce/payloads/hello_loop/`. Since this payload is written in C, you need to compile it using make command: 


```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce/payloads/hello_loop$ make
cc hello_loop.c
cc ../lib/stdlib.c
cc ../lib/print.c
cc ../lib/string.c
cc ../lib/read.c
ld hello_loop.sym
strip hello_loop
objcopy hello_loop.ihex
objcopy hello_loop.bin
```

This will generate `hello_loop.bin` file, which will be used by our client utility and will be uploaded to the PLC to get executed. Now we can send the payload to the PLC using tictactoe mode with different payload:


```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce$ sh client.sh --switch-power --powersupply-delay=1 tictactoe --payload=payloads/hello_loop/build/hello_loop.bin
```



### DEMO 4: Dumping S7 PLC RAM

To dump the PLC memory, we would recommend to first turn on the PLC for few seconds, to let the PLC copy contents of the NAND flash to the RAM (alternatively you can wait as long as you want!). We specially designed `--powersupply-delay` argument in our utility for this purpose. We use dump mode in our utility followed by `-a` argument which user supplies address to dump and `-l` argument for the byte size. 

Similar to other demos we need to first compile our payload:

```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce/payloads/dump_mem$ make
cc dump_mem.c
cc ../lib/stdlib.c
cc ../lib/print.c
cc ../lib/string.c
cc ../lib/read.c
ld dump_mem.sym
strip dump_mem
objcopy dump_mem.ihex
objcopy dump_mem.bin
```


Now we are ready to dump the PLC. Here we put power supply delay argument to 30 seconds (PLC turn on, wait 30 seconds for PLC to boot, then reset it and use special access feature). 


```console
research@ali-Plex-9:~/SiemensS7-Bootloader/uart_rce$ sh client_bricked.sh --switch-power --powersupply-delay=30 dump -a 0x691E28 -l 256
```

In this example, we dump 256 bytes starting from offset `0x691E28` of the PLC memory. Once utility dump the memory, it place it in `uart_rce/` folder with the prefix `mem_dump_` plus start and end range address (mem_dump_00691e28_00691f28). 



## Possible Issues: 

The client utility generally inform you about existence of special access feature on the PLC bootloader. It also fetch the bootloader version from the PLC, as shown below:

```console
Looping now
[+] Got connection
[+] Got special access greeting: -CPU [2d435055]
[*] sending packet: 0200fe
[+] Got PLC bootLoader version: V4.2.1
[*] sending packet: 04803bc27f
```


Our utility currently only supports S7 bootloader version `4.2.1`. The client utility can inform you which bootloader version you are using but fails to communicate with stager or upload the payload. To use it with different S7 PLC with other bootloader version, you probably need to dump the new bootloader from the PLC SPI flash (no desoldering required) and identify various hardcoded function addresses we have in `uart_rce/payloads/`, `uart_rce/stager/` and `uart_rce/lib/`. 





## Public Talks: 

We presented our research at multiple venues. Here is the list of them: 

 * Special Access Features on PLC’s, Ali Abbasi, Tobias Scharnowski, SCADA Security Scientific Symposium (S4), Jan 2020, Miami, USA.

 * [A Deep Dive Into Unconstrained Code Execution on Siemens S7 PLCs](https://media.ccc.de/v/36c3-10709-a_deep_dive_into_unconstrained_code_execution_on_siemens_s7_plcs), Ali Abbasi, Tobias Scharnowski, Chaos Communication Congress (36C3), December 2019, Leipzig, Germany.

 * [Doors of Durin: The Veiled Gate to Siemens S7 Silicon](https://i.blackhat.com/eu-19/Wednesday/eu-19-Abbasi-Doors-Of-Durin-The-Veiled-Gate-To-Siemens-S7-Silicon.pdf), Ali Abbasi, Tobias Scharnowski, Thorsten Holz, Black Hat Europe, December 2019, London, United Kingdom.


