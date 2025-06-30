import time
import random
import os
from PyQt5.QtCore import QObject, pyqtSignal, QTimer # For emitting signals to GUI

class MockSocatServer(QObject):
    """
    Simulates the socat TCP server behavior.
    Generates mock data for the socat terminal view.
    """
    data_received_from_client = pyqtSignal(str) # To show what client "sends"
    data_sent_to_client = pyqtSignal(str)     # To show what server "sends" (device's perspective)
    socat_log_message = pyqtSignal(str)       # For verbose socat-like hex output

    def __init__(self, port=1238):
        super().__init__()
        self.port = port
        self.is_connected = False
        self.client_expects_greeting = False
        self._activity_timer = QTimer(self)
        self._activity_timer.timeout.connect(self.generate_random_activity)

    def start(self):
        self.is_connected = True
        # self.socat_log_message.emit(f"SIM: socat listening on TCP port {self.port}\n")
        # For actual socat hex view, we'd format this differently
        self.socat_log_message.emit(f">>>> SIM: socat mock server started on port {self.port}\n")
        self._activity_timer.start(3000) # Generate activity every 3s
        return True

    def stop(self):
        self.is_connected = False
        self._activity_timer.stop()
        self.socat_log_message.emit("<<<< SIM: socat mock server stopped\n")

    def send_greeting_to_client(self):
        if self.is_connected:
            greeting = b"\x05-CPU is ready and waiting for beautiful commands\r\n" # Example greeting
            # Simulate socat's verbose hex output for this greeting
            hex_view = self.format_for_socat_log(greeting, direction="<") # Device to socat
            self.socat_log_message.emit(hex_view)
            self.data_sent_to_client.emit(greeting.decode('latin-1', errors='replace')) # Send to client sim

    def receive_data(self, data_str):
        """Simulates client sending data to socat/device."""
        if not self.is_connected:
            return

        data_bytes = data_str.encode('latin-1')
        hex_view = self.format_for_socat_log(data_bytes, direction=">") # Socat to device
        self.socat_log_message.emit(hex_view)
        self.data_received_from_client.emit(data_str) # For client sim to process

        # Basic echo or predefined responses for testing
        if data_str.strip() == "GET_VERSION":
            response = b"VERSION_1.0_SIM\r\n"
            hex_view_resp = self.format_for_socat_log(response, direction="<")
            self.socat_log_message.emit(hex_view_resp)
            self.data_sent_to_client.emit(response.decode('latin-1', errors='replace'))

    def generate_random_activity(self):
        """Generates random data to simulate ongoing socat traffic."""
        if not self.is_connected:
            return

        # Simulate data coming from the "device" (serial) side
        length = random.randint(4, 32)
        random_data = os.urandom(length)
        direction_char = "<" # Data from serial to TCP client

        hex_view = self.format_for_socat_log(random_data, direction_char)
        self.socat_log_message.emit(hex_view)
        # self.data_sent_to_client.emit(random_data.decode('latin-1', errors='replace')) # If client needs to see this raw

    def format_for_socat_log(self, data_bytes, direction=">"):
        """
        Formats data similar to 'socat -x -v' output.
        Example:
        > 2023/11/22 10:30:01.123456  length=4 from=0 to=3
        # DATA IN HEX AND ASCII
        """
        timestamp = time.strftime("%Y/%m/%d %H:%M:%S") + ".%06d" % random.randint(0,999999)
        log_entry = f"{direction} {timestamp} length={len(data_bytes)} from=0 to={len(data_bytes)-1}\n"

        hex_lines = []
        ascii_lines = []
        bytes_per_line = 16

        for i in range(0, len(data_bytes), bytes_per_line):
            chunk = data_bytes[i:i+bytes_per_line]
            hex_dump = ' '.join(f'{b:02x}' for b in chunk)
            ascii_dump = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f"  {hex_dump:<{bytes_per_line*3 -1}}") # Pad to align
            ascii_lines.append(f"  |{ascii_dump:<{bytes_per_line}}|")

        for i in range(len(hex_lines)):
            log_entry += hex_lines[i] + ascii_lines[i] + "\n"
        return log_entry


class MockPowerSupply(QObject):
    """Simulates the power supply control."""
    status_update = pyqtSignal(str) # "ON", "OFF", "CYCLING", "ERROR"
    log_message = pyqtSignal(str)   # For application log

    def __init__(self):
        super().__init__()
        self._is_on = False
        self._cycle_timer = QTimer(self)
        self._cycle_timer.setSingleShot(True)
        self._power_on_action_timer = QTimer(self) # Timer for the second part of cycle
        self._power_on_action_timer.setSingleShot(True)


    def turn_on(self, method_params=None):
        self._is_on = True
        self.log_message.emit(f"SIM: Power supply turned ON. (Params: {method_params})")
        self.status_update.emit("ON")
        return True

    def turn_off(self, method_params=None):
        self._is_on = False
        self.log_message.emit(f"SIM: Power supply turned OFF. (Params: {method_params})")
        self.status_update.emit("OFF")
        return True

    def power_cycle(self, delay_ms, on_complete_callback=None, method_params=None):
        self.log_message.emit(f"SIM: Starting power cycle. Turning OFF. Delay: {delay_ms}ms. (Params: {method_params})")
        self.status_update.emit("CYCLING (OFF)")
        self.turn_off(method_params)

        self._on_complete_callback = on_complete_callback # Store callback

        # Schedule the "power on" part of the cycle
        self._power_on_action_timer.timeout.connect(lambda: self._finish_power_cycle(method_params))
        self._power_on_action_timer.start(delay_ms)

    def _finish_power_cycle(self, method_params):
        self.log_message.emit("SIM: Power cycle delay complete. Turning ON.")
        self.status_update.emit("CYCLING (ON)")
        self.turn_on(method_params) # This will emit "ON"
        if self._on_complete_callback:
            self._on_complete_callback() # Notify that the cycle is done

    def get_status(self):
        return "ON" if self._is_on else "OFF"


class MockClientProcess(QObject):
    """
    Simulates the client.py script, including dump_mem.
    Interacts with MockSocatServer and MockPowerSupply.
    """
    log_message = pyqtSignal(str) # For application log
    dump_progress = pyqtSignal(int) # Percentage
    dump_stats = pyqtSignal(str, str, str) # speed, elapsed, remaining
    dump_complete = pyqtSignal(str) # Output filepath
    dump_error = pyqtSignal(str)    # Error message

    # Signals for interaction with socat sim
    send_to_socat = pyqtSignal(str)

    def __init__(self, mock_socat, mock_power_supply):
        super().__init__()
        self.mock_socat = mock_socat
        self.mock_power_supply = mock_power_supply

        self.is_running = False
        self._dump_timer = QTimer(self)
        self._dump_timer.timeout.connect(self._update_dump_progress)
        self._dump_current_bytes = 0
        self._dump_total_bytes = 0
        self._dump_start_time = 0
        self._dump_output_file = ""
        self._dump_chunk_size = 0

        # Connect to socat's data signal
        if self.mock_socat:
            self.mock_socat.data_sent_to_client.connect(self.handle_socat_data)

    def start_process(self, client_args):
        self.log_message.emit(f"SIM: client.py process started with args: {client_args}")
        self.is_running = True

        # Example: if switch_power is in args, simulate power cycle
        if client_args.get("switch_power", False):
            delay = client_args.get("powersupply_delay", 1000)
            ps_method = client_args.get("powersupply_method", "allnet")
            ps_params = client_args.get("powersupply_params", {})
            self.log_message.emit(f"SIM: Initiating power cycle for client start...")
            self.mock_power_supply.power_cycle(delay, self._post_power_cycle_connect, ps_params)
        else:
            self._post_power_cycle_connect() # Directly try to "connect"

    def _post_power_cycle_connect(self):
        self.log_message.emit("SIM: Attempting to connect to socat after power cycle/start.")
        # Simulate sending initial handshake/magic to socat
        self.send_to_socat.emit("MFGT1AAAA") # From client.py magic
        if self.mock_socat:
             # Client expects a greeting after sending its magic bytes
             self.mock_socat.client_expects_greeting = True
             # In a real scenario, client.py would wait for this greeting.
             # Here, we can have socat send it after a small delay or specific trigger.
             QTimer.singleShot(500, self.mock_socat.send_greeting_to_client)


    def handle_socat_data(self, data_str):
        """Handles data 'received' from the mock_socat (simulating device)."""
        self.log_message.emit(f"SIM Client: Received from socat: {data_str.strip()}")
        if "CPU is ready" in data_str: # Example: Greeting received
            self.log_message.emit("SIM Client: Special access greeting received!")
            # Simulate sending stager, etc.
            self.send_to_socat.emit("LOAD_STAGER_SIM_CMD")
            QTimer.singleShot(300, lambda: self.send_to_socat.emit("STAGER_ACK_SIM_CMD"))


    def stop_process(self):
        self.log_message.emit("SIM: client.py process stopped.")
        self.is_running = False
        if self._dump_timer.isActive():
            self._dump_timer.stop()
            self.dump_error.emit("Dump cancelled by process stop.")

    def start_dump_memory(self, address, length, output_file):
        if not self.is_running:
            self.dump_error.emit("Client process not running.")
            return

        self.log_message.emit(f"SIM: Starting memory dump: addr=0x{address:X}, len={length}, file={output_file}")
        self._dump_start_address = address
        self._dump_total_bytes = length
        self._dump_output_file = output_file
        self._dump_current_bytes = 0
        self._dump_start_time = time.time()

        # Simulate some overhead or command sending
        self.send_to_socat.emit(f"DUMP_MEM_CMD_SIM:ADDR=0x{address:X},LEN={length}")

        # Simulate device responding "Ok" then starting to send data
        QTimer.singleShot(200, lambda: self.mock_socat.data_sent_to_client.emit("Ok")) # Simulate "Ok" from dump_mem.c

        # Determine chunk size for progress updates (e.g., 1-5% of total, or fixed)
        self._dump_chunk_size = max(1, self._dump_total_bytes // 100) # Aim for 100 updates
        self._dump_chunk_size = min(self._dump_chunk_size, 1024 * 4) # Max chunk size for realism
        self._dump_chunk_size = max(self._dump_chunk_size, 16) # Min chunk size

        if self._dump_total_bytes == 0:
            self.dump_progress.emit(100)
            self.dump_stats.emit("0 B/s", "0.0s", "0.0s")
            self.dump_complete.emit(self._dump_output_file)
            # Create an empty file for simulation
            try:
                with open(self._dump_output_file, 'wb') as f:
                    pass # Just create the file
                self.log_message.emit(f"SIM: Zero byte dump saved to {self._dump_output_file}")
            except IOError as e:
                self.dump_error.emit(f"Error creating empty dump file: {e}")
            return

        self._dump_timer.start(50) # Update interval for progress

    def _update_dump_progress(self):
        if not self.is_running:
            self._dump_timer.stop()
            return

        # Simulate receiving a chunk of data
        bytes_this_tick = min(self._dump_chunk_size, self._dump_total_bytes - self._dump_current_bytes)
        # Add slight randomness to simulate variable speed
        bytes_this_tick = int(bytes_this_tick * (0.8 + random.random() * 0.4))
        bytes_this_tick = max(0, bytes_this_tick)


        self._dump_current_bytes += bytes_this_tick

        # Simulate data flowing through socat from device
        if self.mock_socat and bytes_this_tick > 0:
            dummy_chunk_data = os.urandom(bytes_this_tick)
            hex_view = self.mock_socat.format_for_socat_log(dummy_chunk_data, direction="<")
            self.mock_socat.socat_log_message.emit(hex_view)


        if self._dump_current_bytes >= self._dump_total_bytes:
            self._dump_current_bytes = self._dump_total_bytes
            self.dump_progress.emit(100)
            self._dump_timer.stop()

            elapsed_time = time.time() - self._dump_start_time
            speed = self._dump_total_bytes / elapsed_time if elapsed_time > 0 else 0

            # Format for human readability (will be done in GUI, but good to have here too)
            speed_str = f"{speed/1024:.2f} KB/s" if speed > 1024 else f"{speed:.2f} B/s"
            elapsed_str = f"{elapsed_time:.1f}s"

            self.dump_stats.emit(speed_str, elapsed_str, "0.0s")

            # Simulate saving the file
            try:
                with open(self._dump_output_file, 'wb') as f:
                    # Write some dummy data for verisimilitude, matching total size
                    # For large files, write in chunks to avoid memory issues
                    remaining_to_write = self._dump_total_bytes
                    sim_chunk_write_size = 1024 * 1024 # 1MB chunks
                    while remaining_to_write > 0:
                        current_write = min(remaining_to_write, sim_chunk_write_size)
                        f.write(os.urandom(current_write))
                        remaining_to_write -= current_write
                self.log_message.emit(f"SIM: Dump content ({self._dump_total_bytes} bytes) saved to {self._dump_output_file}")
                self.dump_complete.emit(self._dump_output_file)
            except IOError as e:
                self.dump_error.emit(f"Error simulating file save: {e}")

        else:
            progress_percent = int((self._dump_current_bytes / self._dump_total_bytes) * 100)
            self.dump_progress.emit(progress_percent)

            elapsed_time = time.time() - self._dump_start_time
            speed = self._dump_current_bytes / elapsed_time if elapsed_time > 0 else 0

            remaining_bytes = self._dump_total_bytes - self._dump_current_bytes
            eta = remaining_bytes / speed if speed > 0 else float('inf')

            speed_str = f"{speed/1024:.2f} KB/s" if speed > 1024 else f"{speed:.2f} B/s"
            if speed == 0: speed_str = "0 B/s"
            elapsed_str = f"{elapsed_time:.1f}s"
            eta_str = f"{eta:.1f}s" if eta != float('inf') else "N/A"

            self.dump_stats.emit(speed_str, elapsed_str, eta_str)

    def simulate_other_action(self, action_name, payload_file, args_str):
        if not self.is_running:
            self.log_message.emit("SIM Error: Client process not running. Cannot perform action.")
            return

        self.log_message.emit(f"SIM: Action '{action_name}' called.")
        if payload_file:
            self.log_message.emit(f"  Payload: {payload_file}")
        if args_str:
            self.log_message.emit(f"  Arguments: {args_str}")

        # Simulate sending a command for this action
        self.send_to_socat.emit(f"ACTION_SIM:{action_name.upper()}_ARGS={args_str}")

        # Simulate some response after a delay
        QTimer.singleShot(random.randint(500, 2000), lambda:
            self.mock_socat.data_sent_to_client.emit(f"SIM_RESP: Action '{action_name}' processed with result: OK_{random.randint(100,999)}")
        )

# Example usage (for testing simulation.py directly, not part of GUI)
if __name__ == '__main__':
    # This is just for standalone testing of the simulation classes
    app = QApplication(sys.argv) # Needed for QTimer

    def test_socat_log(msg):
        print(f"SOCAT LOG: {msg.strip()}")

    def test_client_log(msg):
        print(f"CLIENT LOG: {msg.strip()}")

    def test_power_log(msg):
        print(f"POWER LOG: {msg.strip()}")

    def test_power_status(status):
        print(f"POWER STATUS: {status}")

    def test_dump_prog(val):
        print(f"DUMP PROGRESS: {val}%")

    def test_dump_stat(s, e, r):
        print(f"DUMP STATS: Speed={s}, Elapsed={e}, Remaining={r}")

    def test_dump_done(fp):
        print(f"DUMP COMPLETE: {fp}. File size: {os.path.getsize(fp)} bytes")
        # app.quit() # Quit after dump for testing

    def test_dump_err(err):
        print(f"DUMP ERROR: {err}")
        # app.quit()

    mock_soc = MockSocatServer()
    mock_soc.socat_log_message.connect(test_socat_log)
    mock_soc.data_sent_to_client.connect(lambda x: print(f"SOCAT->CLIENT_SIM: {x.strip()}"))


    mock_ps = MockPowerSupply()
    mock_ps.log_message.connect(test_power_log)
    mock_ps.status_update.connect(test_power_status)

    mock_cli = MockClientProcess(mock_soc, mock_ps)
    mock_cli.log_message.connect(test_client_log)
    mock_cli.dump_progress.connect(test_dump_prog)
    mock_cli.dump_stats.connect(test_dump_stat)
    mock_cli.dump_complete.connect(test_dump_done)
    mock_cli.dump_error.connect(test_dump_err)
    mock_cli.send_to_socat.connect(mock_soc.receive_data) # Connect client output to socat input

    mock_soc.start()

    # Simulate client start with power cycle
    client_sim_args = {
        "switch_power": True,
        "powersupply_delay": 500,
        "powersupply_method": "allnet_sim",
        "powersupply_params": {"host": "sim_host", "port": 80}
    }
    mock_cli.start_process(client_sim_args)

    # Simulate starting a dump after a delay (e.g., after client is "ready")
    # In GUI, this would be triggered by user action
    def delayed_dump():
        if mock_cli.is_running: # Check if client simulation is "running"
             mock_cli.start_dump_memory(0x1000, 2 * 1024 * 1024, "sim_dump.bin") # 2MB dump
        else:
            print("Client sim not ready for dump yet.")
            # QTimer.singleShot(1000, delayed_dump) # Retry if necessary

    QTimer.singleShot(2000, delayed_dump) # Wait for power cycle and "connection"

    sys.exit(app.exec_())
