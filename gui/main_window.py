import sys
import glob
from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QStatusBar, QTabWidget, QTextEdit, QSizePolicy, QFileDialog
from PyQt5.QtCore import QProcess
from gui.power_widget import PowerSupplyWidget
from gui.connection_widget import ConnectionWidget
from gui.dump_widget import DumpWidget
from gui.payload_widget import PayloadWidget
from gui.threads import PLCConnectionThread, MemoryDumpThread, ExecutePayloadThread
from gui.utils import show_message
from gui.collapsible_groupbox import CollapsibleGroupBox

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PLC Exploitation Tool (Refactored)")
        self.setGeometry(100, 100, 900, 700)
        self.client_instance = None
        self.socat_process = None
        self._setup_ui()

    def _setup_ui(self):
        central = QWidget()
        layout = QVBoxLayout(central)
        self.power_widget = PowerSupplyWidget()
        self.connection_widget = ConnectionWidget()
        self.dump_widget = DumpWidget()
        self.payload_widget = PayloadWidget()
        self.power_group = CollapsibleGroupBox("Power Supply Configuration")
        self.power_group.addWidget(self.power_widget)
        self.connection_group = CollapsibleGroupBox("Connection Configuration")
        self.connection_group.addWidget(self.connection_widget)
        self.dump_group = CollapsibleGroupBox("Memory Dump")
        self.dump_group.addWidget(self.dump_widget)
        self.payload_group = CollapsibleGroupBox("Payload Execution")
        self.payload_group.addWidget(self.payload_widget)
        layout.addWidget(self.power_group)
        layout.addWidget(self.connection_group)
        layout.addWidget(self.dump_group)
        layout.addWidget(self.payload_group)
        self.setCentralWidget(central)
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self._setup_terminals(layout)
        self._connect_signals()
        self._set_initial_button_states()

    def _setup_terminals(self, layout):
        self.terminal_tabs = QTabWidget()
        self.socat_output_terminal = QTextEdit()
        self.socat_output_terminal.setReadOnly(True)
        self.socat_output_terminal.setMinimumHeight(180)
        self.socat_output_terminal.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.terminal_tabs.addTab(self.socat_output_terminal, "socat Output")
        self.program_output_terminal = QTextEdit()
        self.program_output_terminal.setReadOnly(True)
        self.program_output_terminal.setMinimumHeight(180)
        self.program_output_terminal.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.terminal_tabs.addTab(self.program_output_terminal, "Program Output")
        layout.addWidget(self.terminal_tabs, stretch=1)

    def _connect_signals(self):
        self.power_widget.power_on_requested.connect(self._handle_power_on)
        self.power_widget.power_off_requested.connect(self._handle_power_off)
        self.connection_widget.connect_requested.connect(self._handle_connect)
        self.connection_widget.disconnect_requested.connect(self._handle_disconnect)
        self.connection_widget.start_socat_requested.connect(self._handle_start_socat)
        self.connection_widget.stop_socat_requested.connect(self._handle_stop_socat)
        self.connection_widget.autodetect_requested.connect(self._handle_autodetect_devices)
        self.dump_widget.start_dump_requested.connect(self._handle_start_dump)
        self.dump_widget.browse_payload_requested.connect(self._handle_browse_dump_payload)
        self.dump_widget.browse_output_requested.connect(self._handle_browse_dump_output)
        self.payload_widget.execute_payload_requested.connect(self._handle_execute_payload)
        self.payload_widget.browse_payload_requested.connect(self._handle_browse_payload_payload)

    def _set_initial_button_states(self):
        self.connection_widget.connect_button.setEnabled(True)
        self.connection_widget.disconnect_button.setEnabled(False)
        self.dump_widget.start_dump_button.setEnabled(False)
        self.payload_widget.execute_button.setEnabled(False)
        self.connection_widget.start_socat_button.setEnabled(True)
        self.connection_widget.stop_socat_button.setEnabled(False)

    def _set_connected_button_states(self):
        self.connection_widget.connect_button.setEnabled(False)
        self.connection_widget.disconnect_button.setEnabled(True)
        self.dump_widget.start_dump_button.setEnabled(True)
        self.payload_widget.execute_button.setEnabled(True)

    def _set_disconnected_button_states(self):
        self.connection_widget.connect_button.setEnabled(True)
        self.connection_widget.disconnect_button.setEnabled(False)
        self.dump_widget.start_dump_button.setEnabled(False)
        self.payload_widget.execute_button.setEnabled(False)

    def _set_socat_running_states(self):
        self.connection_widget.start_socat_button.setEnabled(False)
        self.connection_widget.stop_socat_button.setEnabled(True)

    def _set_socat_stopped_states(self):
        self.connection_widget.start_socat_button.setEnabled(True)
        self.connection_widget.stop_socat_button.setEnabled(False)

    def _handle_autodetect_devices(self):
        self._log("Autodetecting serial devices...")
        patterns = ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*"]
        found = []
        for pattern in patterns:
            found.extend(glob.glob(pattern))
        found = sorted(set(found))
        self.connection_widget.tty_combo.clear()
        if not found:
            self.connection_widget.tty_combo.addItem("")
            self._log("No common serial devices found automatically. Please enter manually if needed.")
        else:
            for device in found:
                self.connection_widget.tty_combo.addItem(device)
                self._log(f"Found: {device}")
        self.status_bar.showMessage(f"Device detection complete. Found {len(found)} potential devices.")

    def _handle_power_on(self, ip, port, output):
        from client import switch_power
        self._log(f"Power ON requested: {ip}:{port} output {output}")
        if switch_power('on', ip, port, output):
            self._log("Power ON command successful.")
            self.status_bar.showMessage("Power ON successful.")
        else:
            self._log("Power ON command failed.")
            show_message(self, "Power Control", "Failed to turn power ON.", "error")

    def _handle_power_off(self, ip, port, output):
        from client import switch_power
        self._log(f"Power OFF requested: {ip}:{port} output {output}")
        if switch_power('off', ip, port, output):
            self._log("Power OFF command successful.")
            self.status_bar.showMessage("Power OFF successful.")
        else:
            self._log("Power OFF command failed.")
            show_message(self, "Power Control", "Failed to turn power OFF.", "error")

    def _handle_connect(self, host, port, tty):
        self._log(f"Connect requested: {host}:{port} tty={tty}")
        stager_path = "payloads/stager/stager.bin"
        self.connection_thread = PLCConnectionThread(host, port, stager_path, self)
        self.connection_thread.connection_succeeded.connect(self._on_connected)
        self.connection_thread.connection_failed.connect(self._on_connect_failed)
        self.connection_thread.start()
        self.status_bar.showMessage("Connecting to PLC...")
        self._set_connected_button_states()

    def _on_connected(self, version, greeting):
        self._log(f"Connected to PLC. Version: {version}, Greeting: {greeting}")
        self.status_bar.showMessage(f"Connected to PLC. Version: {version}")
        self._set_connected_button_states()

    def _on_connect_failed(self, error):
        self._log(f"Connection failed: {error}")
        show_message(self, "Connection Failed", error, "error")
        self.status_bar.showMessage("Connection failed.")
        self._set_disconnected_button_states()

    def _handle_disconnect(self):
        self._log("Disconnect requested.")
        if self.client_instance:
            self.client_instance.disconnect()
            self.client_instance = None
        self.status_bar.showMessage("Disconnected.")
        self._set_disconnected_button_states()

    def _handle_start_socat(self, tty, port):
        self._log(f"Starting socat: {tty}, port {port}")
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self._log("socat is already running.")
            return
        self.socat_process = QProcess(self)
        self.socat_process.readyReadStandardOutput.connect(self._socat_ready_read_stdout)
        self.socat_process.readyReadStandardError.connect(self._socat_ready_read_stderr)
        self.socat_process.finished.connect(self._socat_finished)
        program = "socat"
        arguments = [
            "-v", "-b", "4", "-x",
            f"TCP-LISTEN:{port},fork,reuseaddr",
            f"{tty}"
        ]
        self._log(f"Starting socat: {program} {' '.join(arguments)}")
        self.socat_output_terminal.append(f"<b>Starting socat: {program} {' '.join(arguments)}</b>")
        self.socat_process.start(program, arguments)
        if not self.socat_process.waitForStarted(5000):
            error_msg = self.socat_process.errorString()
            self._log(f"Failed to start socat: {error_msg}")
            self.socat_output_terminal.append(f"<font color='red'><b>Failed to start socat: {error_msg}</b></font>")
            self.socat_process = None
            return
        self._log("socat process started.")
        self._set_socat_running_states()

    def _handle_stop_socat(self):
        self._log("Stopping socat process...")
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self.socat_process.terminate()
            if not self.socat_process.waitForFinished(3000):
                self._log("socat did not terminate gracefully, killing...")
                self.socat_process.kill()
                self.socat_process.waitForFinished(1000)
            self._log("socat process stopped.")
        else:
            self._log("socat is not running or already stopped.")
        self.socat_process = None
        self._set_socat_stopped_states()

    def _socat_ready_read_stdout(self):
        output = self.socat_process.readAllStandardOutput().data().decode(errors='ignore')
        self.socat_output_terminal.append(output)

    def _socat_ready_read_stderr(self):
        error_output = self.socat_process.readAllStandardError().data().decode(errors='ignore')
        self.socat_output_terminal.append(f"<font color='red'>{error_output}</font>")

    def _socat_finished(self, exit_code, exit_status):
        self._log(f"socat process finished. Exit code: {exit_code}, Status: {exit_status}")
        self.socat_output_terminal.append(f"<b>socat process finished. Exit code: {exit_code}</b>")
        self._set_socat_stopped_states()

    # ... rest of MainWindow unchanged ...
    def _handle_start_dump(self, payload, addr, length, output):
        self._log(f"Start dump requested: {payload}, addr={addr}, len={length}, output={output}")
        if not self.client_instance:
            show_message(self, "Error", "Not connected to PLC.", "error")
            return
        self.dump_thread = MemoryDumpThread(self.client_instance, payload, addr, length, output, self)
        self.dump_thread.dump_progress.connect(self._on_dump_progress)
        self.dump_thread.dump_succeeded.connect(self._on_dump_success)
        self.dump_thread.dump_failed.connect(self._on_dump_failed)
        self.dump_thread.start()
        self.status_bar.showMessage("Dumping memory...")

    def _on_dump_progress(self, done, total, speed, elapsed, eta):
        self._log(f"Dump progress: {done}/{total} bytes")

    def _on_dump_success(self, output_path, bytes_written):
        self._log(f"Dump successful: {bytes_written} bytes to {output_path}")
        self.status_bar.showMessage(f"Dump successful: {output_path}")

    def _on_dump_failed(self, error):
        self._log(f"Dump failed: {error}")
        show_message(self, "Dump Failed", error, "error")
        self.status_bar.showMessage("Dump failed.")

    def _handle_execute_payload(self, path, args):
        self._log(f"Execute payload requested: {path} args={args}")
        if not self.client_instance:
            show_message(self, "Error", "Not connected to PLC.", "error")
            return
        self.payload_thread = ExecutePayloadThread(self.client_instance, path, args, self)
        self.payload_thread.payload_execution_succeeded.connect(self._on_payload_success)
        self.payload_thread.payload_execution_failed.connect(self._on_payload_failed)
        self.payload_thread.start()
        self.status_bar.showMessage("Executing payload...")

    def _on_payload_success(self, hook_idx, response):
        self._log(f"Payload executed (hook {hook_idx}): {response}")
        self.status_bar.showMessage(f"Payload executed (hook {hook_idx})")

    def _on_payload_failed(self, error):
        self._log(f"Payload execution failed: {error}")
        show_message(self, "Payload Failed", error, "error")
        self.status_bar.showMessage("Payload execution failed.")

    def _log(self, message):
        self.program_output_terminal.append(message)
