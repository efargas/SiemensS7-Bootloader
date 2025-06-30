import sys
import os # For path operations
from PyQt5.QtWidgets import (QApplication, QMainWindow, QStatusBar, QMenuBar, QAction, QVBoxLayout, QWidget,
                             QGroupBox, QGridLayout, QLabel, QLineEdit, QPushButton, QComboBox,
                             QTabWidget, QTextEdit, QFileDialog, QProgressBar, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal, QProcess # For running socat

# Attempt to import client functionalities
try:
    import client # Assuming client.py is in the same directory or PYTHONPATH
except ImportError:
    print("ERROR: client.py not found. Please ensure it's in the same directory or PYTHONPATH.")
    # A real application might handle this more gracefully, e.g., disable functionality
    # For now, if it fails, the GUI might crash when trying to use client functions.
    client = None


class PLCExploitGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.client_instance = None # To hold PLCInterface instance
        self.socat_process = None # To hold socat QProcess instance
        self.setWindowTitle("PLC Exploitation Tool")
        self.setGeometry(100, 100, 800, 600)  # x, y, width, height

        self._create_menu_bar()
        self._create_status_bar()

        # Central widget and layout
        self.central_widget = QWidget()
        self.main_layout = QVBoxLayout(self.central_widget)
        self.setCentralWidget(self.central_widget)

        self._create_power_supply_group()
        self._create_connection_config_group()
        self._create_connection_management_group()
        self._create_dump_memory_group() # Corrected typo from self.dump_mem_group
        self._create_execute_payload_group()
        self._create_terminal_outputs_group()

    def _create_menu_bar(self):
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)

        # File menu
        file_menu = self.menu_bar.addMenu("&File")
        exit_action = QAction("&Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = self.menu_bar.addMenu("&Help")
        about_action = QAction("&About", self)
        # about_action.triggered.connect(self._show_about_dialog) # To be implemented
        help_menu.addAction(about_action)

    def _create_status_bar(self):
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    # def _show_about_dialog(self):
    #     QMessageBox.about(self, "About PLC Exploitation Tool",
    #                       "A GUI tool for interacting with Siemens S7 PLCs.")

    def _create_execute_payload_group(self):
        execute_group = QGroupBox("Execute Generic Payload")
        layout = QGridLayout()

        # Payload File
        self.gen_payload_label = QLabel("Payload File (.bin):")
        self.gen_payload_path_input = QLineEdit()
        self.gen_payload_path_input.setPlaceholderText("Select payload file...")
        self.gen_payload_path_input.setReadOnly(True)
        self.gen_payload_browse_button = QPushButton("Browse...")
        self.gen_payload_browse_button.setToolTip("Select the .bin payload file to execute.")
        self.gen_payload_browse_button.clicked.connect(self._browse_generic_payload)
        layout.addWidget(self.gen_payload_label, 0, 0)
        layout.addWidget(self.gen_payload_path_input, 0, 1)
        layout.addWidget(self.gen_payload_browse_button, 0, 2)

        # Arguments
        self.gen_payload_args_label = QLabel("Arguments (optional):")
        self.gen_payload_args_input = QLineEdit()
        self.gen_payload_args_input.setToolTip("Optional arguments to pass to the payload.")
        layout.addWidget(self.gen_payload_args_label, 1, 0)
        layout.addWidget(self.gen_payload_args_input, 1, 1, 1, 2) # Span input across 2 columns

        # Execute Payload Button
        self.execute_payload_button = QPushButton("Execute Payload")
        self.execute_payload_button.setToolTip("Upload and execute the selected payload.")
        # self.execute_payload_button.clicked.connect(self._execute_generic_payload) # To be implemented
        self.execute_payload_button.setEnabled(False) # Disabled until connected and in special mode
        layout.addWidget(self.execute_payload_button, 2, 0, 1, 3) # Span across columns

        execute_group.setLayout(layout)
        self.main_layout.addWidget(execute_group)

    def _create_dump_memory_group(self):
        dump_group = QGroupBox("Memory Dump")
        layout = QGridLayout()

        # Start Address
        self.dump_addr_label = QLabel("Start Address (hex):")
        self.dump_addr_input = QLineEdit("0x10010100") # Default from client.py
        self.dump_addr_input.setToolTip("Starting memory address to dump (e.g., 0x10010100).")
        layout.addWidget(self.dump_addr_label, 0, 0)
        layout.addWidget(self.dump_addr_input, 0, 1)

        # Number of Bytes
        self.dump_len_label = QLabel("Number of Bytes:")
        self.dump_len_input = QLineEdit("1024") # Default sensible length
        self.dump_len_input.setToolTip("Number of bytes to dump from the start address.")
        layout.addWidget(self.dump_len_label, 1, 0)
        layout.addWidget(self.dump_len_input, 1, 1)

        # Dump Payload File
        self.dump_payload_label = QLabel("Dump Payload:")
        self.dump_payload_path_input = QLineEdit("payloads/dump_mem/build/dump_mem.bin") # Default
        self.dump_payload_path_input.setReadOnly(True)
        self.dump_payload_browse_button = QPushButton("Browse...")
        self.dump_payload_browse_button.setToolTip("Select the dump_mem.bin payload file.")
        self.dump_payload_browse_button.clicked.connect(self._browse_dump_payload)
        layout.addWidget(self.dump_payload_label, 2, 0)
        layout.addWidget(self.dump_payload_path_input, 2, 1)
        layout.addWidget(self.dump_payload_browse_button, 2, 2)

        # Save Dump As
        self.dump_output_label = QLabel("Save Dump As:")
        self.dump_output_path_input = QLineEdit("memory_dump.bin") # Default
        self.dump_output_path_input.setReadOnly(True)
        self.dump_output_browse_button = QPushButton("Browse...")
        self.dump_output_browse_button.setToolTip("Choose where to save the memory dump.")
        self.dump_output_browse_button.clicked.connect(self._browse_dump_output)
        layout.addWidget(self.dump_output_label, 3, 0)
        layout.addWidget(self.dump_output_path_input, 3, 1)
        layout.addWidget(self.dump_output_browse_button, 3, 2)

        # Start Dump Button
        self.start_dump_button = QPushButton("Start Dump")
        self.start_dump_button.setToolTip("Begin the memory dumping process.")
        # self.start_dump_button.clicked.connect(self._start_dump) # To be implemented
        self.start_dump_button.setEnabled(False) # Disabled until connected and in special mode
        layout.addWidget(self.start_dump_button, 4, 0, 1, 3) # Span across columns

        # Progress Bar
        self.dump_progress_bar = QProgressBar()
        self.dump_progress_bar.setValue(0)
        layout.addWidget(self.dump_progress_bar, 5, 0, 1, 3)

        # Statistics Labels
        self.dump_stats_layout = QGridLayout()
        self.dump_speed_label = QLabel("Speed: N/A")
        self.dump_elapsed_label = QLabel("Elapsed: 0s")
        self.dump_remaining_label = QLabel("ETA: N/A")
        self.dump_stats_layout.addWidget(self.dump_speed_label, 0, 0)
        self.dump_stats_layout.addWidget(self.dump_elapsed_label, 0, 1)
        self.dump_stats_layout.addWidget(self.dump_remaining_label, 0, 2)
        layout.addLayout(self.dump_stats_layout, 6, 0, 1, 3)


        dump_group.setLayout(layout)
        self.main_layout.addWidget(dump_group)


    def _create_terminal_outputs_group(self):
        terminal_tabs = QTabWidget()

        self.socat_output_terminal = QTextEdit()
        self.socat_output_terminal.setReadOnly(True)
        self.socat_output_terminal.setLineWrapMode(QTextEdit.WidgetWidth) # Or NoWrap
        self.socat_output_terminal.setFontFamily("Monospace") # For better terminal look
        terminal_tabs.addTab(self.socat_output_terminal, "socat Output")

        self.program_output_terminal = QTextEdit()
        self.program_output_terminal.setReadOnly(True)
        self.program_output_terminal.setLineWrapMode(QTextEdit.WidgetWidth)
        self.program_output_terminal.setFontFamily("Monospace")
        terminal_tabs.addTab(self.program_output_terminal, "Program Output")

        # Add a stretch factor to make terminals take up more space if needed
        self.main_layout.addWidget(terminal_tabs, 1) # Add with stretch factor

    # --- Action Methods ---

    def _show_message(self, title, message, level="info"):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        if level == "info":
            msg_box.setIcon(QMessageBox.Information)
        elif level == "warning":
            msg_box.setIcon(QMessageBox.Warning)
        elif level == "error":
            msg_box.setIcon(QMessageBox.Critical)
        msg_box.exec_()

    def _log_to_program_output(self, message):
        self.program_output_terminal.append(message)

    def _power_on(self):
        if not client:
            self._show_message("Error", "client.py module not loaded.", "error")
            return
        try:
            modbus_ip = self.modbus_ip_input.text()
            modbus_port = int(self.modbus_port_input.text())
            modbus_output = int(self.modbus_output_input.text())

            self._log_to_program_output(f"Attempting to power ON: {modbus_ip}:{modbus_port} output {modbus_output}")
            if client.switch_power('on', modbus_ip, modbus_port, modbus_output):
                self._log_to_program_output("Power ON command successful.")
                self.status_bar.showMessage("Power ON successful.")
            else:
                self._log_to_program_output("Power ON command failed. Check logs/Modbus settings.")
                self._show_message("Power Control", "Failed to turn power ON. Check Modbus settings and connection.", "error")
        except ValueError:
            self._show_message("Input Error", "Modbus port and output must be integers.", "error")
        except Exception as e:
            self._show_message("Power Control Error", f"An error occurred: {e}", "error")
            self._log_to_program_output(f"Error during power ON: {e}")

    def _power_off(self):
        if not client:
            self._show_message("Error", "client.py module not loaded.", "error")
            return
        try:
            modbus_ip = self.modbus_ip_input.text()
            modbus_port = int(self.modbus_port_input.text())
            modbus_output = int(self.modbus_output_input.text())

            self._log_to_program_output(f"Attempting to power OFF: {modbus_ip}:{modbus_port} output {modbus_output}")
            if client.switch_power('off', modbus_ip, modbus_port, modbus_output):
                self._log_to_program_output("Power OFF command successful.")
                self.status_bar.showMessage("Power OFF successful.")
            else:
                self._log_to_program_output("Power OFF command failed. Check logs/Modbus settings.")
                self._show_message("Power Control", "Failed to turn power OFF. Check Modbus settings and connection.", "error")
        except ValueError:
            self._show_message("Input Error", "Modbus port and output must be integers.", "error")
        except Exception as e:
            self._show_message("Power Control Error", f"An error occurred: {e}", "error")
            self._log_to_program_output(f"Error during power OFF: {e}")

    def _browse_file(self, caption, directory, file_filter, line_edit_widget):
        # Use os.path.expanduser to start in user's home directory if 'directory' is empty or not specific
        start_dir = os.path.expanduser(directory if directory else "~")
        file_name, _ = QFileDialog.getOpenFileName(self, caption, start_dir, file_filter)
        if file_name:
            line_edit_widget.setText(file_name)
            self._log_to_program_output(f"{caption} selected: {file_name}")

    def _browse_save_file(self, caption, directory, file_filter, line_edit_widget):
        start_dir = os.path.expanduser(directory if directory else "~")
        file_name, _ = QFileDialog.getSaveFileName(self, caption, start_dir, file_filter)
        if file_name:
            line_edit_widget.setText(file_name)
            self._log_to_program_output(f"Output file selected: {file_name}")


    def _browse_dump_payload(self):
        self._browse_file("Select Dump Payload File", "./payloads/dump_mem/build/",
                          "Binary files (*.bin);;All files (*)",
                          self.dump_payload_path_input)

    def _browse_dump_output(self):
        self._browse_save_file("Save Memory Dump As", "./",
                               "Binary files (*.bin);;All files (*)",
                               self.dump_output_path_input)

    def _browse_generic_payload(self):
        self._browse_file("Select Generic Payload File", "./payloads/",
                          "Binary files (*.bin);;All files (*)",
                          self.gen_payload_path_input)

    # --- socat Process Handlers ---
    def _socat_ready_read_stdout(self):
        output = self.socat_process.readAllStandardOutput().data().decode(errors='ignore')
        self.socat_output_terminal.append(output)

    def _socat_ready_read_stderr(self):
        error_output = self.socat_process.readAllStandardError().data().decode(errors='ignore')
        self.socat_output_terminal.append(f"<font color='red'>{error_output}</font>") # Show errors in red

    def _socat_finished(self, exit_code, exit_status):
        self._log_to_program_output(f"socat process finished. Exit code: {exit_code}, Status: {exit_status}")
        self.socat_output_terminal.append(f"<b>socat process finished. Exit code: {exit_code}</b>")
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        # Also disable payload/dump buttons if socat dies unexpectedly
        self.start_dump_button.setEnabled(False)
        self.execute_payload_button.setEnabled(False)


    def _start_socat(self):
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self._log_to_program_output("socat is already running.")
            return True

        self.socat_process = QProcess(self)
        self.socat_process.readyReadStandardOutput.connect(self._socat_ready_read_stdout)
        self.socat_process.readyReadStandardError.connect(self._socat_ready_read_stderr)
        self.socat_process.finished.connect(self._socat_finished)

        serial_dev = self.tty_combo.currentText()
        forward_port = self.socat_port_input.text()

        # Ensure stty settings from start.sh are applied.
        # This might require running stty as a separate command or ensuring socat itself can set these.
        # For simplicity, we assume socat can handle raw params or stty is pre-configured.
        # A more robust solution might run `stty` command first.
        # stty -F ${SERIAL_DEV} cs8 38400 ignbrk -brkint -icrnl -imaxbel -opost -onlcr -isig -icanon -iexten -echo -echoe -echok -echoctl -echoke  -ixon -crtscts -parodd parenb raw
        # socat -v -b 4 -x TCP-LISTEN:1238,fork,reuseaddr ${SERIAL_DEV}

        # Basic socat command
        # TODO: Add verbosity and other options from start.sh if necessary
        # socat_cmd = f"socat TCP-LISTEN:{forward_port},fork,reuseaddr {serial_dev},raw,echo=0,b38400"
        # Using PTY to better emulate start.sh behavior for stty settings, though socat might override some.
        # The command from start.sh is: socat -v -b 4 -x TCP-LISTEN:1238,fork,reuseaddr ${SERIAL_DEV}
        # For QProcess, it's better to separate program and arguments
        program = "socat"
        arguments = [
            "-v", # verbose
            "-b", "4", # buffer size (example, might not be critical here)
            "-x", # hex output for data
            f"TCP-LISTEN:{forward_port},fork,reuseaddr",
            f"{serial_dev}" # socat should apply raw settings by default to serial TTYs
        ]
        # Pre-configure serial port using stty (Important!)
        stty_program = "stty"
        stty_args = [
            "-F", serial_dev,
            "cs8", "38400", "ignbrk", "-brkint", "-icrnl", "-imaxbel",
            "-opost", "-onlcr", "-isig", "-icanon", "-iexten",
            "-echo", "-echoe", "-echok", "-echoctl", "-echoke",
            "-ixon", "-crtscts", "-parodd", "parenb", "raw"
        ]
        self._log_to_program_output(f"Configuring {serial_dev} with stty: {' '.join(stty_args)}")
        stty_process = QProcess()
        stty_process.start(stty_program, stty_args)
        stty_process.waitForFinished(5000) # Wait up to 5s
        if stty_process.exitStatus() != QProcess.NormalExit or stty_process.exitCode() != 0:
            err_msg = stty_process.readAllStandardError().data().decode(errors='ignore')
            self._log_to_program_output(f"stty configuration failed for {serial_dev}: {err_msg}")
            self.socat_output_terminal.append(f"<font color='red'><b>stty failed: {err_msg}</b></font>")
            # return False # Allow socat to try anyway, it might still work depending on existing config

        self._log_to_program_output(f"Starting socat: {program} {' '.join(arguments)}")
        self.socat_output_terminal.append(f"<b>Starting socat: {program} {' '.join(arguments)}</b>")
        self.socat_process.start(program, arguments)

        if not self.socat_process.waitForStarted(5000): # Wait 5s for socat to start
            error_msg = self.socat_process.errorString()
            self._log_to_program_output(f"Failed to start socat: {error_msg}")
            self.socat_output_terminal.append(f"<font color='red'><b>Failed to start socat: {error_msg}</b></font>")
            self.socat_process = None # Clear it
            return False

        self._log_to_program_output("socat process started.")
        return True

    def _stop_socat(self):
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self._log_to_program_output("Stopping socat process...")
            self.socat_process.terminate() # Try to terminate gracefully
            if not self.socat_process.waitForFinished(3000): # Wait 3s
                self._log_to_program_output("socat did not terminate gracefully, killing...")
                self.socat_process.kill()
                self.socat_process.waitForFinished(1000) # Wait for kill
            self._log_to_program_output("socat process stopped.")
        else:
            self._log_to_program_output("socat is not running or already stopped.")
        self.socat_process = None


    def _connect_plc(self):
        if not client:
            self._show_message("Error", "client.py module not loaded.", "error")
            return

        if self.client_instance and self.client_instance.r:
            self._show_message("Info", "Already connected to PLC.", "info")
            return

        # Start socat first
        if not self._start_socat():
            self._show_message("Error", "Failed to start socat. Cannot connect to PLC.", "error")
            return

        # Disable connect button, enable disconnect
        self.connect_button.setEnabled(False)
        # self.disconnect_button.setEnabled(True) # Enable this after successful PLC connection

        # PLC connection logic will be in a thread
        self.status_bar.showMessage("Attempting to connect to PLC...")
        self._log_to_program_output("Starting PLC connection thread...")

        # Placeholder for actual connection thread
        # For now, let's simulate success for UI testing purposes
        # In the real version, a QThread will be started here.
        self.connect_button.setEnabled(False) # Disable while attempting

        target_host = "localhost" # socat forwards to here
        try:
            target_port = int(self.socat_port_input.text())
        except ValueError:
            self._show_message("Input Error", "Socat TCP Forward Port must be an integer.", "error")
            self.connect_button.setEnabled(True)
            return

        # Default stager path, can be made configurable later if needed
        stager_payload_path = client.STAGER_PL_FILENAME

        # Create and start the connection thread
        # Ensure any previous thread is not running or cleaned up, though typically not an issue if button logic is correct
        if hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning():
            self._log_to_program_output("Connection attempt already in progress.")
            # Optionally re-enable connect button if it was stuck disabled, or show message
            # self.connect_button.setEnabled(True)
            return

        self.connection_thread = PLCConnectionThread(target_host, target_port, stager_payload_path, self)
        self.connection_thread.connection_succeeded.connect(self._handle_plc_connected)
        self.connection_thread.connection_failed.connect(self._handle_plc_connection_error)
        self.connection_thread.finished.connect(self._on_connection_thread_finished)

        self._log_to_program_output(f"Starting PLC connection thread for {target_host}:{target_port}...")
        self.connection_thread.start()

    def _on_connection_thread_finished(self):
        self._log_to_program_output("PLC Connection thread has finished.")
        # This handler is mostly for cleanup or logging.
        # UI state should be primarily managed by _handle_plc_connected and _handle_plc_connection_error.
        # If the connect button is still disabled AND we are not connected, it means the thread might have
        # exited without emitting a success/failure signal properly or was interrupted.
        if self.connect_button.isEnabled() == False and self.disconnect_button.isEnabled() == False:
             self._log_to_program_output("Connection thread finished, but state unclear. Re-enabling connect button.")
             self.connect_button.setEnabled(True)


    def _handle_plc_connected(self, version_str, greeting_hex):
        self._log_to_program_output(f"Thread: Handshake successful! Greeting: {greeting_hex}")
        self._log_to_program_output(f"Thread: PLC Version: {version_str}")
        self._log_to_program_output(f"Thread: Stager installed.")
        self.status_bar.showMessage(f"Connected to PLC. Version: {version_str}. Stager installed.")

        self.disconnect_button.setEnabled(True)
        self.connect_button.setEnabled(False) # Keep connect disabled
        self.start_dump_button.setEnabled(True)
        self.execute_payload_button.setEnabled(True)

    def _handle_plc_connection_error(self, error_message):
        self._log_to_program_output(f"Thread: PLC Connection Error: {error_message}")
        self._show_message("Connection Failed", f"PLC Connection Error: {error_message}", "error")
        if self.client_instance: # Should be handled by thread, but good practice
            self.client_instance.disconnect()
            self.client_instance = None

        self.connect_button.setEnabled(True) # Re-enable connect button
        self.disconnect_button.setEnabled(False)
        self.start_dump_button.setEnabled(False)
        self.execute_payload_button.setEnabled(False)
        # Optionally stop socat if connection fails completely
        # self._stop_socat()


    def _disconnect_plc(self):
        # If a connection thread is running, we might need to signal it to stop/cancel.
        # For now, assume connection thread finishes before disconnect is typically hit,
        # or that client_instance operations are thread-safe / main thread only after connect.
        if hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning():
            self._log_to_program_output("Attempting to stop connection thread before disconnect...")
            # Add thread termination logic if applicable (e.g., setting a flag and waiting)
            # self.connection_thread.quit() # Or a custom stop method
            # self.connection_thread.wait(1000) # Wait a bit
            # For simplicity, this example doesn't implement full cancellable thread for connect.

        self.status_bar.showMessage("Disconnecting...")
        self._log_to_program_output("Disconnecting from PLC...")

        if self.client_instance:
            try:
                # Ask user if they want to send 'bye' or just disconnect
                reply = QMessageBox.question(self, 'Confirm Disconnect',
                                           "Send 'bye' command to PLC to allow normal boot?",
                                           QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                                           QMessageBox.Yes)

                if reply == QMessageBox.Cancel:
                    self.status_bar.showMessage("Disconnect cancelled.")
                    return

                if reply == QMessageBox.Yes:
                    self._log_to_program_output("Sending bye() command to PLC...")
                    if self.client_instance.send_bye():
                        self._log_to_program_output("bye() command sent successfully.")
                    else:
                        self._log_to_program_output("Failed to send bye() or unexpected response.")

            except Exception as e:
                self._log_to_program_output(f"Error sending bye: {e}")
                self._show_message("Disconnect Error", f"Error during bye command: {e}", "error")
            finally:
                self.client_instance.disconnect()
                self.client_instance = None

        self._stop_socat() # Always stop socat on disconnect

        self.status_bar.showMessage("Disconnected.")
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.start_dump_button.setEnabled(False)
        self.execute_payload_button.setEnabled(False)
        self._log_to_program_output("Disconnected from PLC and socat stopped.")


# --- Worker Threads ---
class PLCConnectionThread(QThread):
    # Signals: success_signal(version_str, greeting_hex), error_signal(error_message)
    connection_succeeded = pyqtSignal(str, str) # version_str, greeting_hex
    connection_failed = pyqtSignal(str)    # error_message

    def __init__(self, host, port, stager_payload_path, parent_gui):
        super().__init__(parent_gui)
        self.host = host
        self.port = port
        self.stager_payload_path = stager_payload_path
        self.parent_gui = parent_gui # To access client_instance, log methods

    def run(self):
        try:
            self.parent_gui.client_instance = client.PLCInterface(self.host, self.port)

            if not self.parent_gui.client_instance.connect():
                self.connection_failed.emit(f"Socket connection failed to {self.host}:{self.port}.")
                return

            self.parent_gui._log_to_program_output(f"Thread: Socket connected to {self.host}:{self.port}. Attempting handshake...")

            # Brief pause for socat to be fully ready (already done in _connect_plc before starting thread)
            # time.sleep(0.2)

            success, greeting = self.parent_gui.client_instance.perform_handshake()
            if not success:
                self.parent_gui.client_instance.disconnect() # Clean up socket connection
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

            self.parent_gui._log_to_program_output(f"Thread: Installing stager ({len(stager_code)} bytes)...")
            self.parent_gui.client_instance.install_stager_payload(stager_code)

            # If all successful
            self.connection_succeeded.emit(version_str, greeting_hex)

        except FileNotFoundError as fnf_err:
            self.connection_failed.emit(str(fnf_err))
            if self.parent_gui.client_instance:
                 self.parent_gui.client_instance.disconnect()
            self.parent_gui.client_instance = None
        except Exception as e:
            self.connection_failed.emit(f"An unexpected error occurred in connection thread: {e}")
            if self.parent_gui.client_instance: # Ensure client is cleaned up
                 self.parent_gui.client_instance.disconnect()
            self.parent_gui.client_instance = None


    def _create_connection_management_group(self):
        management_group = QGroupBox("PLC Connection")
        layout = QGridLayout() # Using GridLayout for potentially more items later

        self.connect_button = QPushButton("Connect to PLC")
        self.connect_button.setToolTip("Start socat, connect to PLC and attempt handshake.")
        self.connect_button.clicked.connect(self._connect_plc)
        layout.addWidget(self.connect_button, 0, 0)

        self.disconnect_button = QPushButton("Disconnect PLC")
        self.disconnect_button.setToolTip("Send bye() command to PLC and stop socat.")
        self.disconnect_button.clicked.connect(self._disconnect_plc)
        self.disconnect_button.setEnabled(False) # Initially disabled until connected
        layout.addWidget(self.disconnect_button, 0, 1)

        management_group.setLayout(layout)
        self.main_layout.addWidget(management_group)


    def _create_connection_config_group(self):
        connection_group = QGroupBox("Connection Configuration")
        layout = QGridLayout()

        # Socat TCP Forward Port
        self.socat_port_label = QLabel("Forwarded TCP Port:")
        self.socat_port_input = QLineEdit("1238") # Default from start.sh
        self.socat_port_input.setToolTip("Local TCP port that socat will forward to the serial device.")
        layout.addWidget(self.socat_port_label, 0, 0)
        layout.addWidget(self.socat_port_input, 0, 1)

        # ttyUSB Selection
        self.tty_label = QLabel("Serial Device (ttyUSB):")
        self.tty_combo = QComboBox()
        # Populate with common options, autodetect will refresh this
        for i in range(4): # Add ttyUSB0 to ttyUSB3
            self.tty_combo.addItem(f"/dev/ttyUSB{i}")
        self.tty_combo.setToolTip("Select the ttyUSB serial device connected to the PLC.")
        layout.addWidget(self.tty_label, 1, 0)
        layout.addWidget(self.tty_combo, 1, 1)

        # Autodetect Devices Button
        self.autodetect_button = QPushButton("Autodetect Devices")
        self.autodetect_button.setToolTip("Attempt to find connected serial devices (e.g., /dev/ttyUSB*).")
        self.autodetect_button.clicked.connect(self._autodetect_devices)
        layout.addWidget(self.autodetect_button, 2, 0, 1, 2) # Span button across two columns

        connection_group.setLayout(layout)
        self.main_layout.addWidget(connection_group)

    def _autodetect_devices(self):
        self._log_to_program_output("Autodetecting serial devices...")
        self.tty_combo.clear()

        # Common patterns for serial devices on Linux
        # For Windows, it would be "COM1", "COM2", etc.
        # For macOS, it's often /dev/tty.usbserial-* or /dev/tty.usbmodem-*

        # Simple glob-based detection for Linux
        import glob
        potential_devices = []
        for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*"]:
            potential_devices.extend(glob.glob(pattern))

        if not potential_devices:
            self._log_to_program_output("No common serial devices found automatically. Please enter manually if needed.")
            self.tty_combo.addItem("") # Add a blank item
        else:
            for device in sorted(list(set(potential_devices))): # Sort and unique
                self.tty_combo.addItem(device)
                self._log_to_program_output(f"Found: {device}")

        self.status_bar.showMessage(f"Device detection complete. Found {len(potential_devices)} potential devices.")

    def _create_power_supply_group(self):
        power_supply_group = QGroupBox("Power Supply")
        layout = QGridLayout()

        # Modbus IP
        self.modbus_ip_label = QLabel("Modbus IP:")
        self.modbus_ip_input = QLineEdit("192.168.1.18")
        self.modbus_ip_input.setToolTip("IP address of the Modbus TCP power supply device.")
        layout.addWidget(self.modbus_ip_label, 0, 0)
        layout.addWidget(self.modbus_ip_input, 0, 1)

        # Modbus Port
        self.modbus_port_label = QLabel("Modbus Port:")
        self.modbus_port_input = QLineEdit("502")
        self.modbus_port_input.setToolTip("Port of the Modbus TCP power supply device.")
        layout.addWidget(self.modbus_port_label, 1, 0)
        layout.addWidget(self.modbus_port_input, 1, 1)

        # Modbus Output
        self.modbus_output_label = QLabel("Modbus Output:")
        self.modbus_output_input = QLineEdit("1") # Default to an example output
        self.modbus_output_input.setToolTip("Modbus coil/output number to control.")
        layout.addWidget(self.modbus_output_label, 2, 0)
        layout.addWidget(self.modbus_output_input, 2, 1)

        # Power Supply Delay
        self.power_delay_label = QLabel("Power ON Delay (ms):")
        self.power_delay_input = QLineEdit("1000") # Default to 1 second
        self.power_delay_input.setToolTip("Delay in milliseconds before turning power ON after turning it OFF.")
        layout.addWidget(self.power_delay_label, 3, 0)
        layout.addWidget(self.power_delay_input, 3, 1)

        # Power ON Button
        self.power_on_button = QPushButton("Power ON")
        self.power_on_button.setToolTip("Manually turn the power supply ON.")
        self.power_on_button.clicked.connect(self._power_on)
        layout.addWidget(self.power_on_button, 4, 0)

        # Power OFF Button
        self.power_off_button = QPushButton("Power OFF")
        self.power_off_button.setToolTip("Manually turn the power supply OFF.")
        self.power_off_button.clicked.connect(self._power_off)
        layout.addWidget(self.power_off_button, 4, 1)

        power_supply_group.setLayout(layout)
        self.main_layout.addWidget(power_supply_group)

    def _create_menu_bar(self):
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)

        # File menu
        file_menu = self.menu_bar.addMenu("&File")
        exit_action = QAction("&Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = self.menu_bar.addMenu("&Help")
        about_action = QAction("&About", self)
        # about_action.triggered.connect(self._show_about_dialog) # To be implemented
        help_menu.addAction(about_action)

    def _create_status_bar(self):
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    # def _show_about_dialog(self):
    #     QMessageBox.about(self, "About PLC Exploitation Tool",
    #                       "A GUI tool for interacting with Siemens S7 PLCs.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = PLCExploitGUI()
    main_window.show()
    sys.exit(app.exec_())
