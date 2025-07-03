import sys
import os # For path operations
from PyQt5.QtWidgets import (QApplication, QMainWindow, QStatusBar, QMenuBar, QAction, QVBoxLayout, QWidget,
                             QGroupBox, QGridLayout, QLabel, QLineEdit, QPushButton, QComboBox,
                             QTabWidget, QTextEdit, QFileDialog, QProgressBar, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal, QProcess, Qt, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup
from PyQt5.QtWidgets import QToolButton, QSizePolicy, QFrame, QScrollArea

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


class CollapsibleGroupBox(QWidget):
    def __init__(self, title="", parent=None, animation_duration=300):
        super(CollapsibleGroupBox, self).__init__(parent)

        self.animation_duration = animation_duration
        self.is_expanded = True # Start expanded by default

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.toggle_button = QToolButton(self)
        self.toggle_button.setStyleSheet("QToolButton { border: none; }")
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.setArrowType(Qt.DownArrow)
        self.toggle_button.setText(str(title))
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(self.is_expanded)
        self.toggle_button.clicked.connect(self._toggle)

        self.content_area = QFrame(self)
        self.content_area.setFrameShape(QFrame.StyledPanel) # or QFrame.NoFrame
        self.content_area.setFrameShadow(QFrame.Plain)
        self.content_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed) # Start with fixed, then expand
        self.content_layout = QVBoxLayout(self.content_area) # Layout for the actual content

        # Animation setup
        self.animation = QPropertyAnimation(self.content_area, b"maximumHeight")
        self.animation.setDuration(self.animation_duration)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)

        main_layout.addWidget(self.toggle_button)
        main_layout.addWidget(self.content_area)

        # Set initial state without animation
        if not self.is_expanded:
            self.content_area.setMaximumHeight(0)

    def setLayout(self, layout):
        # Clear any existing layout in content_layout first
        while self.content_layout.count():
            child = self.content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self.content_layout.addLayout(layout)
        # Adjust content_area's initial size based on its new layout,
        # especially when starting in expanded state.
        if self.is_expanded:
            self.content_area.setMaximumHeight(self.content_area.sizeHint().height() + self.content_layout.contentsMargins().top() + self.content_layout.contentsMargins().bottom())


    def _toggle(self):
        self.is_expanded = not self.is_expanded
        self.toggle_button.setArrowType(Qt.DownArrow if self.is_expanded else Qt.RightArrow)

        current_height = self.content_area.height()
        self.animation.stop() # Stop any ongoing animation

        if self.is_expanded:
            # To expand, set maximumHeight to something large enough for content
            # Get the actual preferred height of the content
            self.content_area.setMaximumHeight(self.content_area.sizeHint().height() + self.content_layout.contentsMargins().top() + self.content_layout.contentsMargins().bottom())
            # If sizeHint is not enough, might need to calculate it more robustly
            # or use a very large number like self.content_area.parentWidget().height() or a fixed large value.
            # For dynamic content, sizeHint should be updated.
            # Let's try a fixed large value for simplicity for now if sizeHint is problematic.
            # target_height = self.content_area.layout().sizeHint().height() # Preferred height of content
            target_height = self.content_area.sizeHint().height()
            if target_height == 0 and self.content_layout.count() > 0 : # if sizeHint is 0, try to get it from layout
                 target_height = self.content_layout.sizeHint().height()

            self.animation.setStartValue(0) # Assuming it was 0 (collapsed)
            self.animation.setEndValue(target_height if target_height > 0 else 300) # Use a default if target_height is 0
        else:
            # To collapse
            self.animation.setStartValue(self.content_area.height())
            self.animation.setEndValue(0)

        self.animation.start()


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

        # Create a top widget for all collapsible sections
        self.sections_widget = QWidget()
        self.sections_layout = QVBoxLayout(self.sections_widget)
        self.sections_layout.setContentsMargins(0,0,0,0)

        self._create_power_supply_group()
        self._create_connection_config_group()
        self._create_connection_management_group()
        self._create_dump_memory_group()
        self._create_execute_payload_group() 

        self.main_layout.addWidget(self.sections_widget) # Add all sections together

        self._create_terminal_outputs_group() # Terminals are separate and should expand

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
        power_supply_group = CollapsibleGroupBox("Power Supply Configuration")
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
        self.sections_layout.addWidget(power_supply_group) # Add to sections_layout

    def _create_connection_config_group(self):
        connection_group = CollapsibleGroupBox("Connection Configuration")
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
        self.sections_layout.addWidget(connection_group) # Add to sections_layout

    def _create_connection_management_group(self):
        management_group = CollapsibleGroupBox("PLC Connection Management")
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
        self.sections_layout.addWidget(management_group) # Add to sections_layout

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

    # def _show_about_dialog(self):
    #     QMessageBox.about(self, "About PLC Exploitation Tool",
    #                       "A GUI tool for interacting with Siemens S7 PLCs.")

    def _create_execute_payload_group(self):
        execute_group = CollapsibleGroupBox("Execute Generic Payload")
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
        self.execute_payload_button.clicked.connect(self._execute_generic_payload) # Connect to implemented method
        self.execute_payload_button.setEnabled(False) # Disabled until connected and in special mode
        layout.addWidget(self.execute_payload_button, 2, 0, 1, 3) # Span across columns

        execute_group.setLayout(layout)
        self.sections_layout.addWidget(execute_group) # Add to sections_layout

    def _create_dump_memory_group(self):
        dump_group = CollapsibleGroupBox("Memory Dump")
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
        self.start_dump_button.clicked.connect(self._start_dump) # Connect to implemented method
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
        self.sections_layout.addWidget(dump_group) # Add to sections_layout


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

    def _append_text_to_log(self, text_edit_widget, message):
        """Helper function to append text and manage scrolling."""
        scrollbar = text_edit_widget.verticalScrollBar()
        at_bottom = scrollbar.value() >= (scrollbar.maximum() - 4) # A little tolerance

        text_edit_widget.append(message)

        if at_bottom:
            scrollbar.setValue(scrollbar.maximum()) # Auto-scroll

    def _log_to_program_output(self, message):
        self._append_text_to_log(self.program_output_terminal, message)

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
        self._append_text_to_log(self.socat_output_terminal, output)

    def _socat_ready_read_stderr(self):
        error_output = self.socat_process.readAllStandardError().data().decode(errors='ignore')
        # For HTML formatted text, QTextEdit's append might not be ideal with the scroll check.
        # Let's use insertHtml and then manage scroll.
        # However, simple append with HTML also works with the _append_text_to_log if we pass HTML.
        # Let's keep it simple first.
        self._append_text_to_log(self.socat_output_terminal, f"<font color='red'>{error_output}</font>")


    def _socat_finished(self, exit_code, exit_status):
        self._log_to_program_output(f"socat process finished. Exit code: {exit_code}, Status: {exit_status}")
        self.socat_output_terminal.append(f"<b>socat process finished. Exit code: {exit_code}</b>")
        self.connect_button.setEnabled(True) # Ready for a new connection attempt

        # If socat died, any existing PLC connection is severed.
        if self.client_instance and self.client_instance.r:
            self._log_to_program_output("socat terminated while PLC connection was active. Cleaning up client.")
            self.client_instance.disconnect() # Close the pwnlib remote object
            self.client_instance = None
            self.status_bar.showMessage("Disconnected from PLC (socat terminated).")

        # Ensure UI reflects that PLC connection is gone
        self.disconnect_button.setEnabled(False)
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


class MemoryDumpThread(QThread):
    dump_progress = pyqtSignal(int, int, float, float, float) # done, total, speed, elapsed, eta
    dump_succeeded = pyqtSignal(str, int) # output_path, bytes_written
    dump_failed = pyqtSignal(str) # error_message

    def __init__(self, client_instance, dump_payload_path, dump_address, num_bytes, output_file_path, parent_gui):
        super().__init__(parent_gui)
        self.client_instance = client_instance
        self.dump_payload_path = dump_payload_path
        self.dump_address = dump_address
        self.num_bytes = num_bytes
        self.output_file_path = output_file_path
        self.parent_gui = parent_gui # For logging mainly

    def run(self):
        original_callback = None
        try:
            self.parent_gui._log_to_program_output(f"Dump Thread: Loading dump payload from {self.dump_payload_path}")
            with open(self.dump_payload_path, "rb") as f:
                dump_payload_code = f.read()

            self.parent_gui._log_to_program_output("Dump Thread: Executing memory dump operation...")

            original_callback = self.client_instance.progress_callback
            self.client_instance.progress_callback = self.dump_progress.emit

            dumped_data = self.client_instance.execute_memory_dump(
                dump_payload_code,
                self.dump_address,
                self.num_bytes
            )

            self.client_instance.progress_callback = original_callback
            original_callback = None # Indicate callback was restored

            self.parent_gui._log_to_program_output(f"Dump Thread: Saving {len(dumped_data)} bytes to {self.output_file_path}")
            with open(self.output_file_path, "wb") as f:
                f.write(dumped_data)

            self.dump_succeeded.emit(self.output_file_path, len(dumped_data))

        except FileNotFoundError as fnf_err:
            self.dump_failed.emit(f"Dump payload file not found: {fnf_err}")
        except Exception as e:
            self.parent_gui._log_to_program_output(f"Dump Thread: Exception: {e}")
            # import traceback # Keep this commented out unless debugging locally
            # traceback.print_exc()
            self.dump_failed.emit(f"An error occurred during memory dump: {e}")
        finally:
            if original_callback is not None and hasattr(self.client_instance, 'progress_callback'):
                # Restore callback if it hasn't been restored yet (e.g. due to an exception before explicit restore)
                self.client_instance.progress_callback = original_callback


class ExecutePayloadThread(QThread):
    payload_execution_succeeded = pyqtSignal(str, object)  # hook_idx_str, response (bytes or None)
    payload_execution_failed = pyqtSignal(str)    # error_message

    def __init__(self, client_instance, payload_path, payload_args_str, parent_gui):
        super().__init__(parent_gui)
        self.client_instance = client_instance
        self.payload_path = payload_path
        self.payload_args_str = payload_args_str # String, will be encoded
        self.parent_gui = parent_gui

    def run(self):
        try:
            self.parent_gui._log_to_program_output(f"Payload Thread: Loading payload from {self.payload_path}")
            with open(self.payload_path, "rb") as f:
                payload_code = f.read()

            # Convert string args to bytes, assuming UTF-8. Payload might expect specific encoding.
            payload_args_bytes = self.payload_args_str.encode('utf-8')

            self.parent_gui._log_to_program_output(f"Payload Thread: Installing payload ({len(payload_code)} bytes) with args '{self.payload_args_str}'...")

            # Using default hook from client.py, can be made configurable in GUI later if needed
            hook_idx = self.client_instance.install_payload_via_stager(payload_code)

            self.parent_gui._log_to_program_output(f"Payload Thread: Invoking payload hook 0x{hook_idx:02x}...")
            # For generic payloads, we usually want a response.
            # The invoke_add_hook has an await_response=True by default.
            response = self.client_instance.invoke_add_hook(hook_idx, payload_args_bytes)

            self.payload_execution_succeeded.emit(f"0x{hook_idx:02x}", response)

        except FileNotFoundError:
            self.payload_execution_failed.emit(f"Payload file not found: {self.payload_path}")
        except Exception as e:
            self.parent_gui._log_to_program_output(f"Payload Thread: Exception: {e}")
            # import traceback
            # traceback.print_exc()
            self.payload_execution_failed.emit(f"An error occurred during payload execution: {e}")


    # --- Memory Dump Methods ---

    # --- Generic Payload Execution Methods ---
    def _execute_generic_payload(self):
        if not self.client_instance or not self.client_instance.r:
            self._show_message("Error", "Not connected to PLC. Cannot execute payload.", "error")
            return

        payload_path = self.gen_payload_path_input.text()
        payload_args = self.gen_payload_args_input.text() # Keep as string, thread will encode

        if not payload_path or not os.path.exists(payload_path):
            self._show_message("Input Error", f"Payload file not found: {payload_path}", "error")
            return

        self.execute_payload_button.setEnabled(False)
        self._log_to_program_output(f"Starting generic payload execution: Path={payload_path}, Args='{payload_args}'")
        self.status_bar.showMessage("Executing payload...")

        if hasattr(self, 'payload_thread') and self.payload_thread and self.payload_thread.isRunning():
            self._log_to_program_output("Payload execution already in progress.")
            # self.execute_payload_button.setEnabled(True) # Re-enable if stuck
            return

        self.payload_thread = ExecutePayloadThread(
            self.client_instance,
            payload_path,
            payload_args,
            self
        )
        self.payload_thread.payload_execution_succeeded.connect(self._handle_payload_success)
        self.payload_thread.payload_execution_failed.connect(self._handle_payload_failure)
        self.payload_thread.finished.connect(self._on_payload_thread_finished)

        self.payload_thread.start()

    def _handle_payload_success(self, hook_idx_str, response):
        decoded_response = ""
        if response is not None:
            try:
                decoded_response = response.decode(errors='replace')
                self._log_to_program_output(f"Payload (hook {hook_idx_str}) executed successfully. Response (hex): {response.hex()}")
                self._log_to_program_output(f"Payload (hook {hook_idx_str}) response (decoded): {decoded_response}")
            except Exception as e:
                self._log_to_program_output(f"Payload (hook {hook_idx_str}) executed successfully. Response (hex): {response.hex()}")
                self._log_to_program_output(f"Could not decode response: {e}")
                decoded_response = f"[Binary data: {response.hex()}]"
        else:
            self._log_to_program_output(f"Payload (hook {hook_idx_str}) executed. No response data returned.")

        self._show_message("Payload Success", f"Payload from hook {hook_idx_str} executed.\nResponse:\n{decoded_response}", "info")
        self.status_bar.showMessage(f"Payload executed (hook {hook_idx_str}).")

    def _handle_payload_failure(self, error_message):
        self._log_to_program_output(f"Generic payload execution failed: {error_message}")
        self._show_message("Payload Failed", f"Generic payload execution failed: {error_message}", "error")
        self.status_bar.showMessage("Payload execution failed.")

    def _on_payload_thread_finished(self):
        self._log_to_program_output("Generic payload execution thread has finished.")
        self.execute_payload_button.setEnabled(True)


    def _start_dump(self):
        if not self.client_instance or not self.client_instance.r:
            self._show_message("Error", "Not connected to PLC. Cannot start dump.", "error")
            return

        try:
            dump_addr_str = self.dump_addr_input.text()
            dump_addr = int(dump_addr_str, 16)
            dump_len = int(self.dump_len_input.text())
            dump_payload_path = self.dump_payload_path_input.text()
            output_file_path = self.dump_output_path_input.text()
        except ValueError:
            self._show_message("Input Error", "Dump address must be a valid hex number and length must be an integer.", "error")
            return

        if not dump_payload_path or not os.path.exists(dump_payload_path):
            self._show_message("Input Error", f"Dump payload file not found: {dump_payload_path}", "error")
            return

        if not output_file_path:
            self._show_message("Input Error", "Output file path for dump not specified.", "error")
            return

        # Disable button, reset progress
        self.start_dump_button.setEnabled(False)
        self.dump_progress_bar.setValue(0)
        self.dump_speed_label.setText("Speed: N/A")
        self.dump_elapsed_label.setText("Elapsed: 0s")
        self.dump_remaining_label.setText("ETA: N/A")
        self._log_to_program_output(f"Starting memory dump: Addr=0x{dump_addr:08x}, Len={dump_len}, Payload={dump_payload_path}, Output={output_file_path}")

        # Create and start the dump thread
        if hasattr(self, 'dump_thread') and self.dump_thread and self.dump_thread.isRunning():
            self._log_to_program_output("Dump operation already in progress.")
            # self.start_dump_button.setEnabled(True) # Re-enable if it was stuck
            return

        self.dump_thread = MemoryDumpThread(
            self.client_instance,
            dump_payload_path,
            dump_addr,
            dump_len,
            output_file_path,
            self # parent_gui for logging and client_instance access (though client_instance is passed directly)
        )
        self.dump_thread.dump_progress.connect(self._update_dump_progress)
        self.dump_thread.dump_succeeded.connect(self._handle_dump_success)
        self.dump_thread.dump_failed.connect(self._handle_dump_failure)
        self.dump_thread.finished.connect(self._on_dump_thread_finished)

        self.status_bar.showMessage(f"Memory dump started to {output_file_path}...")
        self.dump_thread.start()

    def _update_dump_progress(self, done, total, speed, elapsed, eta):
        if total > 0:
            percent = int((done / total) * 100)
            self.dump_progress_bar.setValue(percent)
        else:
            self.dump_progress_bar.setValue(0) # Or indeterminate if possible

        self.dump_speed_label.setText(f"Speed: {client._format_bytes(int(speed))}/s")
        self.dump_elapsed_label.setText(f"Elapsed: {client._format_time(elapsed)}")
        self.dump_remaining_label.setText(f"ETA: {client._format_time(eta)}")
        self.status_bar.showMessage(f"Dumping... {client._format_bytes(done)} / {client._format_bytes(total)}")

    def _handle_dump_success(self, output_path, bytes_written):
        self._log_to_program_output(f"Memory dump successful. {client._format_bytes(bytes_written)} saved to {output_path}")
        self._show_message("Dump Success", f"Memory dump completed.\n{client._format_bytes(bytes_written)} saved to:\n{output_path}", "info")
        self.status_bar.showMessage(f"Dump successful: {output_path}")

    def _handle_dump_failure(self, error_message):
        self._log_to_program_output(f"Memory dump failed: {error_message}")
        self._show_message("Dump Failed", f"Memory dump failed: {error_message}", "error")
        self.dump_progress_bar.setValue(0) # Reset progress bar on failure
        self.status_bar.showMessage("Dump failed.")

    def _on_dump_thread_finished(self):
        self._log_to_program_output("Memory dump thread has finished.")
        self.start_dump_button.setEnabled(True) # Re-enable button
        # Reset progress bar and stats if not already handled by success/failure
        if self.dump_progress_bar.value() != 100 and self.dump_progress_bar.value() != 0 : # If not full or reset
            self.dump_progress_bar.setValue(0)
            self.dump_speed_label.setText("Speed: N/A")
            self.dump_elapsed_label.setText("Elapsed: 0s")
            self.dump_remaining_label.setText("ETA: N/A")


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
        self._log_to_program_output("Close event triggered. Cleaning up...")

        # Confirm exit if connected or operations are in progress
        confirm_exit = True
        if (self.client_instance and self.client_instance.r) or \
           (hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning()) or \
           (hasattr(self, 'dump_thread') and self.dump_thread and self.dump_thread.isRunning()) or \
           (hasattr(self, 'payload_thread') and self.payload_thread and self.payload_thread.isRunning()):

            reply = QMessageBox.question(self, 'Confirm Exit',
                                       "Are you sure you want to exit? Active connections or operations might be interrupted.",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                confirm_exit = False

        if not confirm_exit:
            event.ignore()
            self._log_to_program_output("Exit cancelled by user.")
            return

        # Stop any running worker threads (gracefully if possible)
        # Connection Thread
        if hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning():
            self._log_to_program_output("Stopping connection thread...")
            self.connection_thread.quit() # Request termination
            if not self.connection_thread.wait(1000): # Wait 1s
                 self._log_to_program_output("Connection thread did not terminate gracefully.")
                 # self.connection_thread.terminate() # Force if needed, but can be risky

        # Dump Thread
        if hasattr(self, 'dump_thread') and self.dump_thread and self.dump_thread.isRunning():
            self._log_to_program_output("Stopping dump thread...")
            self.dump_thread.quit()
            if not self.dump_thread.wait(1000):
                self._log_to_program_output("Dump thread did not terminate gracefully.")

        # Payload Thread
        if hasattr(self, 'payload_thread') and self.payload_thread and self.payload_thread.isRunning():
            self._log_to_program_output("Stopping payload thread...")
            self.payload_thread.quit()
            if not self.payload_thread.wait(1000):
                self._log_to_program_output("Payload thread did not terminate gracefully.")

        # Disconnect from PLC if connected (without further user prompt here as exit is confirmed)
        if self.client_instance and self.client_instance.r:
            self._log_to_program_output("Sending bye() to PLC before exiting...")
            try:
                self.client_instance.send_bye()
            except Exception as e:
                self._log_to_program_output(f"Error sending bye() on exit: {e}")
            finally:
                self.client_instance.disconnect()
                self.client_instance = None

        # Stop socat process
        self._stop_socat()

        self._log_to_program_output("Cleanup complete. Exiting.")
        event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = PLCExploitGUI()
    main_window.show()
    sys.exit(app.exec_())
