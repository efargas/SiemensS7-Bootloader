import sys
import os # For path operations
from PyQt5.QtWidgets import (QApplication, QMainWindow, QStatusBar, QMenuBar, QAction, QVBoxLayout, QWidget,
                             QGroupBox, QGridLayout, QLabel, QLineEdit, QPushButton, QComboBox,
                             QTabWidget, QTextEdit, QFileDialog, QProgressBar, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal, QProcess, Qt, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup, QSettings
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
    class MinimalClientMock:
        def switch_power(self, *args, **kwargs): print("MockClient: switch_power called"); return False
        STAGER_PL_FILENAME = "payloads/stager/stager.bin" # Default path
        def _format_bytes(self, b): return f"{b} B"
        def _format_time(self, t): return f"{t} s"
    if client is None:
        print("WARNING: client.py could not be imported. Using a minimal mock for GUI stability. Some features will not work.")
except Exception as e: # Catch other potential errors during import
    print(f"ERROR: An unexpected error occurred while importing client.py: {e}")
    client = None

# --- Custom Logging Handler for Qt ---
import logging
import logging.handlers # For RotatingFileHandler
from PyQt5.QtCore import QObject # Make sure QObject is imported here if not globally for the file

class QtLogHandler(logging.Handler, QObject): # Inherit from QObject
    log_received = pyqtSignal(str)

    def __init__(self, parent_qobject=None): # Accept a QObject parent
        super().__init__() # This will call logging.Handler.__init__
        QObject.__init__(self, parent_qobject) # Explicitly call QObject.__init__

    def emit(self, record):
        msg = self.format(record)
        self.log_received.emit(msg)

class CollapsibleGroupBox(QWidget):
    def __init__(self, title="", parent=None, animation_duration=300):
        super(CollapsibleGroupBox, self).__init__(parent)
        self.animation_duration = animation_duration
        self.is_expanded = True
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
        self.content_area.setFrameShape(QFrame.StyledPanel)
        self.content_area.setFrameShadow(QFrame.Plain)
        self.content_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.content_layout = QVBoxLayout(self.content_area)
        self.animation = QPropertyAnimation(self.content_area, b"maximumHeight")
        self.animation.setDuration(self.animation_duration)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        main_layout.addWidget(self.toggle_button)
        main_layout.addWidget(self.content_area)
        if not self.is_expanded:
            self.content_area.setMaximumHeight(0)

    def setLayout(self, layout):
        while self.content_layout.count():
            child = self.content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self.content_layout.addLayout(layout)
        if self.is_expanded:
            self.content_area.setMaximumHeight(self.content_area.sizeHint().height() + self.content_layout.contentsMargins().top() + self.content_layout.contentsMargins().bottom())

    def _toggle(self):
        self.is_expanded = not self.is_expanded
        self.toggle_button.setArrowType(Qt.DownArrow if self.is_expanded else Qt.RightArrow)
        self.animation.stop()
        if self.is_expanded:
            target_height = self.content_area.sizeHint().height()
            if target_height == 0 and self.content_layout.count() > 0 :
                 target_height = self.content_layout.sizeHint().height()
            self.animation.setStartValue(0)
            self.animation.setEndValue(target_height if target_height > 0 else 300)
        else:
            self.animation.setStartValue(self.content_area.height())
            self.animation.setEndValue(0)
        self.animation.start()

class PLCExploitGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.client_instance = None
        self.socat_process = None
        self.setWindowTitle("PLC Exploitation Tool")
        self.setGeometry(100, 100, 800, 600)

        self._create_menu_bar()
        self._create_status_bar()

        self.central_widget = QWidget()
        self.main_layout = QVBoxLayout(self.central_widget)
        self.setCentralWidget(self.central_widget)

        self.sections_widget = QWidget()
        self.sections_layout = QVBoxLayout(self.sections_widget)
        self.sections_layout.setContentsMargins(0,0,0,0)

        self._create_power_supply_group()
        self._create_connection_config_group()
        self._create_connection_management_group()
        self._create_dump_memory_group()
        self._create_execute_payload_group() 

        self.main_layout.addWidget(self.sections_widget)
        self._create_terminal_outputs_group() # This also calls _setup_logging

        self._load_settings() # Load settings after UI is created and logging is set up

    # --- UI Creation Methods ---
    def _create_menu_bar(self):
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)

        # File menu
        file_menu = self.menu_bar.addMenu("&File")

        save_config_action = QAction("&Save Configuration Now", self)
        save_config_action.setToolTip("Save all current settings (Modbus, connection, paths, etc.) immediately.")
        save_config_action.triggered.connect(self._save_settings) # Direct call to existing save method
        file_menu.addAction(save_config_action)

        load_config_action = QAction("&Load Configuration Now", self)
        load_config_action.setToolTip("Load all settings from storage, overwriting current UI values.")
        load_config_action.triggered.connect(self._confirm_load_settings)
        file_menu.addAction(load_config_action)

        file_menu.addSeparator()

        exit_action = QAction("&Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = self.menu_bar.addMenu("&Help")
        about_action = QAction("&About", self)
        # about_action.triggered.connect(self._show_about_dialog) # To be implemented
        help_menu.addAction(about_action)

        # Settings Menu
        settings_menu = self.menu_bar.addMenu("&Settings")
        logging_menu = settings_menu.addMenu("Logging")
        self.log_to_file_action = QAction("Enable Log to File", self, checkable=True)
        self.log_to_file_action.triggered.connect(self._toggle_file_logging)
        logging_menu.addAction(self.log_to_file_action)
        set_log_file_action = QAction("Set Log File Path...", self)
        set_log_file_action.triggered.connect(self._set_log_file_path)
        logging_menu.addAction(set_log_file_action)

    def _create_status_bar(self):
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _create_power_supply_group(self):
        power_supply_group = CollapsibleGroupBox("Power Supply Configuration")
        layout = QGridLayout()
        self.modbus_ip_label = QLabel("Modbus IP:")
        self.modbus_ip_input = QLineEdit("192.168.1.18")
        self.modbus_ip_input.setToolTip("IP address of the Modbus TCP power supply device.")
        layout.addWidget(self.modbus_ip_label, 0, 0)
        layout.addWidget(self.modbus_ip_input, 0, 1)
        self.modbus_port_label = QLabel("Modbus Port:")
        self.modbus_port_input = QLineEdit("502")
        self.modbus_port_input.setToolTip("Port of the Modbus TCP power supply device.")
        layout.addWidget(self.modbus_port_label, 1, 0)
        layout.addWidget(self.modbus_port_input, 1, 1)
        self.modbus_output_label = QLabel("Modbus Output:")
        self.modbus_output_input = QLineEdit("1")
        self.modbus_output_input.setToolTip("Modbus coil/output number to control.")
        layout.addWidget(self.modbus_output_label, 2, 0)
        layout.addWidget(self.modbus_output_input, 2, 1)
        self.power_delay_label = QLabel("Power ON Delay (ms):")
        self.power_delay_input = QLineEdit("1000")
        self.power_delay_input.setToolTip("Delay in milliseconds before turning power ON after turning it OFF.")
        layout.addWidget(self.power_delay_label, 3, 0)
        layout.addWidget(self.power_delay_input, 3, 1)
        self.power_on_button = QPushButton("Power ON")
        self.power_on_button.setToolTip("Manually turn the power supply ON.")
        self.power_on_button.clicked.connect(self._power_on)
        layout.addWidget(self.power_on_button, 4, 0)
        self.power_off_button = QPushButton("Power OFF")
        self.power_off_button.setToolTip("Manually turn the power supply OFF.")
        self.power_off_button.clicked.connect(self._power_off)
        layout.addWidget(self.power_off_button, 4, 1)
        power_supply_group.setLayout(layout)
        self.sections_layout.addWidget(power_supply_group)

    def _create_connection_config_group(self):
        connection_group = CollapsibleGroupBox("Connection Configuration")
        layout = QGridLayout()
        self.socat_port_label = QLabel("Forwarded TCP Port:")
        self.socat_port_input = QLineEdit("1238")
        self.socat_port_input.setToolTip("Local TCP port that socat will forward to the serial device.")
        layout.addWidget(self.socat_port_label, 0, 0)
        layout.addWidget(self.socat_port_input, 0, 1)
        self.tty_label = QLabel("Serial Device (ttyUSB):")
        self.tty_combo = QComboBox()
        for i in range(4): self.tty_combo.addItem(f"/dev/ttyUSB{i}")
        self.tty_combo.setToolTip("Select the ttyUSB serial device connected to the PLC.")
        layout.addWidget(self.tty_label, 1, 0)
        layout.addWidget(self.tty_combo, 1, 1)
        self.autodetect_button = QPushButton("Autodetect Devices")
        self.autodetect_button.setToolTip("Attempt to find connected serial devices (e.g., /dev/ttyUSB*).")
        self.autodetect_button.clicked.connect(self._autodetect_devices)
        layout.addWidget(self.autodetect_button, 2, 0, 1, 2)
        connection_group.setLayout(layout)
        self.sections_layout.addWidget(connection_group)

    def _create_connection_management_group(self):
        management_group = CollapsibleGroupBox("PLC Connection Management")
        layout = QGridLayout()
        self.connect_button = QPushButton("Connect to PLC")
        self.connect_button.setToolTip("Start socat, connect to PLC and attempt handshake.")
        self.connect_button.clicked.connect(self._connect_plc)
        layout.addWidget(self.connect_button, 0, 0)
        self.disconnect_button = QPushButton("Disconnect PLC")
        self.disconnect_button.setToolTip("Send bye() command to PLC and stop socat.")
        self.disconnect_button.clicked.connect(self._disconnect_plc)
        self.disconnect_button.setEnabled(False)
        layout.addWidget(self.disconnect_button, 0, 1)
        management_group.setLayout(layout)
        self.sections_layout.addWidget(management_group)

    def _create_execute_payload_group(self):
        execute_group = CollapsibleGroupBox("Execute Generic Payload")
        layout = QGridLayout()
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
        self.gen_payload_args_label = QLabel("Arguments (optional):")
        self.gen_payload_args_input = QLineEdit()
        self.gen_payload_args_input.setToolTip("Optional arguments to pass to the payload.")
        layout.addWidget(self.gen_payload_args_label, 1, 0)
        layout.addWidget(self.gen_payload_args_input, 1, 1, 1, 2)
        self.execute_payload_button = QPushButton("Execute Payload")
        self.execute_payload_button.setToolTip("Upload and execute the selected payload.")
        self.execute_payload_button.clicked.connect(self._execute_generic_payload)
        self.execute_payload_button.setEnabled(False)
        layout.addWidget(self.execute_payload_button, 2, 0, 1, 3)
        execute_group.setLayout(layout)
        self.sections_layout.addWidget(execute_group)

    def _create_dump_memory_group(self):
        dump_group = CollapsibleGroupBox("Memory Dump")
        layout = QGridLayout()
        self.dump_addr_label = QLabel("Start Address (hex):")
        self.dump_addr_input = QLineEdit("0x10010100")
        self.dump_addr_input.setToolTip("Starting memory address to dump (e.g., 0x10010100).")
        layout.addWidget(self.dump_addr_label, 0, 0)
        layout.addWidget(self.dump_addr_input, 0, 1)
        self.dump_len_label = QLabel("Number of Bytes:")
        self.dump_len_input = QLineEdit("1024")
        self.dump_len_input.setToolTip("Number of bytes to dump from the start address.")
        layout.addWidget(self.dump_len_label, 1, 0)
        layout.addWidget(self.dump_len_input, 1, 1)
        self.dump_payload_label = QLabel("Dump Payload:")
        self.dump_payload_path_input = QLineEdit("payloads/dump_mem/build/dump_mem.bin")
        self.dump_payload_path_input.setReadOnly(True)
        self.dump_payload_browse_button = QPushButton("Browse...")
        self.dump_payload_browse_button.setToolTip("Select the dump_mem.bin payload file.")
        self.dump_payload_browse_button.clicked.connect(self._browse_dump_payload)
        layout.addWidget(self.dump_payload_label, 2, 0)
        layout.addWidget(self.dump_payload_path_input, 2, 1)
        layout.addWidget(self.dump_payload_browse_button, 2, 2)
        self.dump_output_label = QLabel("Save Dump As:")
        self.dump_output_path_input = QLineEdit("memory_dump.bin")
        self.dump_output_path_input.setReadOnly(True)
        self.dump_output_browse_button = QPushButton("Browse...")
        self.dump_output_browse_button.setToolTip("Choose where to save the memory dump.")
        self.dump_output_browse_button.clicked.connect(self._browse_dump_output)
        layout.addWidget(self.dump_output_label, 3, 0)
        layout.addWidget(self.dump_output_path_input, 3, 1)
        layout.addWidget(self.dump_output_browse_button, 3, 2)
        self.start_dump_button = QPushButton("Start Dump")
        self.start_dump_button.setToolTip("Begin the memory dumping process.")
        self.start_dump_button.clicked.connect(self._start_dump)
        self.start_dump_button.setEnabled(False)
        layout.addWidget(self.start_dump_button, 4, 0, 1, 3)
        self.dump_progress_bar = QProgressBar()
        self.dump_progress_bar.setValue(0)
        layout.addWidget(self.dump_progress_bar, 5, 0, 1, 3)
        self.dump_stats_layout = QGridLayout()
        self.dump_speed_label = QLabel("Speed: N/A")
        self.dump_elapsed_label = QLabel("Elapsed: 0s")
        self.dump_remaining_label = QLabel("ETA: N/A")
        self.dump_stats_layout.addWidget(self.dump_speed_label, 0, 0)
        self.dump_stats_layout.addWidget(self.dump_elapsed_label, 0, 1)
        self.dump_stats_layout.addWidget(self.dump_remaining_label, 0, 2)
        layout.addLayout(self.dump_stats_layout, 6, 0, 1, 3)
        dump_group.setLayout(layout)
        self.sections_layout.addWidget(dump_group)

    def _create_terminal_outputs_group(self):
        terminal_tabs = QTabWidget()
        self.socat_output_terminal = QTextEdit()
        self.socat_output_terminal.setReadOnly(True)
        self.socat_output_terminal.setLineWrapMode(QTextEdit.WidgetWidth)
        self.socat_output_terminal.setFontFamily("Monospace")
        terminal_tabs.addTab(self.socat_output_terminal, "socat Output")
        self.program_output_terminal = QTextEdit()
        self.program_output_terminal.setReadOnly(True)
        self.program_output_terminal.setLineWrapMode(QTextEdit.WidgetWidth)
        self.program_output_terminal.setFontFamily("Monospace")
        terminal_tabs.addTab(self.program_output_terminal, "Program Output")
        self.main_layout.addWidget(terminal_tabs, 1)
        self._setup_logging()

    # --- Logging Setup and UI Methods ---
    def _setup_logging(self):
        self.app_logger = logging.getLogger()
        self.app_logger.setLevel(logging.DEBUG)
        for handler in self.app_logger.handlers[:]:
            self.app_logger.removeHandler(handler)
        self.qt_log_handler = QtLogHandler(self)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.qt_log_handler.setFormatter(formatter)
        self.app_logger.addHandler(self.qt_log_handler)
        self.qt_log_handler.log_received.connect(self._append_text_to_gui_log_terminal)
        self.app_logger.info("Logging system initialized and connected to GUI.")
        self._configure_file_logging()

    def _configure_file_logging(self):
        if hasattr(self, 'file_log_handler') and self.file_log_handler:
            self.app_logger.removeHandler(self.file_log_handler)
            self.file_log_handler.close()
            self.file_log_handler = None
        settings = QSettings("MyCompany", "PLCExploitTool")
        log_to_file = settings.value("logging/log_to_file_enabled", False, type=bool)
        log_file_path = settings.value("logging/log_file_path", "plc_exploit_tool.log")
        log_max_bytes = settings.value("logging/log_max_bytes", 1024*1024*5, type=int)
        log_backup_count = settings.value("logging/log_backup_count", 3, type=int)
        if log_to_file and log_file_path:
            try:
                self.file_log_handler = logging.handlers.RotatingFileHandler(
                    log_file_path, maxBytes=log_max_bytes, backupCount=log_backup_count
                )
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                self.file_log_handler.setFormatter(formatter)
                self.app_logger.addHandler(self.file_log_handler)
                self.app_logger.info(f"File logging enabled. Logging to: {log_file_path}")
            except Exception as e:
                self.app_logger.error(f"Failed to configure file logging to {log_file_path}: {e}")
                self.file_log_handler = None
        else:
            self.app_logger.info("File logging is disabled.")

    def _append_text_to_gui_log_terminal(self, message):
        scrollbar = self.program_output_terminal.verticalScrollBar()
        at_bottom = scrollbar.value() >= (scrollbar.maximum() - scrollbar.pageStep()/2)
        self.program_output_terminal.append(message)
        if at_bottom:
            scrollbar.setValue(scrollbar.maximum())

    def _toggle_file_logging(self):
        settings = QSettings("MyCompany", "PLCExploitTool")
        is_enabled = self.log_to_file_action.isChecked()
        settings.setValue("logging/log_to_file_enabled", is_enabled)
        self.app_logger.info(f"File logging toggled via UI. Enabled: {is_enabled}")
        self._configure_file_logging()

    def _set_log_file_path(self):
        settings = QSettings("MyCompany", "PLCExploitTool")
        current_path = settings.value("logging/log_file_path", "plc_exploit_tool.log")
        new_path, _ = QFileDialog.getSaveFileName(self, "Set Log File Path", current_path, "Log files (*.log);;All files (*)")
        if new_path:
            settings.setValue("logging/log_file_path", new_path)
            self.app_logger.info(f"Log file path changed to: {new_path}")
            if self.log_to_file_action.isChecked():
                self._configure_file_logging()
        else:
            self.app_logger.info("Log file path selection cancelled.")

    # --- Settings Management Methods ---
    def _load_settings(self):
        self.app_logger.info("Loading application settings...")
        settings = QSettings("MyCompany", "PLCExploitTool")
        self.modbus_ip_input.setText(settings.value("power/modbus_ip", "192.168.1.18"))
        self.modbus_port_input.setText(settings.value("power/modbus_port", "502"))
        self.modbus_output_input.setText(settings.value("power/modbus_output", "1"))
        self.power_delay_input.setText(settings.value("power/delay", "1000"))
        self.socat_port_input.setText(settings.value("connection/socat_port", "1238"))
        saved_tty = settings.value("connection/tty_device", "/dev/ttyUSB0")
        if self.tty_combo.findText(saved_tty) == -1: self.tty_combo.addItem(saved_tty)
        self.tty_combo.setCurrentText(saved_tty)
        self.dump_payload_path_input.setText(settings.value("dump/payload_path", "payloads/dump_mem/build/dump_mem.bin"))
        self.dump_addr_input.setText(settings.value("dump/address", "0x10010100"))
        self.dump_len_input.setText(settings.value("dump/length", "1024"))
        self.dump_output_path_input.setText(settings.value("dump/output_path", "memory_dump.bin"))
        self.gen_payload_path_input.setText(settings.value("execute/payload_path", ""))
        self.gen_payload_args_input.setText(settings.value("execute/args", ""))
        geometry = settings.value("window/geometry")
        if geometry: self.restoreGeometry(geometry)
        # Check if log_to_file_action exists before trying to setChecked, as _load_settings is called in __init__ before menu is fully populated by some paths
        if hasattr(self, 'log_to_file_action'):
            log_to_file_enabled = settings.value("logging/log_to_file_enabled", False, type=bool)
            self.log_to_file_action.setChecked(log_to_file_enabled)
        self.app_logger.info("Settings loaded.")

    def _save_settings(self):
        self.app_logger.info("Saving application settings...")
        settings = QSettings("MyCompany", "PLCExploitTool")
        settings.setValue("power/modbus_ip", self.modbus_ip_input.text())
        settings.setValue("power/modbus_port", self.modbus_port_input.text())
        settings.setValue("power/modbus_output", self.modbus_output_input.text())
        settings.setValue("power/delay", self.power_delay_input.text())
        settings.setValue("connection/socat_port", self.socat_port_input.text())
        settings.setValue("connection/tty_device", self.tty_combo.currentText())
        settings.setValue("dump/payload_path", self.dump_payload_path_input.text())
        settings.setValue("dump/address", self.dump_addr_input.text())
        settings.setValue("dump/length", self.dump_len_input.text())
        settings.setValue("dump/output_path", self.dump_output_path_input.text())
        settings.setValue("execute/payload_path", self.gen_payload_path_input.text())
        settings.setValue("execute/args", self.gen_payload_args_input.text())
        settings.setValue("window/geometry", self.saveGeometry())
        if hasattr(self, 'log_to_file_action'): # Ensure action exists
            settings.setValue("logging/log_to_file_enabled", self.log_to_file_action.isChecked())
        if hasattr(self, 'file_log_handler') and self.file_log_handler is not None:
             # These are saved based on current handler state if it exists
             settings.setValue("logging/log_file_path", self.file_log_handler.baseFilename)
             settings.setValue("logging/log_max_bytes", self.file_log_handler.maxBytes)
             settings.setValue("logging/log_backup_count", self.file_log_handler.backupCount)
        elif not settings.contains("logging/log_file_path"): # Save defaults if never saved
            settings.setValue("logging/log_file_path", "plc_exploit_tool.log")
            settings.setValue("logging/log_max_bytes", 1024*1024*5)
            settings.setValue("logging/log_backup_count", 3)

        self.app_logger.info("Settings saved.")

    def _confirm_load_settings(self):
        reply = QMessageBox.question(self, 'Confirm Load Configuration',
                                   "Loading configuration will overwrite any unsaved changes in the UI. Are you sure you want to continue?",
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.app_logger.info("User confirmed to load settings. Calling _load_settings().")
            self._load_settings()
            # Re-initialize logging based on potentially new settings from file
            self._configure_file_logging()
            self.app_logger.info("Settings have been reloaded from storage.")
            self._show_message("Load Complete", "Settings have been reloaded from storage.", "info")
        else:
            self.app_logger.info("User cancelled loading settings.")

    # --- Core Action Methods & Associated Thread/Process Management ---
    def _run_power_control(self, mode):
        if not client: self._show_message("Error", "client.py module not loaded.", "error"); return
        if hasattr(self, 'power_thread') and self.power_thread and self.power_thread.isRunning():
            self.app_logger.warning(f"Power control operation already in progress.")
            self._show_message("Busy", "Another power control operation is already running.", "warning")
            return
        try:
            modbus_ip = self.modbus_ip_input.text()
            modbus_port = int(self.modbus_port_input.text())
            modbus_output = int(self.modbus_output_input.text())
        except ValueError: self._show_message("Input Error", "Modbus port and output must be integers.", "error"); return
        self.power_on_button.setEnabled(False); self.power_off_button.setEnabled(False)
        self.status_bar.showMessage(f"Attempting to turn power {mode.upper()}...")
        self.app_logger.info(f"Initiating power {mode.upper()}: {modbus_ip}:{modbus_port} output {modbus_output}")
        self.power_thread = PowerControlThread(mode, modbus_ip, modbus_port, modbus_output, self)
        self.power_thread.power_control_succeeded.connect(self._handle_power_control_success)
        self.power_thread.power_control_failed.connect(self._handle_power_control_failure)
        self.power_thread.finished.connect(self._on_power_thread_finished)
        self.power_thread.start()

    def _power_on(self): self._run_power_control('on')
    def _power_off(self): self._run_power_control('off')

    def _start_socat(self):
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self.app_logger.info("socat is already running.")
            return True
        self.socat_process = QProcess(self)
        self.socat_process.readyReadStandardOutput.connect(self._socat_ready_read_stdout)
        self.socat_process.readyReadStandardError.connect(self._socat_ready_read_stderr)
        self.socat_process.finished.connect(self._socat_finished)
        serial_dev = self.tty_combo.currentText(); forward_port = self.socat_port_input.text()
        program = "socat"; arguments = ["-v", "-b", "4", "-x", f"TCP-LISTEN:{forward_port},fork,reuseaddr", f"{serial_dev}"]
        stty_program = "stty"; stty_args = ["-F", serial_dev, "cs8", "38400", "ignbrk", "-brkint", "-icrnl", "-imaxbel", "-opost", "-onlcr", "-isig", "-icanon", "-iexten", "-echo", "-echoe", "-echok", "-echoctl", "-echoke", "-ixon", "-crtscts", "-parodd", "parenb", "raw"]
        self.app_logger.info(f"Configuring {serial_dev} with stty: {' '.join(stty_args)}")
        stty_process = QProcess(); stty_process.start(stty_program, stty_args)
        stty_process.waitForFinished(5000)
        if stty_process.exitStatus() != QProcess.NormalExit or stty_process.exitCode() != 0:
            err_msg = stty_process.readAllStandardError().data().decode(errors='ignore')
            self.app_logger.error(f"stty configuration failed for {serial_dev}: {err_msg}")
            self.socat_output_terminal.append(f"<font color='red'><b>stty failed: {err_msg}</b></font>")
        self.app_logger.info(f"Starting socat: {program} {' '.join(arguments)}")
        self.socat_output_terminal.append(f"<b>Starting socat: {program} {' '.join(arguments)}</b>")
        self.socat_process.start(program, arguments)
        if not self.socat_process.waitForStarted(5000):
            error_msg = self.socat_process.errorString()
            self.app_logger.error(f"Failed to start socat: {error_msg}")
            self.socat_output_terminal.append(f"<font color='red'><b>Failed to start socat: {error_msg}</b></font>")
            self.socat_process = None; return False
        self.app_logger.info("socat process started.")
        return True

    def _stop_socat(self):
        if self.socat_process and self.socat_process.state() == QProcess.Running:
            self.app_logger.info("Stopping socat process...")
            self.socat_process.terminate()
            if not self.socat_process.waitForFinished(3000):
                self.app_logger.warning("socat did not terminate gracefully, killing...")
                self.socat_process.kill(); self.socat_process.waitForFinished(1000)
            self.app_logger.info("socat process stopped.")
        else: self.app_logger.info("socat is not running or already stopped.")
        self.socat_process = None

    def _connect_plc(self):
        if not client: self._show_message("Error", "client.py module not loaded.", "error"); return
        if self.client_instance and self.client_instance.r: self._show_message("Info", "Already connected to PLC.", "info"); return
        if not self._start_socat(): self._show_message("Error", "Failed to start socat. Cannot connect to PLC.", "error"); return
        self.connect_button.setEnabled(False)
        self.status_bar.showMessage("Attempting to connect to PLC...")
        self.app_logger.info("Starting PLC connection thread...")
        target_host = "localhost"
        try: target_port = int(self.socat_port_input.text())
        except ValueError: self._show_message("Input Error", "Socat TCP Forward Port must be an integer.", "error"); self.connect_button.setEnabled(True); return

        stager_payload_path = ""
        if client and hasattr(client, 'STAGER_PL_FILENAME'):
            stager_payload_path = client.STAGER_PL_FILENAME
        else: # Fallback if client or attribute is missing
             self.app_logger.warning("client.STAGER_PL_FILENAME not found, using default path for stager.")
             stager_payload_path = "payloads/stager/stager.bin" # Default if client is not loaded

        if hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning():
            self.app_logger.warning("Connection attempt already in progress."); return
        self.connection_thread = PLCConnectionThread(target_host, target_port, stager_payload_path, self)
        self.connection_thread.connection_succeeded.connect(self._handle_plc_connected)
        self.connection_thread.connection_failed.connect(self._handle_plc_connection_error)
        self.connection_thread.finished.connect(self._on_connection_thread_finished)
        self.app_logger.info(f"Starting PLC connection thread for {target_host}:{target_port}...")
        self.connection_thread.start()

    def _disconnect_plc(self):
        if hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning():
            self.app_logger.warning("Attempting to stop connection thread before disconnect...")
        self.status_bar.showMessage("Disconnecting...")
        self.app_logger.info("Disconnecting from PLC...")
        if self.client_instance:
            try:
                reply = QMessageBox.question(self, 'Confirm Disconnect', "Send 'bye' command to PLC to allow normal boot?", QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, QMessageBox.Yes)
                if reply == QMessageBox.Cancel: self.status_bar.showMessage("Disconnect cancelled."); return
                if reply == QMessageBox.Yes:
                    self.app_logger.info("Sending bye() command to PLC...")
                    if self.client_instance.send_bye(): self.app_logger.info("bye() command sent successfully.")
                    else: self.app_logger.warning("Failed to send bye() or unexpected response.")
            except Exception as e:
                self.app_logger.error(f"Error sending bye: {e}", exc_info=True)
                self._show_message("Disconnect Error", f"Error during bye command: {e}", "error")
            finally: self.client_instance.disconnect(); self.client_instance = None
        self._stop_socat()
        self.status_bar.showMessage("Disconnected.")
        self.connect_button.setEnabled(True); self.disconnect_button.setEnabled(False)
        self.start_dump_button.setEnabled(False); self.execute_payload_button.setEnabled(False)
        self.app_logger.info("Disconnected from PLC and socat stopped.")

    def _start_dump(self):
        if not self.client_instance or not self.client_instance.r: self._show_message("Error", "Not connected to PLC. Cannot start dump.", "error"); return
        try:
            dump_addr_str = self.dump_addr_input.text(); dump_addr = int(dump_addr_str, 16)
            dump_len = int(self.dump_len_input.text()); dump_payload_path = self.dump_payload_path_input.text()
            output_file_path = self.dump_output_path_input.text()
        except ValueError: self._show_message("Input Error", "Dump address must be a valid hex number and length must be an integer.", "error"); return
        if not dump_payload_path or not os.path.exists(dump_payload_path): self._show_message("Input Error", f"Dump payload file not found: {dump_payload_path}", "error"); return
        if not output_file_path: self._show_message("Input Error", "Output file path for dump not specified.", "error"); return
        self.start_dump_button.setEnabled(False); self.dump_progress_bar.setValue(0)
        self.dump_speed_label.setText("Speed: N/A"); self.dump_elapsed_label.setText("Elapsed: 0s"); self.dump_remaining_label.setText("ETA: N/A")
        self.app_logger.info(f"Starting memory dump: Addr=0x{dump_addr:08x}, Len={dump_len}, Payload={dump_payload_path}, Output={output_file_path}")
        if hasattr(self, 'dump_thread') and self.dump_thread and self.dump_thread.isRunning():
            self.app_logger.warning("Dump operation already in progress."); return
        self.dump_thread = MemoryDumpThread(self.client_instance, dump_payload_path, dump_addr, dump_len, output_file_path, self)
        self.dump_thread.dump_progress.connect(self._update_dump_progress)
        self.dump_thread.dump_succeeded.connect(self._handle_dump_success)
        self.dump_thread.dump_failed.connect(self._handle_dump_failure)
        self.dump_thread.finished.connect(self._on_dump_thread_finished)
        self.status_bar.showMessage(f"Memory dump started to {output_file_path}...")
        self.dump_thread.start()

    def _execute_generic_payload(self):
        if not self.client_instance or not self.client_instance.r: self._show_message("Error", "Not connected to PLC. Cannot execute payload.", "error"); return
        payload_path = self.gen_payload_path_input.text(); payload_args = self.gen_payload_args_input.text()
        if not payload_path or not os.path.exists(payload_path): self._show_message("Input Error", f"Payload file not found: {payload_path}", "error"); return
        self.execute_payload_button.setEnabled(False)
        self.app_logger.info(f"Starting generic payload execution: Path={payload_path}, Args='{payload_args}'")
        self.status_bar.showMessage("Executing payload...")
        if hasattr(self, 'payload_thread') and self.payload_thread and self.payload_thread.isRunning():
            self.app_logger.warning("Payload execution already in progress."); return
        self.payload_thread = ExecutePayloadThread(self.client_instance, payload_path, payload_args, self)
        self.payload_thread.payload_execution_succeeded.connect(self._handle_payload_success)
        self.payload_thread.payload_execution_failed.connect(self._handle_payload_failure)
        self.payload_thread.finished.connect(self._on_payload_thread_finished)
        self.payload_thread.start()

    # --- Slot Methods (Handlers for Thread Signals & Process Signals) ---
    def _handle_power_control_success(self, mode):
        self.app_logger.info(f"Successfully turned power {mode.upper()}.")
        self.status_bar.showMessage(f"Power {mode.upper()} successful.")

    def _handle_power_control_failure(self, mode, error_message):
        self.app_logger.error(f"Failed to turn power {mode.upper()}: {error_message}")
        self.status_bar.showMessage(f"Power {mode.upper()} failed.")
        self._show_message("Power Control Error", f"Failed to turn power {mode.upper()}: {error_message}", "error")

    def _on_power_thread_finished(self):
        self.app_logger.info("Power control thread finished.")
        self.power_on_button.setEnabled(True); self.power_off_button.setEnabled(True)
        if hasattr(self, 'power_thread'): self.power_thread = None

    def _socat_ready_read_stdout(self):
        output = self.socat_process.readAllStandardOutput().data().decode(errors='ignore').strip()
        if output: self.app_logger.info(f"[socat STDOUT] {output}"); self.socat_output_terminal.append(output)

    def _socat_ready_read_stderr(self):
        error_output = self.socat_process.readAllStandardError().data().decode(errors='ignore').strip()
        if error_output: self.app_logger.error(f"[socat STDERR] {error_output}"); self.socat_output_terminal.append(f"<font color='red'>{error_output}</font>")

    def _socat_finished(self, exit_code, exit_status):
        self.app_logger.info(f"socat process finished. Exit code: {exit_code}, Status: {exit_status}")
        self.connect_button.setEnabled(True)
        if self.client_instance and self.client_instance.r:
            self.app_logger.warning("socat terminated while PLC connection was active. Cleaning up client.")
            self.client_instance.disconnect(); self.client_instance = None
            self.status_bar.showMessage("Disconnected from PLC (socat terminated).")
        self.disconnect_button.setEnabled(False); self.start_dump_button.setEnabled(False); self.execute_payload_button.setEnabled(False)

    def _handle_plc_connected(self, version_str, greeting_hex):
        self.app_logger.info(f"PLC Handshake successful! Greeting: {greeting_hex}")
        self.app_logger.info(f"PLC Version: {version_str}")
        self.app_logger.info(f"Stager installed.")
        self.status_bar.showMessage(f"Connected to PLC. Version: {version_str}. Stager installed.")
        self.disconnect_button.setEnabled(True); self.connect_button.setEnabled(False)
        self.start_dump_button.setEnabled(True); self.execute_payload_button.setEnabled(True)

    def _handle_plc_connection_error(self, error_message):
        self.app_logger.error(f"PLC Connection Error: {error_message}", exc_info=True) # Show traceback for connection errors
        self._show_message("Connection Failed", f"PLC Connection Error: {error_message}", "error")
        if self.client_instance: self.client_instance.disconnect(); self.client_instance = None
        self.connect_button.setEnabled(True); self.disconnect_button.setEnabled(False)
        self.start_dump_button.setEnabled(False); self.execute_payload_button.setEnabled(False)

    def _on_connection_thread_finished(self):
        self.app_logger.info("PLC Connection thread has finished.")
        if not self.connect_button.isEnabled() and not self.disconnect_button.isEnabled():
             self.app_logger.warning("Connection thread finished, but state unclear. Re-enabling connect button.")
             self.connect_button.setEnabled(True)
        if hasattr(self, 'connection_thread'): self.connection_thread = None
        # If connection failed, _handle_plc_connection_error should have reset buttons.
        # If succeeded, _handle_plc_connected should have set them.
        # This finished handler is mostly for clearing the thread instance.

    def _update_dump_progress(self, done, total, speed, elapsed, eta):
        if total > 0: percent = int((done / total) * 100); self.dump_progress_bar.setValue(percent)
        else: self.dump_progress_bar.setValue(0)
        if client: # Check if client module was imported successfully
            self.dump_speed_label.setText(f"Speed: {client._format_bytes(int(speed))}/s")
            self.dump_elapsed_label.setText(f"Elapsed: {client._format_time(elapsed)}")
            self.dump_remaining_label.setText(f"ETA: {client._format_time(eta)}")
            self.status_bar.showMessage(f"Dumping... {client._format_bytes(done)} / {client._format_bytes(total)}")
        else: # Fallback if client is None
            self.dump_speed_label.setText(f"Speed: {int(speed)} B/s")
            self.dump_elapsed_label.setText(f"Elapsed: {int(elapsed)}s")
            self.dump_remaining_label.setText(f"ETA: {int(eta)}s")
            self.status_bar.showMessage(f"Dumping... {done} / {total}")


    def _handle_dump_success(self, output_path, bytes_written):
        formatted_bytes = f"{bytes_written} bytes"
        if client: formatted_bytes = client._format_bytes(bytes_written)
        self.app_logger.info(f"Memory dump successful. {formatted_bytes} saved to {output_path}")
        self._show_message("Dump Success", f"Memory dump completed.\n{formatted_bytes} saved to:\n{output_path}", "info")
        self.status_bar.showMessage(f"Dump successful: {output_path}")

    def _handle_dump_failure(self, error_message):
        self.app_logger.error(f"Memory dump failed: {error_message}", exc_info=True)
        self._show_message("Dump Failed", f"Memory dump failed: {error_message}", "error")
        self.dump_progress_bar.setValue(0); self.status_bar.showMessage("Dump failed.")

    def _on_dump_thread_finished(self):
        self.app_logger.info("Memory dump thread has finished.")
        self.start_dump_button.setEnabled(True)
        if self.dump_progress_bar.value() != 100 and self.dump_progress_bar.value() != 0 :
            self.dump_progress_bar.setValue(0)
            self.dump_speed_label.setText("Speed: N/A"); self.dump_elapsed_label.setText("Elapsed: 0s"); self.dump_remaining_label.setText("ETA: N/A")
        if hasattr(self, 'dump_thread'): self.dump_thread = None

    def _handle_payload_success(self, hook_idx_str, response):
        decoded_response = ""
        if response is not None:
            try:
                decoded_response = response.decode(errors='replace')
                self.app_logger.info(f"Payload (hook {hook_idx_str}) executed successfully. Response (hex): {response.hex()}")
                self.app_logger.info(f"Payload (hook {hook_idx_str}) response (decoded): {decoded_response}")
            except Exception as e:
                self.app_logger.error(f"Payload (hook {hook_idx_str}) executed successfully but response decoding failed: {e}. Response (hex): {response.hex()}", exc_info=True)
                decoded_response = f"[Binary data: {response.hex()}]"
        else: self.app_logger.info(f"Payload (hook {hook_idx_str}) executed. No response data returned.")
        self._show_message("Payload Success", f"Payload from hook {hook_idx_str} executed.\nResponse:\n{decoded_response}", "info")
        self.status_bar.showMessage(f"Payload executed (hook {hook_idx_str}).")

    def _handle_payload_failure(self, error_message):
        self.app_logger.error(f"Generic payload execution failed: {error_message}", exc_info=True)
        self._show_message("Payload Failed", f"Generic payload execution failed: {error_message}", "error")
        self.status_bar.showMessage("Payload execution failed.")

    def _on_payload_thread_finished(self):
        self.app_logger.info("Generic payload execution thread has finished.")
        self.execute_payload_button.setEnabled(True)
        if hasattr(self, 'payload_thread'): self.payload_thread = None

    # --- UI Utility/Helper Methods ---
    def _show_message(self, title, message, level="info"):
        log_level_map = {"info": logging.INFO, "warning": logging.WARNING, "error": logging.CRITICAL}
        self.app_logger.log(log_level_map.get(level, logging.INFO), f"Showing message box: Title='{title}', Message='{message}'")
        msg_box = QMessageBox(self); msg_box.setWindowTitle(title); msg_box.setText(message)
        if level == "info": msg_box.setIcon(QMessageBox.Information)
        elif level == "warning": msg_box.setIcon(QMessageBox.Warning)
        elif level == "error": msg_box.setIcon(QMessageBox.Critical)
        msg_box.exec_()

    def _autodetect_devices(self):
        self.app_logger.info("Autodetecting serial devices...")
        self.tty_combo.clear()
        import glob; potential_devices = []
        for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*"]: potential_devices.extend(glob.glob(pattern))
        if not potential_devices:
            self.app_logger.warning("No common serial devices found automatically.")
            self.tty_combo.addItem("")
        else:
            for device in sorted(list(set(potential_devices))): self.tty_combo.addItem(device); self.app_logger.info(f"Found: {device}")
        self.status_bar.showMessage(f"Device detection complete. Found {len(potential_devices)} potential devices.")

    def _browse_file(self, caption, directory, file_filter, line_edit_widget):
        start_dir = os.path.expanduser(directory if directory else "~")
        file_name, _ = QFileDialog.getOpenFileName(self, caption, start_dir, file_filter)
        if file_name: line_edit_widget.setText(file_name); self.app_logger.info(f"{caption} selected: {file_name}")

    def _browse_save_file(self, caption, directory, file_filter, line_edit_widget):
        start_dir = os.path.expanduser(directory if directory else "~")
        file_name, _ = QFileDialog.getSaveFileName(self, caption, start_dir, file_filter)
        if file_name: line_edit_widget.setText(file_name); self.app_logger.info(f"Output file selected: {file_name}")

    def _browse_dump_payload(self): self._browse_file("Select Dump Payload File", "./payloads/dump_mem/build/", "Binary files (*.bin);;All files (*)", self.dump_payload_path_input)
    def _browse_dump_output(self): self._browse_save_file("Save Memory Dump As", "./", "Binary files (*.bin);;All files (*)", self.dump_output_path_input)
    def _browse_generic_payload(self): self._browse_file("Select Generic Payload File", "./payloads/", "Binary files (*.bin);;All files (*)", self.gen_payload_path_input)

    def _log_to_program_output(self, message): # Maintained for brief, direct info messages from GUI not needing full logger verbosity.
        self.app_logger.info(message)

    # --- Event Handlers ---
    def closeEvent(self, event):
        self.app_logger.info("Close event triggered. Cleaning up...")
        confirm_exit = True
        if (self.client_instance and self.client_instance.r) or \
           (hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning()) or \
           (hasattr(self, 'dump_thread') and self.dump_thread and self.dump_thread.isRunning()) or \
           (hasattr(self, 'payload_thread') and self.payload_thread and self.payload_thread.isRunning()):
            reply = QMessageBox.question(self, 'Confirm Exit', "Are you sure you want to exit? Active connections or operations might be interrupted.", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No: confirm_exit = False
        if not confirm_exit: event.ignore(); self.app_logger.info("Exit cancelled by user."); return
        
        threads_to_stop = []
        if hasattr(self, 'connection_thread') and self.connection_thread and self.connection_thread.isRunning(): threads_to_stop.append(("connection", self.connection_thread))
        if hasattr(self, 'dump_thread') and self.dump_thread and self.dump_thread.isRunning(): threads_to_stop.append(("dump", self.dump_thread))
        if hasattr(self, 'payload_thread') and self.payload_thread and self.payload_thread.isRunning(): threads_to_stop.append(("payload", self.payload_thread))
        if hasattr(self, 'power_thread') and self.power_thread and self.power_thread.isRunning(): threads_to_stop.append(("power", self.power_thread))

        for name, thread_instance in threads_to_stop:
            self.app_logger.info(f"Stopping {name} thread...")
            thread_instance.quit()
            if not thread_instance.wait(1000): self.app_logger.warning(f"{name.capitalize()} thread did not terminate gracefully.")

        if self.client_instance and self.client_instance.r:
            self.app_logger.info("Sending bye() to PLC before exiting...")
            try: self.client_instance.send_bye()
            except Exception as e: self.app_logger.error(f"Error sending bye() on exit: {e}", exc_info=True)
            finally: self.client_instance.disconnect(); self.client_instance = None
        self._stop_socat()
        self.app_logger.info("Cleanup complete. Exiting.")
        self._save_settings()
        event.accept()

# --- Worker Threads (Placed after PLCExploitGUI for better readability if gui.py grows) ---
class PLCConnectionThread(QThread):
    connection_succeeded = pyqtSignal(str, str)
    connection_failed = pyqtSignal(str)

    def __init__(self, host, port, stager_payload_path, parent_gui):
        super().__init__(parent_gui)
        self.host = host; self.port = port; self.stager_payload_path = stager_payload_path; self.parent_gui = parent_gui

    def run(self):
        try:
            self.parent_gui.client_instance = client.PLCInterface(self.host, self.port)
            if not self.parent_gui.client_instance.connect():
                self.connection_failed.emit(f"Socket connection failed to {self.host}:{self.port}."); return
            self.parent_gui.app_logger.info(f"ConnectionThread: Socket connected to {self.host}:{self.port}. Attempting handshake...")
            success, greeting = self.parent_gui.client_instance.perform_handshake()
            if not success:
                self.parent_gui.client_instance.disconnect(); self.parent_gui.client_instance = None
                self.connection_failed.emit(f"Handshake failed: {greeting}"); return
            greeting_hex = greeting.hex() if greeting else "N/A"
            version_str = self.parent_gui.client_instance.get_plc_version()
            if not os.path.exists(self.stager_payload_path):
                self.parent_gui.client_instance.disconnect(); self.parent_gui.client_instance = None
                self.connection_failed.emit(f"Stager payload {self.stager_payload_path} not found!"); return
            with open(self.stager_payload_path, "rb") as f: stager_code = f.read()
            self.parent_gui.app_logger.info(f"ConnectionThread: Installing stager ({len(stager_code)} bytes)...")
            self.parent_gui.client_instance.install_stager_payload(stager_code)
            self.connection_succeeded.emit(version_str, greeting_hex)
        except FileNotFoundError as fnf_err:
            self.parent_gui.app_logger.error(f"ConnectionThread: FileNotFoundError - {fnf_err}")
            self.connection_failed.emit(str(fnf_err))
            if self.parent_gui.client_instance: self.parent_gui.client_instance.disconnect(); self.parent_gui.client_instance = None
        except Exception as e:
            self.parent_gui.app_logger.error(f"ConnectionThread: An unexpected error occurred - {e}", exc_info=True)
            self.connection_failed.emit(f"An unexpected error occurred in connection thread: {e}")
            if self.parent_gui.client_instance: self.parent_gui.client_instance.disconnect(); self.parent_gui.client_instance = None

class MemoryDumpThread(QThread):
    dump_progress = pyqtSignal(int, int, float, float, float)
    dump_succeeded = pyqtSignal(str, int)
    dump_failed = pyqtSignal(str)

    def __init__(self, client_instance, dump_payload_path, dump_address, num_bytes, output_file_path, parent_gui):
        super().__init__(parent_gui)
        self.client_instance = client_instance; self.dump_payload_path = dump_payload_path; self.dump_address = dump_address
        self.num_bytes = num_bytes; self.output_file_path = output_file_path; self.parent_gui = parent_gui

    def run(self):
        original_callback = None
        try:
            self.parent_gui.app_logger.info(f"DumpThread: Loading dump payload from {self.dump_payload_path}")
            with open(self.dump_payload_path, "rb") as f: dump_payload_code = f.read()
            self.parent_gui.app_logger.info("DumpThread: Executing memory dump operation...")
            original_callback = self.client_instance.progress_callback
            self.client_instance.progress_callback = self.dump_progress.emit
            dumped_data = self.client_instance.execute_memory_dump(dump_payload_code, self.dump_address, self.num_bytes)
            self.client_instance.progress_callback = original_callback; original_callback = None
            self.parent_gui.app_logger.info(f"DumpThread: Saving {len(dumped_data)} bytes to {self.output_file_path}")
            with open(self.output_file_path, "wb") as f: f.write(dumped_data)
            self.dump_succeeded.emit(self.output_file_path, len(dumped_data))
        except FileNotFoundError as fnf_err:
            self.parent_gui.app_logger.error(f"DumpThread: FileNotFoundError - {fnf_err}")
            self.dump_failed.emit(f"Dump payload file not found: {fnf_err}")
        except Exception as e:
            self.parent_gui.app_logger.error(f"DumpThread: Exception - {e}", exc_info=True)
            self.dump_failed.emit(f"An error occurred during memory dump: {e}")
        finally:
            if original_callback is not None and hasattr(self.client_instance, 'progress_callback') and self.client_instance:
                self.client_instance.progress_callback = original_callback

class ExecutePayloadThread(QThread):
    payload_execution_succeeded = pyqtSignal(str, object)
    payload_execution_failed = pyqtSignal(str)

    def __init__(self, client_instance, payload_path, payload_args_str, parent_gui):
        super().__init__(parent_gui)
        self.client_instance = client_instance; self.payload_path = payload_path;
        self.payload_args_str = payload_args_str; self.parent_gui = parent_gui

    def run(self):
        try:
            self.parent_gui.app_logger.info(f"PayloadThread: Loading payload from {self.payload_path}")
            with open(self.payload_path, "rb") as f: payload_code = f.read()
            payload_args_bytes = self.payload_args_str.encode('utf-8')
            self.parent_gui.app_logger.info(f"PayloadThread: Installing payload ({len(payload_code)} bytes) with args '{self.payload_args_str}'...")
            hook_idx = self.client_instance.install_payload_via_stager(payload_code)
            self.parent_gui.app_logger.info(f"PayloadThread: Invoking payload hook 0x{hook_idx:02x}...")
            response = self.client_instance.invoke_add_hook(hook_idx, payload_args_bytes)
            self.payload_execution_succeeded.emit(f"0x{hook_idx:02x}", response)
        except FileNotFoundError as fnf_err:
            self.parent_gui.app_logger.error(f"PayloadThread: FileNotFoundError - {fnf_err}")
            self.payload_execution_failed.emit(f"Payload file not found: {self.payload_path}")
        except Exception as e:
            self.parent_gui.app_logger.error(f"PayloadThread: Exception - {e}", exc_info=True)
            self.payload_execution_failed.emit(f"An error occurred during payload execution: {e}")

class PowerControlThread(QThread):
    power_control_succeeded = pyqtSignal(str)
    power_control_failed = pyqtSignal(str, str)

    def __init__(self, mode, modbus_ip, modbus_port, modbus_output, parent_gui):
        super().__init__(parent_gui)
        self.mode = mode; self.modbus_ip = modbus_ip; self.modbus_port = modbus_port;
        self.modbus_output = modbus_output; self.parent_gui = parent_gui

    def run(self):
        if not client: self.power_control_failed.emit(self.mode, "client.py module not loaded."); return
        try:
            self.parent_gui.app_logger.info(f"PowerControlThread: Attempting to power {self.mode.upper()}...")
            success = client.switch_power(self.mode, self.modbus_ip, self.modbus_port, self.modbus_output)
            if success:
                self.parent_gui.app_logger.info(f"PowerControlThread: Power {self.mode.upper()} command successful.")
                self.power_control_succeeded.emit(self.mode)
            else:
                self.parent_gui.app_logger.warning(f"PowerControlThread: Power {self.mode.upper()} command failed (client.switch_power returned False).")
                self.power_control_failed.emit(self.mode, "client.switch_power returned false. Check Modbus settings and connection.")
        except Exception as e:
            self.parent_gui.app_logger.error(f"PowerControlThread: Exception during power {self.mode.upper()}: {e}", exc_info=True)
            self.power_control_failed.emit(self.mode, f"An error occurred: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    QApplication.setOrganizationName("MyCompany")
    QApplication.setApplicationName("PLCExploitTool")
    main_window = PLCExploitGUI()
    main_window.show()
    sys.exit(app.exec_())

[end of gui.py]
