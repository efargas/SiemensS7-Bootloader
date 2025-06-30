import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QGroupBox, QLabel, QStatusBar, QMenuBar, QAction, QTextEdit,
    QLineEdit, QPushButton, QCheckBox, QFormLayout, QSpinBox, QRadioButton,
    QStackedWidget, QProgressBar, QFileDialog, QComboBox
)
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QIntValidator # For hex input if needed, though QLineEdit can suffice

from simulation import MockSocatServer, MockPowerSupply, MockClientProcess

# Constants for "Other Actions" defined in simulation.py or a shared constants file ideally
# For now, keep them here for simplicity of this example.
ACTION_TEST_SIM = "Test (Simulated)"
ACTION_HELLO_LOOP_SIM = "Hello Loop (Simulated)"
ACTION_TIC_TAC_TOE_SIM = "Tic Tac Toe (Simulated)"
ACTION_INVOKE_HOOK_SIM = "Invoke Hook (Simulated)"
# Add more actions as needed
OTHER_ACTIONS = [ACTION_TEST_SIM, ACTION_HELLO_LOOP_SIM, ACTION_TIC_TAC_TOE_SIM, ACTION_INVOKE_HOOK_SIM]

def format_time(seconds):
    """Helper to format seconds into MM:SS or HH:MM:SS"""
    if seconds == float('inf') or seconds < 0:
        return "N/A"
    if not isinstance(seconds, (int, float)):
        try: # If it's already a string like "N/A" or "X.Ys"
            if "N/A" in str(seconds): return "N/A"
            return str(seconds) # pass through
        except:
            return "N/A"

    s = int(seconds)
    if s < 3600: # Less than an hour
        return f"{s // 60:02d}:{s % 60:02d}"
    else: # Hour or more
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"

# Helper function for tooltips (can be expanded)
def create_tooltip_label(text, tooltip_text):
    label = QLabel(text)
    label.setToolTip(tooltip_text)
    return label

class MainAppGui(QMainWindow):
    """
    Main application GUI window.
    Handles UI setup, user interactions, and connects to simulation or real backend logic.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modern Application GUI")
        self.setGeometry(100, 100, 1200, 800) # x, y, width, height

        self.init_simulation_components()
        self.init_ui()
        self.connect_signals_to_simulation()
        self.load_settings() # Load settings after UI is initialized

    def init_simulation_components(self):
        """Initializes the simulation backend components."""
        self.sim_socat_server = MockSocatServer()
        self.sim_power_supply = MockPowerSupply()
        self.sim_client_process = MockClientProcess(self.sim_socat_server, self.sim_power_supply)
        self.is_simulation_mode = True # Default to true for now, or load from settings

    def init_ui(self):
        """Sets up the main user interface structure and widgets."""
        # --- Central Widget and Main Layout ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget) # Horizontal layout: Left Pane | Right Pane

        # --- Left Pane: Configuration & Actions ---
        left_pane_widget = QWidget()
        left_pane_layout = QVBoxLayout(left_pane_widget)
        left_pane_widget.setFixedWidth(400) # Give left pane a fixed width

        # Placeholder for Global Controls
        global_controls_group = QGroupBox("Global Controls")
        global_controls_layout = QVBoxLayout() # Changed to QVBoxLayout for sim checkbox

        self.simulation_mode_checkbox = QCheckBox("Enable Simulation Mode")
        self.simulation_mode_checkbox.setChecked(self.is_simulation_mode)
        self.simulation_mode_checkbox.setToolTip("Run in simulation mode without real hardware.")
        self.simulation_mode_checkbox.stateChanged.connect(self.toggle_simulation_mode)
        global_controls_layout.addWidget(self.simulation_mode_checkbox)

        # These buttons will be connected to sim/real logic
        self.main_connect_button = QPushButton("Connect (socat & Client)") # Combined connect
        self.main_connect_button.setToolTip("Connect to socat and initialize client.")
        global_controls_layout.addWidget(self.main_connect_button)

        self.main_disconnect_button = QPushButton("Disconnect All")
        self.main_disconnect_button.setToolTip("Disconnect client and socat.")
        self.main_disconnect_button.setEnabled(False) # Initially disabled
        global_controls_layout.addWidget(self.main_disconnect_button)

        global_controls_group.setLayout(global_controls_layout)
        left_pane_layout.addWidget(global_controls_group)


        # Tab Widget for different settings
        self.config_tabs = QTabWidget()

        # Tab 1: socat & Connection (Settings are now more for information in sim mode)
        self.tab_socat = QWidget()
        self.config_tabs.addTab(self.tab_socat, "socat & Connection")
        tab_socat_layout = QFormLayout(self.tab_socat)
        tab_socat_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        self.socat_port_input = QSpinBox()
        self.socat_port_input.setRange(1024, 65535)
        self.socat_port_input.setValue(1238) # Default from simulation.py
        self.socat_port_input.setToolTip("Local TCP port for socat to listen on.")
        tab_socat_layout.addRow(create_tooltip_label("Socat TCP Port:", self.socat_port_input.toolTip()), self.socat_port_input)

        self.serial_device_input = QLineEdit("/dev/ttyUSB0")
        self.serial_device_input.setToolTip("Serial device (real mode) or simulated ID.")
        tab_socat_layout.addRow(create_tooltip_label("Serial Device:", self.serial_device_input.toolTip()), self.serial_device_input)

        self.autodetect_serial_checkbox = QCheckBox("Autodetect Serial Device")
        self.autodetect_serial_checkbox.setToolTip("Attempt to automatically find the correct serial device (real mode).")
        tab_socat_layout.addRow(self.autodetect_serial_checkbox)

        # Removed connect_socat_button from here, moved to global controls

        # Placeholder for stty options (Advanced)
        # tab_socat_layout.addWidget(QLabel("Advanced stty options (placeholder)"))
        # tab_socat_layout.addStretch() # Removed to allow form layout to manage spacing

        # Tab 2: Power Supply
        self.tab_power = QWidget()
        self.config_tabs.addTab(self.tab_power, "Power Supply")
        tab_power_main_layout = QVBoxLayout(self.tab_power) # Main layout for this tab

        # --- Power Supply Method Selection ---
        method_group = QGroupBox("Power Supply Method")
        method_layout = QHBoxLayout()
        self.ps_method_allnet_radio = QRadioButton("ALLNET")
        self.ps_method_allnet_radio.setToolTip("Control power supply using ALLNET HTTP interface.")
        self.ps_method_modbus_radio = QRadioButton("Modbus TCP")
        self.ps_method_modbus_radio.setToolTip("Control power supply using Modbus TCP.")
        self.ps_method_allnet_radio.setChecked(True) # Default
        method_layout.addWidget(self.ps_method_allnet_radio)
        method_layout.addWidget(self.ps_method_modbus_radio)
        method_group.setLayout(method_layout)
        tab_power_main_layout.addWidget(method_group)

        # --- StackedWidget for Method-Specific Settings ---
        self.ps_settings_stack = QStackedWidget()

        # ALLNET Settings Page
        allnet_page = QWidget()
        allnet_layout = QFormLayout(allnet_page)
        self.ps_allnet_host_input = QLineEdit("powersupply")
        self.ps_allnet_host_input.setToolTip("Hostname or IP of the ALLNET power supply device.")
        allnet_layout.addRow(create_tooltip_label("ALLNET Host:", "Hostname or IP of the ALLNET power supply device."), self.ps_allnet_host_input)
        self.ps_allnet_port_input = QSpinBox()
        self.ps_allnet_port_input.setRange(1, 65535)
        self.ps_allnet_port_input.setValue(80)
        self.ps_allnet_port_input.setToolTip("Port number for the ALLNET power supply device.")
        allnet_layout.addRow(create_tooltip_label("ALLNET Port:", "Port number for the ALLNET power supply device."), self.ps_allnet_port_input)
        self.ps_settings_stack.addWidget(allnet_page)

        # Modbus TCP Settings Page
        modbus_page = QWidget()
        modbus_layout = QFormLayout(modbus_page)
        self.ps_modbus_ip_input = QLineEdit("192.168.1.18")
        self.ps_modbus_ip_input.setToolTip("IP address of the Modbus TCP device.")
        modbus_layout.addRow(create_tooltip_label("Modbus IP:", "IP address of the Modbus TCP device."), self.ps_modbus_ip_input)
        self.ps_modbus_port_input = QSpinBox()
        self.ps_modbus_port_input.setRange(1, 65535)
        self.ps_modbus_port_input.setValue(502)
        self.ps_modbus_port_input.setToolTip("Port number for Modbus TCP communication.")
        modbus_layout.addRow(create_tooltip_label("Modbus Port:", "Port for Modbus TCP."), self.ps_modbus_port_input)
        self.ps_modbus_output_input = QSpinBox() # Using SpinBox for coil address, could be QLineEdit if non-numeric
        self.ps_modbus_output_input.setRange(0, 255) # Typical coil range
        self.ps_modbus_output_input.setValue(0)
        self.ps_modbus_output_input.setToolTip("Modbus coil address/output number to control (integer).")
        modbus_layout.addRow(create_tooltip_label("Modbus Output/Coil:", "Modbus coil address."), self.ps_modbus_output_input)
        self.ps_settings_stack.addWidget(modbus_page)

        tab_power_main_layout.addWidget(self.ps_settings_stack)

        # Connect radio buttons to stacked widget display
        self.ps_method_allnet_radio.toggled.connect(lambda: self.ps_settings_stack.setCurrentIndex(0))
        self.ps_method_modbus_radio.toggled.connect(lambda: self.ps_settings_stack.setCurrentIndex(1))

        # --- Common Power Settings & Controls ---
        common_power_group = QGroupBox("Power Controls & Settings")
        common_power_layout = QFormLayout() # Using QFormLayout for consistency

        self.ps_delay_input = QSpinBox()
        self.ps_delay_input.setRange(0, 300000) # 0 to 5 minutes
        self.ps_delay_input.setValue(60000)
        self.ps_delay_input.setSuffix(" ms")
        self.ps_delay_input.setToolTip("Delay in milliseconds between power off and power on during a power cycle.")
        common_power_layout.addRow(create_tooltip_label("Power Cycle Delay:", "Delay for power cycle (ms)."), self.ps_delay_input)

        self.ps_status_label = QLabel("Status: Unknown")
        self.ps_status_label.setToolTip("Current status of the power supply.")
        common_power_layout.addRow(create_tooltip_label("Power Supply Status:", "Current power status."), self.ps_status_label)

        # Buttons in a QHBoxLayout for horizontal arrangement
        power_buttons_layout = QHBoxLayout()
        self.ps_manual_on_button = QPushButton("Manual Power ON")
        self.ps_manual_on_button.setToolTip("Manually turn the power supply ON.")
        power_buttons_layout.addWidget(self.ps_manual_on_button)

        self.ps_manual_off_button = QPushButton("Manual Power OFF")
        self.ps_manual_off_button.setToolTip("Manually turn the power supply OFF.")
        power_buttons_layout.addWidget(self.ps_manual_off_button)

        self.ps_cycle_button = QPushButton("Execute Power Cycle")
        self.ps_cycle_button.setToolTip("Perform an automated power cycle (Off -> Delay -> On).")
        power_buttons_layout.addWidget(self.ps_cycle_button)

        common_power_layout.addRow(power_buttons_layout) # Add the QHBoxLayout to the QFormLayout
        common_power_group.setLayout(common_power_layout)
        tab_power_main_layout.addWidget(common_power_group)

        tab_power_main_layout.addStretch() # Add stretch at the end of the main vertical layout

        # Tab 3: dump_mem Payload
        self.tab_dump_mem = QWidget()
        self.config_tabs.addTab(self.tab_dump_mem, "dump_mem Payload")
        tab_dump_mem_layout = QFormLayout(self.tab_dump_mem) # Using QFormLayout

        self.dm_start_address_input = QLineEdit("0x10010100")
        self.dm_start_address_input.setToolTip("Memory address to start dumping from (hex, e.g., 0x10010100).")
        # Optional: Add validator for hex input if desired
        # self.dm_start_address_input.setValidator(QRegExpValidator(QRegExp("0x[0-9A-Fa-f]{1,8}")))
        tab_dump_mem_layout.addRow(create_tooltip_label("Start Address (hex):", self.dm_start_address_input.toolTip()), self.dm_start_address_input)

        self.dm_num_bytes_input = QLineEdit("1024") # Can be decimal or hex with 0x prefix
        self.dm_num_bytes_input.setToolTip("Number of bytes to dump (decimal or hex with 0x prefix, e.g., 1024 or 0x400).")
        # Optional: Validator for numbers (decimal or hex)
        tab_dump_mem_layout.addRow(create_tooltip_label("Number of Bytes:", self.dm_num_bytes_input.toolTip()), self.dm_num_bytes_input)

        # Output File Path
        output_file_layout = QHBoxLayout()
        self.dm_output_file_input = QLineEdit()
        self.dm_output_file_input.setPlaceholderText("Default: mem_dump_ADDRESS_LENGTH.bin")
        self.dm_output_file_input.setReadOnly(False) # User can type or use browse
        self.dm_output_file_input.setToolTip("Path to save the memory dump. Leave blank for default.")
        output_file_layout.addWidget(self.dm_output_file_input)
        self.dm_browse_button = QPushButton("Browse...")
        self.dm_browse_button.setToolTip("Browse for a location to save the dump file.")
        self.dm_browse_button.clicked.connect(self.browse_dump_file_location)
        output_file_layout.addWidget(self.dm_browse_button)
        tab_dump_mem_layout.addRow(create_tooltip_label("Output File:", self.dm_output_file_input.toolTip()), output_file_layout)

        self.dm_start_button = QPushButton("Start Memory Dump")
        self.dm_start_button.setToolTip("Begin the memory dump process.")
        # self.dm_start_button.clicked.connect(self.start_memory_dump_action) # Slot to be defined
        tab_dump_mem_layout.addRow(self.dm_start_button)

        # Progress Indicators
        self.dm_progress_bar = QProgressBar()
        self.dm_progress_bar.setToolTip("Progress of the current memory dump.")
        self.dm_progress_bar.setValue(0) # Initial value
        tab_dump_mem_layout.addRow(create_tooltip_label("Progress:", self.dm_progress_bar.toolTip()), self.dm_progress_bar)

        self.dm_read_speed_label = QLabel("Speed: N/A")
        self.dm_read_speed_label.setToolTip("Current memory dump speed.")
        tab_dump_mem_layout.addRow(create_tooltip_label("Read Speed:", self.dm_read_speed_label.toolTip()), self.dm_read_speed_label)

        self.dm_time_elapsed_label = QLabel("Elapsed: 0s")
        self.dm_time_elapsed_label.setToolTip("Time elapsed for the current dump.")
        tab_dump_mem_layout.addRow(create_tooltip_label("Time Elapsed:", self.dm_time_elapsed_label.toolTip()), self.dm_time_elapsed_label)

        self.dm_time_remaining_label = QLabel("ETA: N/A")
        self.dm_time_remaining_label.setToolTip("Estimated time remaining for the dump.")
        tab_dump_mem_layout.addRow(create_tooltip_label("Time Remaining (ETA):", self.dm_time_remaining_label.toolTip()), self.dm_time_remaining_label)

        # Tab 4: Other Actions
        self.tab_other_actions = QWidget()
        self.config_tabs.addTab(self.tab_other_actions, "Other Actions")
        tab_other_actions_layout = QFormLayout(self.tab_other_actions)

        self.oa_action_combo = QComboBox()
        self.oa_action_combo.addItems(OTHER_ACTIONS)
        self.oa_action_combo.setToolTip("Select a predefined client action to execute.")
        tab_other_actions_layout.addRow(create_tooltip_label("Action:", self.oa_action_combo.toolTip()), self.oa_action_combo)

        oa_payload_layout = QHBoxLayout()
        self.oa_payload_file_input = QLineEdit()
        self.oa_payload_file_input.setPlaceholderText("Path to payload file (if required)")
        self.oa_payload_file_input.setToolTip("Path to the payload binary for the selected action (e.g., for invoke_hook).")
        oa_payload_layout.addWidget(self.oa_payload_file_input)
        self.oa_browse_payload_button = QPushButton("Browse...")
        self.oa_browse_payload_button.setToolTip("Browse for a payload file.")
        self.oa_browse_payload_button.clicked.connect(self.browse_oa_payload_file)
        oa_payload_layout.addWidget(self.oa_browse_payload_button)
        tab_other_actions_layout.addRow(create_tooltip_label("Payload File:", self.oa_payload_file_input.toolTip()), oa_payload_layout)

        self.oa_args_input = QLineEdit()
        self.oa_args_input.setPlaceholderText("Arguments for the action/payload")
        self.oa_args_input.setToolTip("Arguments to be passed to the selected action or payload.")
        tab_other_actions_layout.addRow(create_tooltip_label("Arguments:", self.oa_args_input.toolTip()), self.oa_args_input)

        self.oa_run_action_button = QPushButton("Run Selected Action")
        self.oa_run_action_button.setToolTip("Execute the chosen action with the specified parameters.")
        # self.oa_run_action_button.clicked.connect(self.handle_oa_run_action) # To be defined
        tab_other_actions_layout.addRow(self.oa_run_action_button)
        self.oa_run_action_button.setEnabled(False) # Initially disabled

        left_pane_layout.addWidget(self.config_tabs)
        main_layout.addWidget(left_pane_widget)

        # --- Right Pane: Output Terminals ---
        right_pane_widget = QWidget()
        right_pane_layout = QVBoxLayout(right_pane_widget)

        self.output_tabs = QTabWidget()

        # Output Tab 1: socat Output
        self.tab_socat_out = QWidget()
        socat_out_main_layout = QVBoxLayout(self.tab_socat_out) # Main layout for this tab

        self.socat_output_terminal = QTextEdit()
        self.socat_output_terminal.setReadOnly(True)
        self.socat_output_terminal.setFontFamily("Courier")
        socat_out_main_layout.addWidget(self.socat_output_terminal)

        clear_socat_log_button = QPushButton("Clear socat Log")
        clear_socat_log_button.setToolTip("Clear the content of the socat output window.")
        clear_socat_log_button.clicked.connect(self.socat_output_terminal.clear)
        socat_out_main_layout.addWidget(clear_socat_log_button)
        self.output_tabs.addTab(self.tab_socat_out, "socat Output")


        # Output Tab 2: Application Log
        self.tab_app_log = QWidget()
        app_log_main_layout = QVBoxLayout(self.tab_app_log) # Main layout for this tab

        self.app_log_terminal = QTextEdit()
        self.app_log_terminal.setReadOnly(True)
        self.app_log_terminal.setFontFamily("Courier")
        app_log_main_layout.addWidget(self.app_log_terminal)

        clear_app_log_button = QPushButton("Clear Application Log")
        clear_app_log_button.setToolTip("Clear the content of the application log window.")
        clear_app_log_button.clicked.connect(self.app_log_terminal.clear)
        app_log_main_layout.addWidget(clear_app_log_button)
        self.output_tabs.addTab(self.tab_app_log, "Application Log")

        right_pane_layout.addWidget(self.output_tabs)
        main_layout.addWidget(right_pane_widget)

        # --- Menu Bar ---
        menubar = self.menuBar()
        file_menu = menubar.addMenu('&File')

        exit_action = QAction('&Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # --- Status Bar ---
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")

        self.app_log_terminal.append("GUI Initialized.")
        self.update_ui_for_simulation_mode() # Set initial UI state based on sim mode

    def toggle_simulation_mode(self, state):
        """Handles the toggling of the simulation mode checkbox."""
        self.is_simulation_mode = bool(state)
        self.append_app_log(f"Simulation mode {'enabled' if self.is_simulation_mode else 'disabled'}.")
        # Potentially disconnect if mode is switched while active
        if self.sim_client_process and self.sim_client_process.is_running: # or real process
            self.handle_disconnect_all()
        self.update_ui_for_simulation_mode()

    def update_ui_for_simulation_mode(self):
        """Updates UI elements based on the current simulation mode (enabled/disabled)."""
        # Enable/disable certain UI elements based on simulation mode
        # For example, serial port detection might be disabled in sim mode
        self.autodetect_serial_checkbox.setEnabled(not self.is_simulation_mode)
        self.serial_device_input.setEnabled(not self.is_simulation_mode)
        # Or change labels, etc.
        if self.is_simulation_mode:
            self.serial_device_input.setPlaceholderText("Simulated Device ID")
            self.statusBar.showMessage("Ready (Simulation Mode)")
        else:
            self.serial_device_input.setPlaceholderText("/dev/ttyUSB0 or COM1")
            self.statusBar.showMessage("Ready (Real Mode)")


    def connect_signals_to_simulation(self):
        # Global controls
        self.main_connect_button.clicked.connect(self.handle_connect_all)
        self.main_disconnect_button.clicked.connect(self.handle_disconnect_all)

        # Simulation object signals to GUI slots
        self.sim_socat_server.socat_log_message.connect(self.append_socat_log)
        # self.sim_socat_server.data_sent_to_client # Potentially log this too if needed for debug

        self.sim_power_supply.log_message.connect(self.append_app_log)
        self.sim_power_supply.status_update.connect(self.update_power_supply_status_display)

        self.sim_client_process.log_message.connect(self.append_app_log)
        self.sim_client_process.dump_progress.connect(self.dm_progress_bar.setValue)
        self.sim_client_process.dump_stats.connect(self.update_dump_stats_display)
        self.sim_client_process.dump_complete.connect(self.handle_dump_complete)
        self.sim_client_process.dump_error.connect(self.handle_dump_error)
        self.sim_client_process.send_to_socat.connect(self.sim_socat_server.receive_data) # Client sim talks to socat sim

        # GUI actions to Simulation methods
        # Power Supply Tab
        self.ps_manual_on_button.clicked.connect(self.handle_ps_manual_on)
        self.ps_manual_off_button.clicked.connect(self.handle_ps_manual_off)
        self.ps_cycle_button.clicked.connect(self.handle_ps_cycle)

        # Dump Memory Tab
        self.dm_start_button.clicked.connect(self.handle_dm_start)

        # Other Actions Tab
        self.oa_run_action_button.clicked.connect(self.handle_oa_run_action)

        # Disable buttons initially until client is "connected"
        self.dm_start_button.setEnabled(False)
        self.oa_run_action_button.setEnabled(False)


    # --- GUI SLOTS / HANDLERS for Simulation ---
    def append_socat_log(self, message):
        self.socat_output_terminal.append(message.strip())

    def append_app_log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.app_log_terminal.append(f"[{timestamp}] {message}")
        print(f"APP LOG: [{timestamp}] {message}") # Also print to console for debugging

    def update_power_supply_status_display(self, status_text):
        self.ps_status_label.setText(f"Status: {status_text}")
        # Log for this is already handled by the signal from MockPowerSupply

    def update_dump_stats_display(self, speed, elapsed_str, remaining_str):
        # The simulation now sends pre-formatted strings for speed.
        # For time, it sends seconds as string (e.g. "15.3s"), we use format_time for MM:SS
        # However, simulation's _update_dump_progress already calculates these as strings.
        # Let's assume simulation sends raw seconds for elapsed and remaining for better GUI formatting.
        # For now, we'll adapt to current sim output if it's string, or format if it's num.

        self.dm_read_speed_label.setText(f"Speed: {speed}") # Speed is already formatted by sim

        try: # Try to parse sim's string output for time if it's like "12.3s"
            elapsed_seconds = float(elapsed_str.replace('s','')) if isinstance(elapsed_str, str) else elapsed_str
        except ValueError:
            elapsed_seconds = -1 # Mark as N/A
        self.dm_time_elapsed_label.setText(f"Elapsed: {format_time(elapsed_seconds)}")

        try:
            remaining_seconds = float(remaining_str.replace('s','')) if isinstance(remaining_str, str) and "N/A" not in remaining_str else remaining_str
        except ValueError:
            remaining_seconds = -1 # Mark as N/A
        self.dm_time_remaining_label.setText(f"ETA: {format_time(remaining_seconds)}")


    def handle_dump_complete(self, output_filepath):
        self.append_app_log(f"SUCCESS: Memory dump completed and saved to {output_filepath}")
        self.statusBar.showMessage(f"Dump complete: {output_filepath}", 5000)
        # Re-enable dump button if desired, or wait for disconnect/reconnect
        self.dm_start_button.setEnabled(True) # Or based on client state

    def handle_dump_error(self, error_message):
        self.append_app_log(f"ERROR: Memory dump failed: {error_message}")
        self.statusBar.showMessage(f"Dump error: {error_message}", 5000)
        self.dm_progress_bar.setValue(0) # Reset progress bar on error
        self.dm_start_button.setEnabled(True) # Re-enable button after error

    def handle_connect_all(self):
        if self.is_simulation_mode:
            self.append_app_log("Attempting to connect in Simulation Mode...")

            # Start socat server simulation
            socat_port = self.socat_port_input.value()
            self.sim_socat_server.port = socat_port # Update port if changed in GUI
            if self.sim_socat_server.start():
                self.append_app_log(f"Mock Socat Server started on port {socat_port}.")

                # Prepare client_args for sim_client_process
                client_args = {
                    "switch_power": self.config_tabs.isTabEnabled(1), # Crude check if power tab is relevant
                    "powersupply_delay": self.ps_delay_input.value(),
                    "powersupply_method": "allnet_sim" if self.ps_method_allnet_radio.isChecked() else "modbus_sim",
                    "powersupply_params": self.get_current_power_supply_params_for_sim(),
                    "action": "sim_idle", # Default action
                    # Add other relevant params from GUI for client sim if needed
                }
                self.sim_client_process.start_process(client_args)
                self.main_connect_button.setEnabled(False)
                self.main_disconnect_button.setEnabled(True)
                self.dm_start_button.setEnabled(True)
                self.oa_run_action_button.setEnabled(True) # Enable other actions too
                self.statusBar.showMessage("Connected (Simulation)", 3000)
            else:
                self.append_app_log("ERROR: Mock Socat Server failed to start.")
                self.statusBar.showMessage("Connection Failed (Simulation)", 3000)
        else:
            self.append_app_log("Real connection mode not implemented yet.")
            self.statusBar.showMessage("Real connection mode not implemented.", 3000)

    def handle_disconnect_all(self):
        if self.is_simulation_mode:
            self.append_app_log("Disconnecting in Simulation Mode...")
            self.sim_client_process.stop_process()
            self.sim_socat_server.stop()
            self.main_connect_button.setEnabled(True)
            self.main_disconnect_button.setEnabled(False)
            self.dm_start_button.setEnabled(False)
            self.oa_run_action_button.setEnabled(False) # Disable other actions
            self.dm_progress_bar.setValue(0)
            self.update_dump_stats_display("N/A", "0s", "N/A") # Pass strings as sim might send them
            self.statusBar.showMessage("Disconnected (Simulation)", 3000)
        else:
            self.append_app_log("Real disconnection mode not implemented yet.")

    def get_current_power_supply_params_for_sim(self):
        params = {}
        if self.ps_method_allnet_radio.isChecked():
            params['host'] = self.ps_allnet_host_input.text()
            params['port'] = self.ps_allnet_port_input.value()
        else: # Modbus
            params['ip'] = self.ps_modbus_ip_input.text()
            params['port'] = self.ps_modbus_port_input.value()
            params['output'] = self.ps_modbus_output_input.value()
        return params

    def handle_ps_manual_on(self):
        if self.is_simulation_mode:
            params = self.get_current_power_supply_params_for_sim()
            method = "allnet_sim" if self.ps_method_allnet_radio.isChecked() else "modbus_sim"
            self.sim_power_supply.turn_on({"method": method, **params})
        else:
            self.append_app_log("Real PS ON not implemented.")

    def handle_ps_manual_off(self):
        if self.is_simulation_mode:
            params = self.get_current_power_supply_params_for_sim()
            method = "allnet_sim" if self.ps_method_allnet_radio.isChecked() else "modbus_sim"
            self.sim_power_supply.turn_off({"method": method, **params})
        else:
            self.append_app_log("Real PS OFF not implemented.")

    def handle_ps_cycle(self):
        if self.is_simulation_mode:
            delay = self.ps_delay_input.value()
            params = self.get_current_power_supply_params_for_sim()
            method = "allnet_sim" if self.ps_method_allnet_radio.isChecked() else "modbus_sim"
            self.sim_power_supply.power_cycle(delay, method_params={"method": method, **params})
        else:
            self.append_app_log("Real PS Cycle not implemented.")

    def handle_dm_start(self):
        if self.is_simulation_mode and self.sim_client_process.is_running:
            try:
                addr_text = self.dm_start_address_input.text()
                addr = int(addr_text, 16) if 'x' in addr_text.lower() else int(addr_text)

                len_text = self.dm_num_bytes_input.text()
                length = int(len_text, 16) if 'x' in len_text.lower() else int(len_text)

                output_file = self.dm_output_file_input.text()
                if not output_file: # Generate default if empty
                    output_file = f"sim_mem_dump_{addr:08x}_{length:08x}.bin"
                    self.dm_output_file_input.setText(output_file) # Update GUI

                self.dm_start_button.setEnabled(False) # Disable while dumping
                self.sim_client_process.start_dump_memory(addr, length, output_file)

            except ValueError as e:
                self.append_app_log(f"ERROR: Invalid address or length for dump: {e}")
                self.statusBar.showMessage("Invalid dump parameters.", 3000)
                self.dm_start_button.setEnabled(True) # Re-enable on error
        elif not self.is_simulation_mode:
            self.append_app_log("Real dump_mem not implemented.")
        else:
            self.append_app_log("Client not connected/running. Cannot start dump.")
            self.statusBar.showMessage("Client not connected.", 3000)


    def browse_dump_file_location(self):
        # Try to generate a more specific default filename if possible
        try:
            start_addr_text = self.dm_start_address_input.text()
            num_bytes_text = self.dm_num_bytes_input.text()
            # Attempt to parse hex/decimal for default filename
            start_addr = int(start_addr_text, 16) if 'x' in start_addr_text.lower() else int(start_addr_text)
            num_bytes = int(num_bytes_text, 16) if 'x' in num_bytes_text.lower() else int(num_bytes_text)
            default_filename = f"mem_dump_{start_addr:08x}_{num_bytes:08x}.bin"
        except ValueError:
            default_filename = "mem_dump.bin" # Fallback default

        options = QFileDialog.Options()
        # options |= QFileDialog.DontUseNativeDialog # Uncomment if native dialog causes issues
        fileName, _ = QFileDialog.getSaveFileName(self,
                                                  "Save Memory Dump As...",
                                                  default_filename, # Default directory/filename
                                                  "Binary Files (*.bin);;All Files (*)",
                                                  options=options)
        if fileName:
            self.dm_output_file_input.setText(fileName)

    def browse_oa_payload_file(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self,
                                                  "Select Payload File",
                                                  "", # Default directory
                                                  "Binary Files (*.bin);;All Files (*)",
                                                  options=options)
        if fileName:
            self.oa_payload_file_input.setText(fileName)

    def handle_oa_run_action(self):
        if not (self.is_simulation_mode and self.sim_client_process.is_running):
            self.append_app_log("Client not connected/running. Cannot run other action.")
            self.statusBar.showMessage("Client not connected.", 3000)
            return

        action_name = self.oa_action_combo.currentText()
        payload_file = self.oa_payload_file_input.text()
        args_str = self.oa_args_input.text()

        self.append_app_log(f"Running other action: {action_name}...")
        self.sim_client_process.simulate_other_action(action_name, payload_file, args_str)
        self.statusBar.showMessage(f"Simulating action: {action_name}", 3000)


    def closeEvent(self, event):
        """Handle the window close event to save settings."""
        self.save_settings()
        super().closeEvent(event)

    def save_settings(self):
        """Save current GUI settings."""
        settings = QSettings("MyCompany", "MyAppName") # Use your app/company name
        self.append_app_log("Saving settings...")

        # Simulation Mode
        settings.setValue("simulation/enabled", self.simulation_mode_checkbox.isChecked())

        # Socat & Connection
        settings.setValue("socat/port", self.socat_port_input.value())
        settings.setValue("socat/serial_device", self.serial_device_input.text())
        settings.setValue("socat/autodetect_serial", self.autodetect_serial_checkbox.isChecked())

        # Power Supply
        settings.setValue("powersupply/method_allnet", self.ps_method_allnet_radio.isChecked())
        settings.setValue("powersupply/allnet_host", self.ps_allnet_host_input.text())
        settings.setValue("powersupply/allnet_port", self.ps_allnet_port_input.value())
        settings.setValue("powersupply/modbus_ip", self.ps_modbus_ip_input.text())
        settings.setValue("powersupply/modbus_port", self.ps_modbus_port_input.value())
        settings.setValue("powersupply/modbus_output", self.ps_modbus_output_input.value())
        settings.setValue("powersupply/cycle_delay", self.ps_delay_input.value())

        # Dump Memory
        settings.setValue("dump_mem/start_address", self.dm_start_address_input.text())
        settings.setValue("dump_mem/num_bytes", self.dm_num_bytes_input.text())
        settings.setValue("dump_mem/output_file", self.dm_output_file_input.text())

        # Window geometry (optional, but good for user experience)
        settings.setValue("window/geometry", self.saveGeometry())
        settings.setValue("window/state", self.saveState())

        self.append_app_log("Settings saved.")

    def load_settings(self):
        """Load GUI settings from previous session."""
        settings = QSettings("MyCompany", "MyAppName")
        self.append_app_log("Loading settings...")

        # Simulation Mode
        sim_enabled = settings.value("simulation/enabled", True, type=bool) # Default to True
        self.is_simulation_mode = sim_enabled # Update internal state first
        self.simulation_mode_checkbox.setChecked(sim_enabled)
        # self.toggle_simulation_mode(sim_enabled) # This might run too early or cause issues if called here
                                                # Better to call update_ui_for_simulation_mode at the end.

        # Socat & Connection
        self.socat_port_input.setValue(settings.value("socat/port", 1238, type=int))
        self.serial_device_input.setText(settings.value("socat/serial_device", "/dev/ttyUSB0"))
        self.autodetect_serial_checkbox.setChecked(settings.value("socat/autodetect_serial", False, type=bool))

        # Power Supply
        is_allnet = settings.value("powersupply/method_allnet", True, type=bool)
        if is_allnet:
            self.ps_method_allnet_radio.setChecked(True)
        else:
            self.ps_method_modbus_radio.setChecked(True)
        # This will also trigger the stacked widget change if radio button connections are already made

        self.ps_allnet_host_input.setText(settings.value("powersupply/allnet_host", "powersupply"))
        self.ps_allnet_port_input.setValue(settings.value("powersupply/allnet_port", 80, type=int))
        self.ps_modbus_ip_input.setText(settings.value("powersupply/modbus_ip", "192.168.1.18"))
        self.ps_modbus_port_input.setValue(settings.value("powersupply/modbus_port", 502, type=int))
        self.ps_modbus_output_input.setValue(settings.value("powersupply/modbus_output", 0, type=int))
        self.ps_delay_input.setValue(settings.value("powersupply/cycle_delay", 60000, type=int))

        # Dump Memory
        self.dm_start_address_input.setText(settings.value("dump_mem/start_address", "0x10010100"))
        self.dm_num_bytes_input.setText(settings.value("dump_mem/num_bytes", "1024"))
        self.dm_output_file_input.setText(settings.value("dump_mem/output_file", ""))

        # Window geometry
        geometry = settings.value("window/geometry")
        if geometry:
            self.restoreGeometry(geometry)
        state = settings.value("window/state")
        if state:
            self.restoreState(state)

        self.update_ui_for_simulation_mode() # Ensure UI reflects loaded sim mode correctly
        self.append_app_log("Settings loaded.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    # Set application and organization name for QSettings to work without explicit path
    app.setOrganizationName("MyCompany")
    app.setApplicationName("MyAppName")

    main_gui = MainAppGui()
    main_gui.show()
    sys.exit(app.exec_())
