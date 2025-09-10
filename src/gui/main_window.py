import sys
import logging
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox, QTabWidget, QTextEdit,
    QFileDialog, QMessageBox, QComboBox, QStackedWidget
)
from PyQt5.QtCore import QThread, QObject, pyqtSignal, pyqtSlot, QWaitCondition, QMutex, QSettings, QRegExp
from PyQt5.QtGui import QIntValidator, QRegExpValidator

from src.logic.plc_client import PlcClient
from src.gui.log_handler import QLogHandler

class Worker(QObject):
    # ... (Worker class remains the same)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    tictactoe_output = pyqtSignal(str)
    dump_finished = pyqtSignal(bytes)

    def __init__(self, plc_client, action, **kwargs):
        super().__init__()
        self.plc_client = plc_client
        self.action = action
        self.kwargs = kwargs
        self.mutex = QMutex()
        self.wait_condition = QWaitCondition()
        self.input_data = None
        self.logger = logging.getLogger(__name__)

    def run(self):
        try:
            if self.action == "connect":
                if not self.plc_client.connect(**self.kwargs):
                    self.error.emit("Failed to connect to PLC.")
            elif self.action == "disconnect":
                self.plc_client.disconnect(**self.kwargs)
            elif self.action == "dump_memory":
                data = self.plc_client.dump_memory(**self.kwargs)
                self.dump_finished.emit(data)
            elif self.action == "run_test":
                self.plc_client.run_test_payload(**self.kwargs)
            elif self.action == "run_tictactoe":
                self.plc_client.run_tictactoe(
                    input_callback=self.request_input_from_gui,
                    output_callback=self.tictactoe_output.emit,
                    **self.kwargs
                )
            self.finished.emit()
        except Exception as e:
            self.logger.error(f"An error occurred in worker thread: {e}", exc_info=True)
            self.error.emit(str(e))

    def request_input_from_gui(self):
        self.mutex.lock()
        self.tictactoe_output.emit("<<Awaiting input from GUI>>")
        self.wait_condition.wait(self.mutex)
        data = self.input_data
        self.mutex.unlock()
        return data

    def provide_input(self, data):
        self.mutex.lock()
        self.input_data = data
        self.wait_condition.wakeAll()
        self.mutex.unlock()

class MainWindow(QMainWindow):
    tictactoe_input_ready = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Siemens S7 PLC Control")

        self.settings = QSettings()
        self._setup_logging()

        self.plc_client = None
        self.thread = None
        self.worker = None

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self._create_connection_group()
        self._create_actions_group()
        self._create_log_group()
        self._set_validators()

        self.layout.addWidget(self.connection_group)
        self.layout.addWidget(self.actions_group)
        self.layout.addWidget(self.log_group)

        self.load_settings()
        self.update_ui_state()

    def _setup_logging(self):
        self.log_handler = QLogHandler()
        self.log_handler.log_received.connect(self.update_log)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
        self.log_handler.setFormatter(formatter)

        file_handler = logging.FileHandler("app.log")
        file_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.addHandler(self.log_handler)
        root_logger.addHandler(file_handler)
        root_logger.setLevel(logging.DEBUG)

    def _create_connection_group(self):
        self.connection_group = QGroupBox("Connection")
        layout = QVBoxLayout()
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit()
        h_layout.addWidget(self.host_input)
        h_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit()
        h_layout.addWidget(self.port_input)
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.toggle_connection)
        h_layout.addWidget(self.connect_button)
        layout.addLayout(h_layout)

        self.ps_checkbox = QCheckBox("Switch Power Supply")
        self.ps_checkbox.toggled.connect(self._toggle_ps_widgets)
        layout.addWidget(self.ps_checkbox)

        self._create_ps_group()
        layout.addWidget(self.ps_group)

        self.connection_group.setLayout(layout)

    def _create_ps_group(self):
        self.ps_group = QGroupBox("Power Supply Configuration")
        layout = QVBoxLayout()

        self.ps_type_combo = QComboBox()
        self.ps_type_combo.addItems(["HTTP Switch", "Modbus TCP"])
        self.ps_type_combo.currentIndexChanged.connect(self._update_ps_stack)
        layout.addWidget(self.ps_type_combo)

        self.ps_stack = QStackedWidget()

        http_widget = QWidget()
        http_layout = QHBoxLayout()
        http_layout.addWidget(QLabel("PS Host:"))
        self.ps_host_input = QLineEdit()
        http_layout.addWidget(self.ps_host_input)
        http_layout.addWidget(QLabel("PS Port:"))
        self.ps_port_input = QLineEdit()
        http_layout.addWidget(self.ps_port_input)
        http_widget.setLayout(http_layout)

        modbus_widget = QWidget()
        modbus_layout = QHBoxLayout()
        modbus_layout.addWidget(QLabel("Modbus Host:"))
        self.modbus_host_input = QLineEdit()
        modbus_layout.addWidget(self.modbus_host_input)
        modbus_layout.addWidget(QLabel("Port:"))
        self.modbus_port_input = QLineEdit()
        modbus_layout.addWidget(self.modbus_port_input)
        modbus_layout.addWidget(QLabel("Slave ID:"))
        self.modbus_slave_id_spin = QSpinBox()
        self.modbus_slave_id_spin.setRange(0, 255)
        modbus_layout.addWidget(self.modbus_slave_id_spin)
        modbus_layout.addWidget(QLabel("Coil Addr:"))
        self.modbus_coil_addr_spin = QSpinBox()
        self.modbus_coil_addr_spin.setRange(0, 65535)
        modbus_layout.addWidget(self.modbus_coil_addr_spin)
        modbus_widget.setLayout(modbus_layout)

        self.ps_stack.addWidget(http_widget)
        self.ps_stack.addWidget(modbus_widget)

        layout.addWidget(self.ps_stack)

        delay_layout = QHBoxLayout()
        delay_layout.addStretch()
        delay_layout.addWidget(QLabel("Delay (s):"))
        self.ps_delay_spinbox = QSpinBox()
        self.ps_delay_spinbox.setRange(0, 3600)
        delay_layout.addWidget(self.ps_delay_spinbox)
        layout.addLayout(delay_layout)

        self.ps_group.setLayout(layout)
        self.ps_group.setVisible(False)

    def _toggle_ps_widgets(self, checked):
        self.ps_group.setVisible(checked)
        self.update_ui_state()

    def _update_ps_stack(self, index):
        self.ps_stack.setCurrentIndex(index)

    def _create_actions_group(self):
        self.actions_group = QGroupBox("Actions")
        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.update_ui_state)
        self._create_dump_tab()
        self._create_test_tab()
        self._create_tictactoe_tab()
        layout.addWidget(self.tabs)
        self.run_button = QPushButton("Run Action")
        self.run_button.clicked.connect(self.run_action)
        layout.addWidget(self.run_button)
        self.actions_group.setLayout(layout)

    def _create_dump_tab(self):
        self.dump_tab = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Address (hex):"))
        self.dump_addr_input = QLineEdit()
        layout.addWidget(self.dump_addr_input)
        layout.addWidget(QLabel("Length (bytes):"))
        self.dump_len_input = QLineEdit()
        layout.addWidget(self.dump_len_input)
        self.dump_payload_button = QPushButton("Select Dump Payload")
        self.dump_payload_button.clicked.connect(lambda: self.select_file(self.dump_payload_label))
        self.dump_payload_label = QLabel("No file selected.")
        layout.addWidget(self.dump_payload_button)
        layout.addWidget(self.dump_payload_label)
        self.dump_output_button = QPushButton("Select Output File")
        self.dump_output_button.clicked.connect(self.select_output_file)
        self.dump_output_label = QLabel("No file selected.")
        layout.addWidget(self.dump_output_button)
        layout.addWidget(self.dump_output_label)
        self.dump_tab.setLayout(layout)
        self.tabs.addTab(self.dump_tab, "Dump Memory")

    def _create_test_tab(self):
        self.test_tab = QWidget()
        layout = QVBoxLayout()
        self.test_payload_button = QPushButton("Select Test Payload")
        self.test_payload_button.clicked.connect(lambda: self.select_file(self.test_payload_label))
        self.test_payload_label = QLabel("No file selected.")
        layout.addWidget(self.test_payload_button)
        layout.addWidget(self.test_payload_label)
        self.test_tab.setLayout(layout)
        self.tabs.addTab(self.test_tab, "Run Test Payload")

    def _create_tictactoe_tab(self):
        self.tictactoe_tab = QWidget()
        layout = QVBoxLayout()
        self.ttt_payload_button = QPushButton("Select TicTacToe Payload")
        self.ttt_payload_button.clicked.connect(lambda: self.select_file(self.ttt_payload_label))
        self.ttt_payload_label = QLabel("No file selected.")
        layout.addWidget(self.ttt_payload_button)
        layout.addWidget(self.ttt_payload_label)
        self.ttt_output = QTextEdit()
        self.ttt_output.setReadOnly(True)
        layout.addWidget(self.ttt_output)
        self.ttt_input = QLineEdit()
        self.ttt_input.setPlaceholderText("Enter your move and press Enter")
        self.ttt_input.returnPressed.connect(self.send_tictactoe_input)
        layout.addWidget(self.ttt_input)
        self.tictactoe_tab.setLayout(layout)
        self.tabs.addTab(self.tictactoe_tab, "Tic-Tac-Toe")

    def _create_log_group(self):
        self.log_group = QGroupBox("Log")
        layout = QVBoxLayout()

        log_level_layout = QHBoxLayout()
        log_level_layout.addWidget(QLabel("UI Log Level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level_combo.currentIndexChanged.connect(self.set_log_level)
        log_level_layout.addWidget(self.log_level_combo)
        log_level_layout.addStretch()
        layout.addLayout(log_level_layout)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)
        self.log_group.setLayout(layout)

    def _set_validators(self):
        port_validator = QIntValidator(1, 65535, self)
        self.port_input.setValidator(port_validator)
        self.ps_port_input.setValidator(port_validator)
        self.modbus_port_input.setValidator(port_validator)

        hex_validator = QRegExpValidator(QRegExp("0x[0-9A-Fa-f]{1,8}"), self)
        self.dump_addr_input.setValidator(hex_validator)

        len_validator = QIntValidator(1, 0xFFFFFFFF, self)
        self.dump_len_input.setValidator(len_validator)

    def set_log_level(self, index):
        level_str = self.log_level_combo.currentText()
        level = getattr(logging, level_str)
        self.log_handler.setLevel(level)

    def update_ui_state(self, is_running=False):
        is_connected = self.plc_client is not None and self.plc_client.r is not None
        self.connection_group.setEnabled(not is_running)
        self.actions_group.setEnabled(is_connected and not is_running)

        run_enabled = is_connected and not is_running
        if run_enabled:
            current_tab = self.tabs.currentWidget()
            if current_tab == self.dump_tab:
                if not os.path.exists(self.dump_payload_label.text()) or not self.dump_output_label.text():
                    run_enabled = False
            elif current_tab == self.test_tab:
                if not os.path.exists(self.test_payload_label.text()):
                    run_enabled = False
            elif current_tab == self.tictactoe_tab:
                if not os.path.exists(self.ttt_payload_label.text()):
                    run_enabled = False

        self.run_button.setEnabled(run_enabled)

        if is_running:
            self.connect_button.setText("Busy...")
        elif is_connected:
            self.connect_button.setText("Disconnect")
        else:
            self.connect_button.setText("Connect")

    @pyqtSlot(str)
    def update_log(self, message):
        self.log_output.append(message)

    def toggle_connection(self):
        if not self.plc_client or not self.plc_client.r:
            self.connect_plc()
        else:
            self.disconnect_plc()

    def _start_worker(self, action, **kwargs):
        self.thread = QThread()
        self.worker = Worker(self.plc_client, action, **kwargs)
        self.worker.moveToThread(self.thread)

        self.worker.error.connect(self.on_error)
        self.worker.finished.connect(self.on_worker_finished)

        self.worker.dump_finished.connect(self.save_dump_file)
        self.worker.tictactoe_output.connect(self.handle_tictactoe_output)
        self.tictactoe_input_ready.connect(self.worker.provide_input)

        self.thread.started.connect(self.worker.run)
        self.thread.start()
        self.update_ui_state(is_running=True)

    def connect_plc(self):
        host = self.host_input.text()
        port_text = self.port_input.text()
        if not port_text:
            QMessageBox.critical(self, "Input Error", "PLC Port cannot be empty.")
            return
        port = int(port_text)

        self.plc_client = PlcClient(host, port)

        kwargs = {"switch_power": self.ps_checkbox.isChecked()}
        if self.ps_checkbox.isChecked():
            kwargs["ps_delay"] = self.ps_delay_spinbox.value()
            ps_type = self.ps_type_combo.currentText()
            kwargs["ps_type"] = ps_type
            if ps_type == "HTTP Switch":
                kwargs["ps_host"] = self.ps_host_input.text()
                kwargs["ps_port"] = int(self.ps_port_input.text())
            elif ps_type == "Modbus TCP":
                kwargs["ps_host"] = self.modbus_host_input.text()
                kwargs["ps_port"] = int(self.modbus_port_input.text())
                kwargs["modbus_slave_id"] = self.modbus_slave_id_spin.value()
                kwargs["modbus_coil_addr"] = self.modbus_coil_addr_spin.value()

        self._start_worker("connect", **kwargs)

    def disconnect_plc(self):
        self._start_worker("disconnect")

    def run_action(self):
        current_tab = self.tabs.currentWidget()
        try:
            if current_tab == self.dump_tab:
                payload_path = self.dump_payload_label.text()
                address = int(self.dump_addr_input.text(), 0)
                length = int(self.dump_len_input.text(), 0)
                self._start_worker("dump_memory", address=address, length=length, dump_payload=open(payload_path, "rb").read())
            elif current_tab == self.test_tab:
                payload_path = self.test_payload_label.text()
                self._start_worker("run_test", payload=open(payload_path, "rb").read())
            elif current_tab == self.tictactoe_tab:
                payload_path = self.ttt_payload_label.text()
                self.ttt_output.clear()
                self._start_worker("run_tictactoe", payload=open(payload_path, "rb").read())
        except (ValueError, FileNotFoundError) as e:
            QMessageBox.critical(self, "Error", f"Failed to start action: {e}")

    def on_worker_finished(self):
        if self.worker.action == "connect" and (not self.plc_client or self.plc_client.r is None):
             self.plc_client = None
        elif self.worker.action == "disconnect":
             self.plc_client = None

        self.thread.quit()
        self.thread.wait()
        self.update_ui_state(is_running=False)

    def on_error(self, message):
        QMessageBox.critical(self, "Error", message)
        if self.worker.action == "connect":
            self.plc_client = None
        self.update_ui_state(is_running=False)

    @pyqtSlot(bytes)
    def save_dump_file(self, data):
        output_path = self.dump_output_label.text()
        try:
            with open(output_path, "wb") as f:
                f.write(data)
            QMessageBox.information(self, "Success", f"Memory dump saved to {output_path}")
        except IOError as e:
            QMessageBox.critical(self, "File Error", f"Failed to save dump file: {e}")

    @pyqtSlot(str)
    def handle_tictactoe_output(self, text):
        self.ttt_output.insertPlainText(text)
        self.ttt_output.ensureCursorVisible()

    def send_tictactoe_input(self):
        text = self.ttt_input.text()
        self.ttt_input.clear()
        self.tictactoe_input_ready.emit(text)

    def select_file(self, label_widget):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Payload", os.getcwd(), "Binary Files (*.bin);;All Files (*)")
        if filename:
            label_widget.setText(filename)
            self.update_ui_state()

    def select_output_file(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Dump As...", os.getcwd(), "Binary Files (*.bin);;All Files (*)")
        if filename:
            self.dump_output_label.setText(filename)
            self.update_ui_state()

    def load_settings(self):
        self.restoreGeometry(self.settings.value("geometry", self.saveGeometry()))
        self.host_input.setText(self.settings.value("connection/host", "localhost"))
        self.port_input.setText(self.settings.value("connection/port", "9999"))
        self.ps_checkbox.setChecked(self.settings.value("ps/enabled", False, type=bool))
        self.ps_type_combo.setCurrentIndex(self.settings.value("ps/type_index", 0, type=int))
        self.ps_host_input.setText(self.settings.value("ps/http_host", "powersupply"))
        self.ps_port_input.setText(self.settings.value("ps/http_port", "80"))
        self.modbus_host_input.setText(self.settings.value("ps/modbus_host", "localhost"))
        self.modbus_port_input.setText(self.settings.value("ps/modbus_port", "502"))
        self.modbus_slave_id_spin.setValue(self.settings.value("ps/modbus_slave_id", 1, type=int))
        self.modbus_coil_addr_spin.setValue(self.settings.value("ps/modbus_coil_addr", 0, type=int))
        self.ps_delay_spinbox.setValue(self.settings.value("ps/delay", 10, type=int))
        self.dump_addr_input.setText(self.settings.value("dump/address", "0x10000000"))
        self.dump_len_input.setText(self.settings.value("dump/length", "256"))
        self.dump_payload_label.setText(self.settings.value("dump/payload_path", "payloads/dump_mem/build/dump_mem.bin"))
        self.dump_output_label.setText(self.settings.value("dump/output_path", "memory_dump.bin"))
        self.test_payload_label.setText(self.settings.value("test/payload_path", "payloads/hello_world/hello_world.bin"))
        self.ttt_payload_label.setText(self.settings.value("tictactoe/payload_path", "payloads/tic_tac_toe/build/tic_tac_toe.bin"))
        self.log_level_combo.setCurrentText(self.settings.value("logging/level", "INFO"))
        self.set_log_level(self.log_level_combo.currentIndex())

    def save_settings(self):
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("connection/host", self.host_input.text())
        self.settings.setValue("connection/port", self.port_input.text())
        self.settings.setValue("ps/enabled", self.ps_checkbox.isChecked())
        self.settings.setValue("ps/type_index", self.ps_type_combo.currentIndex())
        self.settings.setValue("ps/http_host", self.ps_host_input.text())
        self.settings.setValue("ps/http_port", self.ps_port_input.text())
        self.settings.setValue("ps/modbus_host", self.modbus_host_input.text())
        self.settings.setValue("ps/modbus_port", self.modbus_port_input.text())
        self.settings.setValue("ps/modbus_slave_id", self.modbus_slave_id_spin.value())
        self.settings.setValue("ps/modbus_coil_addr", self.modbus_coil_addr_spin.value())
        self.settings.setValue("ps/delay", self.ps_delay_spinbox.value())
        self.settings.setValue("dump/address", self.dump_addr_input.text())
        self.settings.setValue("dump/length", self.dump_len_input.text())
        self.settings.setValue("dump/payload_path", self.dump_payload_label.text())
        self.settings.setValue("dump/output_path", self.dump_output_label.text())
        self.settings.setValue("test/payload_path", self.test_payload_label.text())
        self.settings.setValue("tictactoe/payload_path", self.ttt_payload_label.text())
        self.settings.setValue("logging/level", self.log_level_combo.currentText())

    def closeEvent(self, event):
        self.save_settings()
        if self.plc_client and self.plc_client.r:
            self.disconnect_plc()
        event.accept()

if __name__ == '__main__':
    # ... (main execution)
    pass
