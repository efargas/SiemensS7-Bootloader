import sys
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox, QTabWidget, QTextEdit,
    QFileDialog, QMessageBox
)
from PyQt5.QtCore import QThread, QObject, pyqtSignal, pyqtSlot, QWaitCondition, QMutex

from src.logic.plc_client import PlcClient

class Worker(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    log_message = pyqtSignal(str)
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
            self.log_message.emit(f"An error occurred in worker thread: {e}")
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
        self.setGeometry(100, 100, 800, 600)

        self.plc_client = None
        self.thread = None
        self.worker = None

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self._create_connection_group()
        self._create_actions_group()
        self._create_log_group()

        self.layout.addWidget(self.connection_group)
        self.layout.addWidget(self.actions_group)
        self.layout.addWidget(self.log_group)

        self.update_ui_state()

    def _create_connection_group(self):
        self.connection_group = QGroupBox("Connection")
        layout = QVBoxLayout()
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("localhost")
        h_layout.addWidget(self.host_input)
        h_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit("9999")
        h_layout.addWidget(self.port_input)
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.toggle_connection)
        h_layout.addWidget(self.connect_button)
        layout.addLayout(h_layout)
        self.ps_checkbox = QCheckBox("Switch Power Supply")
        layout.addWidget(self.ps_checkbox)
        ps_layout = QHBoxLayout()
        ps_layout.addWidget(QLabel("PS Host:"))
        self.ps_host_input = QLineEdit("powersupply")
        ps_layout.addWidget(self.ps_host_input)
        ps_layout.addWidget(QLabel("PS Port:"))
        self.ps_port_input = QLineEdit("80")
        ps_layout.addWidget(self.ps_port_input)
        ps_layout.addWidget(QLabel("Delay (s):"))
        self.ps_delay_spinbox = QSpinBox()
        self.ps_delay_spinbox.setValue(10)
        ps_layout.addWidget(self.ps_delay_spinbox)
        layout.addLayout(ps_layout)
        self.connection_group.setLayout(layout)

    def _create_actions_group(self):
        self.actions_group = QGroupBox("Actions")
        layout = QVBoxLayout()
        self.tabs = QTabWidget()
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
        self.dump_addr_input = QLineEdit("0x10000000")
        layout.addWidget(self.dump_addr_input)
        layout.addWidget(QLabel("Length (bytes):"))
        self.dump_len_input = QLineEdit("256")
        layout.addWidget(self.dump_len_input)
        self.dump_payload_button = QPushButton("Select Dump Payload")
        self.dump_payload_button.clicked.connect(lambda: self.select_file(self.dump_payload_label))
        self.dump_payload_label = QLabel("payloads/dump_mem/build/dump_mem.bin")
        layout.addWidget(self.dump_payload_button)
        layout.addWidget(self.dump_payload_label)
        self.dump_output_button = QPushButton("Select Output File")
        self.dump_output_button.clicked.connect(self.select_output_file)
        self.dump_output_label = QLabel("memory_dump.bin")
        layout.addWidget(self.dump_output_button)
        layout.addWidget(self.dump_output_label)
        self.dump_tab.setLayout(layout)
        self.tabs.addTab(self.dump_tab, "Dump Memory")

    def _create_test_tab(self):
        self.test_tab = QWidget()
        layout = QVBoxLayout()
        self.test_payload_button = QPushButton("Select Test Payload")
        self.test_payload_button.clicked.connect(lambda: self.select_file(self.test_payload_label))
        self.test_payload_label = QLabel("payloads/hello_world/hello_world.bin")
        layout.addWidget(self.test_payload_button)
        layout.addWidget(self.test_payload_label)
        self.test_tab.setLayout(layout)
        self.tabs.addTab(self.test_tab, "Run Test Payload")

    def _create_tictactoe_tab(self):
        self.tictactoe_tab = QWidget()
        layout = QVBoxLayout()
        self.ttt_payload_button = QPushButton("Select TicTacToe Payload")
        self.ttt_payload_button.clicked.connect(lambda: self.select_file(self.ttt_payload_label))
        self.ttt_payload_label = QLabel("payloads/tic_tac_toe/build/tic_tac_toe.bin")
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
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)
        self.log_group.setLayout(layout)

    def update_ui_state(self, is_running=False):
        is_connected = self.plc_client is not None and self.plc_client.r is not None
        self.connection_group.setEnabled(not is_running)
        self.actions_group.setEnabled(is_connected and not is_running)
        self.run_button.setEnabled(is_connected and not is_running)

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

        self.worker.log_message.connect(self.update_log)
        self.worker.error.connect(self.on_error)
        self.worker.finished.connect(self.on_worker_finished)

        # Action-specific connections
        self.worker.dump_finished.connect(self.save_dump_file)
        self.worker.tictactoe_output.connect(self.handle_tictactoe_output)
        self.tictactoe_input_ready.connect(self.worker.provide_input)

        self.thread.started.connect(self.worker.run)
        self.thread.start()
        self.update_ui_state(is_running=True)

    def connect_plc(self):
        host = self.host_input.text()
        port = int(self.port_input.text())
        self.plc_client = PlcClient(host, port, log_callback=self.update_log)
        kwargs = {
            "switch_power": self.ps_checkbox.isChecked(),
            "ps_host": self.ps_host_input.text(),
            "ps_port": int(self.ps_port_input.text()),
            "ps_delay": self.ps_delay_spinbox.value()
        }
        self._start_worker("connect", **kwargs)

    def disconnect_plc(self):
        self._start_worker("disconnect")

    def run_action(self):
        current_tab = self.tabs.currentWidget()
        try:
            if current_tab == self.dump_tab:
                address = int(self.dump_addr_input.text(), 0)
                length = int(self.dump_len_input.text(), 0)
                payload_path = self.dump_payload_label.text()
                with open(payload_path, "rb") as f:
                    payload = f.read()
                self._start_worker("dump_memory", address=address, length=length, dump_payload=payload)
            elif current_tab == self.test_tab:
                payload_path = self.test_payload_label.text()
                with open(payload_path, "rb") as f:
                    payload = f.read()
                self._start_worker("run_test", payload=payload)
            elif current_tab == self.tictactoe_tab:
                payload_path = self.ttt_payload_label.text()
                with open(payload_path, "rb") as f:
                    payload = f.read()
                self.ttt_output.clear()
                self._start_worker("run_tictactoe", payload=payload)
        except (ValueError, FileNotFoundError) as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_worker_finished(self):
        if self.worker.action == "connect" and self.plc_client.r is None:
             # Connection failed
             self.plc_client = None
        elif self.worker.action == "disconnect":
             self.plc_client = None

        self.thread.quit()
        self.thread.wait()
        self.update_ui_state(is_running=False)

    def on_error(self, message):
        QMessageBox.critical(self, "Error", message)
        if self.worker.action == "connect":
            self.plc_client = None # Ensure client is cleared on connection error
        self.update_ui_state(is_running=False)


    @pyqtSlot(bytes)
    def save_dump_file(self, data):
        output_path = self.dump_output_label.text()
        try:
            with open(output_path, "wb") as f:
                f.write(data)
            self.update_log(f"Memory dump saved to {output_path}")
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
        filename, _ = QFileDialog.getOpenFileName(self, "Select Payload", "", "Binary Files (*.bin);;All Files (*)")
        if filename:
            label_widget.setText(filename)

    def select_output_file(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Dump As...", "", "Binary Files (*.bin);;All Files (*)")
        if filename:
            self.dump_output_label.setText(filename)

    def closeEvent(self, event):
        if self.plc_client and self.plc_client.r:
            self.disconnect_plc()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())
