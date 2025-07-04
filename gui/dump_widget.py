from PyQt5.QtWidgets import QWidget, QGridLayout, QLabel, QLineEdit, QPushButton, QProgressBar
from PyQt5.QtCore import pyqtSignal

class DumpWidget(QWidget):
    start_dump_requested = pyqtSignal(str, int, str, str)
    browse_payload_requested = pyqtSignal()
    browse_output_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        self.dump_addr_label = QLabel("Start Address (hex):")
        self.dump_addr_input = QLineEdit("0x10010100")
        layout.addWidget(self.dump_addr_label, 0, 0)
        layout.addWidget(self.dump_addr_input, 0, 1)
        self.dump_len_label = QLabel("Number of Bytes:")
        self.dump_len_input = QLineEdit("1024")
        layout.addWidget(self.dump_len_label, 1, 0)
        layout.addWidget(self.dump_len_input, 1, 1)
        self.dump_payload_label = QLabel("Dump Payload:")
        self.dump_payload_path_input = QLineEdit("payloads/dump_mem/build/dump_mem.bin")
        self.dump_payload_path_input.setReadOnly(True)
        self.dump_payload_browse_button = QPushButton("Browse...")
        self.dump_payload_browse_button.clicked.connect(self.browse_payload_requested.emit)
        layout.addWidget(self.dump_payload_label, 2, 0)
        layout.addWidget(self.dump_payload_path_input, 2, 1)
        layout.addWidget(self.dump_payload_browse_button, 2, 2)
        self.dump_output_label = QLabel("Save Dump As:")
        self.dump_output_path_input = QLineEdit("memory_dump.bin")
        self.dump_output_path_input.setReadOnly(True)
        self.dump_output_browse_button = QPushButton("Browse...")
        self.dump_output_browse_button.clicked.connect(self.browse_output_requested.emit)
        layout.addWidget(self.dump_output_label, 3, 0)
        layout.addWidget(self.dump_output_path_input, 3, 1)
        layout.addWidget(self.dump_output_browse_button, 3, 2)
        self.start_dump_button = QPushButton("Start Dump")
        self.start_dump_button.clicked.connect(self._emit_start_dump)
        layout.addWidget(self.start_dump_button, 4, 0, 1, 3)
        self.dump_progress_bar = QProgressBar()
        layout.addWidget(self.dump_progress_bar, 5, 0, 1, 3)
    def _emit_start_dump(self):
        try:
            addr = int(self.dump_addr_input.text(), 16)
            length = int(self.dump_len_input.text())
            payload = self.dump_payload_path_input.text()
            output = self.dump_output_path_input.text()
            self.start_dump_requested.emit(payload, addr, length, output)
        except Exception:
            pass
