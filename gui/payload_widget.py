from PyQt5.QtWidgets import QWidget, QGridLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtCore import pyqtSignal

class PayloadWidget(QWidget):
    execute_payload_requested = pyqtSignal(str, str)
    browse_payload_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        self.payload_label = QLabel("Payload File (.bin):")
        self.payload_path_input = QLineEdit()
        self.payload_path_input.setReadOnly(True)
        self.payload_browse_button = QPushButton("Browse...")
        self.payload_browse_button.clicked.connect(self.browse_payload_requested.emit)
        layout.addWidget(self.payload_label, 0, 0)
        layout.addWidget(self.payload_path_input, 0, 1)
        layout.addWidget(self.payload_browse_button, 0, 2)
        self.args_label = QLabel("Arguments (optional):")
        self.args_input = QLineEdit()
        layout.addWidget(self.args_label, 1, 0)
        layout.addWidget(self.args_input, 1, 1, 1, 2)
        self.execute_button = QPushButton("Execute Payload")
        self.execute_button.clicked.connect(self._emit_execute)
        layout.addWidget(self.execute_button, 2, 0, 1, 3)
    def _emit_execute(self):
        path = self.payload_path_input.text()
        args = self.args_input.text()
        self.execute_payload_requested.emit(path, args)
