from PyQt5.QtWidgets import QWidget, QGridLayout, QLabel, QLineEdit, QComboBox, QPushButton
from PyQt5.QtCore import pyqtSignal

class ConnectionWidget(QWidget):
    connect_requested = pyqtSignal(str, int, str)
    disconnect_requested = pyqtSignal()
    autodetect_requested = pyqtSignal()
    start_socat_requested = pyqtSignal(str, int)
    stop_socat_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        self.socat_port_label = QLabel("Forwarded TCP Port:")
        self.socat_port_input = QLineEdit("1238")
        layout.addWidget(self.socat_port_label, 0, 0)
        layout.addWidget(self.socat_port_input, 0, 1)
        self.tty_label = QLabel("Serial Device (ttyUSB):")
        self.tty_combo = QComboBox()
        for i in range(4):
            self.tty_combo.addItem(f"/dev/ttyUSB{i}")
        layout.addWidget(self.tty_label, 1, 0)
        layout.addWidget(self.tty_combo, 1, 1)
        self.autodetect_button = QPushButton("Autodetect Devices")
        self.autodetect_button.clicked.connect(self._emit_autodetect)
        layout.addWidget(self.autodetect_button, 2, 0, 1, 2)
        self.connect_button = QPushButton("Connect to PLC")
        self.connect_button.clicked.connect(self._emit_connect)
        layout.addWidget(self.connect_button, 3, 0)
        self.disconnect_button = QPushButton("Disconnect PLC")
        self.disconnect_button.clicked.connect(self._emit_disconnect)
        layout.addWidget(self.disconnect_button, 3, 1)
        self.start_socat_button = QPushButton("Start Socat")
        self.start_socat_button.clicked.connect(self._emit_start_socat)
        layout.addWidget(self.start_socat_button, 4, 0)
        self.stop_socat_button = QPushButton("Stop Socat")
        self.stop_socat_button.clicked.connect(self._emit_stop_socat)
        layout.addWidget(self.stop_socat_button, 4, 1)
    def _emit_connect(self):
        try:
            port = int(self.socat_port_input.text())
            tty = self.tty_combo.currentText()
            self.connect_requested.emit("localhost", port, tty)
        except Exception:
            pass
    def _emit_disconnect(self):
        self.disconnect_requested.emit()
    def _emit_autodetect(self):
        self.autodetect_requested.emit()
    def _emit_start_socat(self):
        try:
            port = int(self.socat_port_input.text())
            tty = self.tty_combo.currentText()
            self.start_socat_requested.emit(tty, port)
        except Exception:
            pass
    def _emit_stop_socat(self):
        self.stop_socat_requested.emit()
