from PyQt5.QtWidgets import QWidget, QGridLayout, QLabel, QLineEdit, QPushButton
from PyQt5.QtCore import pyqtSignal

class PowerSupplyWidget(QWidget):
    power_on_requested = pyqtSignal(str, int, int)
    power_off_requested = pyqtSignal(str, int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)

        self.modbus_ip_label = QLabel("Modbus IP:")
        self.modbus_ip_input = QLineEdit("192.168.1.18")
        layout.addWidget(self.modbus_ip_label, 0, 0)
        layout.addWidget(self.modbus_ip_input, 0, 1)

        self.modbus_port_label = QLabel("Modbus Port:")
        self.modbus_port_input = QLineEdit("502")
        layout.addWidget(self.modbus_port_label, 1, 0)
        layout.addWidget(self.modbus_port_input, 1, 1)

        self.modbus_output_label = QLabel("Modbus Output:")
        self.modbus_output_input = QLineEdit("1")
        layout.addWidget(self.modbus_output_label, 2, 0)
        layout.addWidget(self.modbus_output_input, 2, 1)

        self.power_on_button = QPushButton("Power ON")
        self.power_on_button.clicked.connect(self._emit_power_on)
        layout.addWidget(self.power_on_button, 3, 0)

        self.power_off_button = QPushButton("Power OFF")
        self.power_off_button.clicked.connect(self._emit_power_off)
        layout.addWidget(self.power_off_button, 3, 1)

    def _emit_power_on(self):
        try:
            ip = self.modbus_ip_input.text()
            port = int(self.modbus_port_input.text())
            output = int(self.modbus_output_input.text())
            self.power_on_requested.emit(ip, port, output)
        except Exception:
            pass

    def _emit_power_off(self):
        try:
            ip = self.modbus_ip_input.text()
            port = int(self.modbus_port_input.text())
            output = int(self.modbus_output_input.text())
            self.power_off_requested.emit(ip, port, output)
        except Exception:
            pass
