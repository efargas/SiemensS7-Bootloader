from PyQt5.QtWidgets import QMessageBox

def show_message(parent, title, message, level="info"):
    msg_box = QMessageBox(parent)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    if level == "info":
        msg_box.setIcon(QMessageBox.Information)
    elif level == "warning":
        msg_box.setIcon(QMessageBox.Warning)
    elif level == "error":
        msg_box.setIcon(QMessageBox.Critical)
    msg_box.exec_()
