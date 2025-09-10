import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QCoreApplication
from src.gui.main_window import MainWindow

if __name__ == '__main__':
    QCoreApplication.setOrganizationName("PLC-Tools")
    QCoreApplication.setApplicationName("S7-PLC-Control")

    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec_())
