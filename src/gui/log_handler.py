import logging
from PyQt5.QtCore import QObject, pyqtSignal

class QLogHandler(logging.Handler, QObject):
    log_received = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        QObject.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.log_received.emit(msg)
