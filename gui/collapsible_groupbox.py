from PyQt5.QtWidgets import QWidget, QVBoxLayout, QToolButton, QFrame, QSizePolicy
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve

class CollapsibleGroupBox(QWidget):
    def __init__(self, title="", parent=None, animation_duration=300):
        super().__init__(parent)
        self.animation_duration = animation_duration
        self.is_expanded = True
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.toggle_button = QToolButton(self)
        self.toggle_button.setStyleSheet("QToolButton { border: none; }")
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.setArrowType(Qt.DownArrow)
        self.toggle_button.setText(str(title))
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(self.is_expanded)
        self.toggle_button.clicked.connect(self._toggle)
        self.content_area = QFrame(self)
        self.content_area.setFrameShape(QFrame.StyledPanel)
        self.content_area.setFrameShadow(QFrame.Plain)
        self.content_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.content_layout = QVBoxLayout(self.content_area)
        self.animation = QPropertyAnimation(self.content_area, b"maximumHeight")
        self.animation.setDuration(self.animation_duration)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        main_layout.addWidget(self.toggle_button)
        main_layout.addWidget(self.content_area)
        if not self.is_expanded:
            self.content_area.setMaximumHeight(0)
    def addWidget(self, widget):
        self.content_layout.addWidget(widget)
        if self.is_expanded:
            self.content_area.setMaximumHeight(self.content_area.sizeHint().height() + self.content_layout.contentsMargins().top() + self.content_layout.contentsMargins().bottom())
    def setContentLayout(self, layout):
        while self.content_layout.count():
            child = self.content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self.content_layout.addLayout(layout)
        if self.is_expanded:
            self.content_area.setMaximumHeight(self.content_area.sizeHint().height() + self.content_layout.contentsMargins().top() + self.content_layout.contentsMargins().bottom())
    def _toggle(self):
        self.is_expanded = not self.is_expanded
        self.toggle_button.setArrowType(Qt.DownArrow if self.is_expanded else Qt.RightArrow)
        self.animation.stop()
        if self.is_expanded:
            target_height = self.content_area.sizeHint().height()
            if target_height == 0 and self.content_layout.count() > 0:
                target_height = self.content_layout.sizeHint().height()
            self.animation.setStartValue(0)
            self.animation.setEndValue(target_height if target_height > 0 else 300)
        else:
            self.animation.setStartValue(self.content_area.height())
            self.animation.setEndValue(0)
        self.animation.start()
