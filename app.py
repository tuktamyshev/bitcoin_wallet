from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

import storage
from ledger import Ledger
from wallet_widget import WalletWidget


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bitcoin HD-кошелёк — Лаборатория")
        self.setMinimumSize(1100, 820)

        self.data = storage.load_data()
        self.ledger = Ledger()
        self.ledger.import_state(self.data.get("ledger", {}))

        self._split = False
        self._active = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── toolbar ──
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self.btn_a = QPushButton("Кошелёк A")
        self.btn_a.setObjectName("walletTabBtn")
        self.btn_a.setCheckable(True)
        self.btn_a.setChecked(True)
        self.btn_a.setCursor(Qt.PointingHandCursor)
        self.btn_a.clicked.connect(lambda: self._select_wallet(0))

        self.btn_b = QPushButton("Кошелёк B")
        self.btn_b.setObjectName("walletTabBtn")
        self.btn_b.setCheckable(True)
        self.btn_b.setCursor(Qt.PointingHandCursor)
        self.btn_b.clicked.connect(lambda: self._select_wallet(1))

        self.split_btn = QPushButton("⫼  Разделить экран")
        self.split_btn.setObjectName("splitBtn")
        self.split_btn.setCursor(Qt.PointingHandCursor)
        self.split_btn.clicked.connect(self._toggle_split)

        toolbar.addWidget(self.btn_a)
        toolbar.addWidget(self.btn_b)
        toolbar.addStretch()
        toolbar.addWidget(self.split_btn)

        # ── wallets ──
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setChildrenCollapsible(False)

        saved_wallets = lambda: self.data.get("wallets", [])

        self.wallet1 = WalletWidget(
            "A", self.ledger,
            get_saved_wallets=saved_wallets,
            on_wallet_saved=self._on_wallet_saved,
            on_name_change=self._on_name_change,
        )
        self.wallet2 = WalletWidget(
            "B", self.ledger,
            get_saved_wallets=saved_wallets,
            on_wallet_saved=self._on_wallet_saved,
            on_name_change=self._on_name_change,
        )

        self.splitter.addWidget(self.wallet1)
        self.splitter.addWidget(self.wallet2)

        root.addLayout(toolbar)
        root.addWidget(self.splitter)

        self.ledger.add_listener(self._auto_save_ledger)

        self._apply_view()
        self._apply_styles()

    def _on_wallet_saved(self, wallet_info):
        storage.upsert_wallet(self.data, wallet_info)
        self.data["ledger"] = self.ledger.export_state()
        storage.save_data(self.data)

    def _on_name_change(self, slot, name):
        if slot == "A":
            self.btn_a.setText(name)
        else:
            self.btn_b.setText(name)

    def _auto_save_ledger(self):
        self.data["ledger"] = self.ledger.export_state()
        storage.save_data(self.data)

    def _select_wallet(self, idx):
        if self._split:
            return
        self._active = idx
        self._apply_view()

    def _toggle_split(self):
        self._split = not self._split
        self._apply_view()

    def _apply_view(self):
        if self._split:
            self.wallet1.show()
            self.wallet2.show()
            self.splitter.setSizes([650, 650])
            self.split_btn.setText("⫼  Один экран")
            self.btn_a.setChecked(True)
            self.btn_b.setChecked(True)
            self.btn_a.setEnabled(False)
            self.btn_b.setEnabled(False)
        else:
            self.wallet1.setVisible(self._active == 0)
            self.wallet2.setVisible(self._active == 1)
            self.split_btn.setText("⫼  Разделить экран")
            self.btn_a.setEnabled(True)
            self.btn_b.setEnabled(True)
            self.btn_a.setChecked(self._active == 0)
            self.btn_b.setChecked(self._active == 1)

    def _apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background: #0f1117;
                color: #c9d1d9;
                font-family: "Helvetica Neue", "SF Pro Text", sans-serif;
                font-size: 13px;
            }
            QFrame#panel {
                background: #161b22;
                border: 1px solid #2d333b;
                border-radius: 10px;
            }
            QFrame#section {
                background: #1c2128;
                border: 1px solid #2d333b;
                border-radius: 8px;
            }
            QLabel#walletTitle {
                color: #a5b4fc;
                font-size: 15px;
                font-weight: 800;
                padding-bottom: 2px;
            }
            QLabel#sectionTitle {
                color: #e6edf3;
                font-size: 12px;
                font-weight: 700;
            }
            QLabel#hintLabel {
                color: #484f58;
                font-size: 11px;
            }

            QPushButton {
                background: #6366f1;
                color: #fff;
                border: none;
                border-radius: 7px;
                padding: 6px 12px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover { background: #818cf8; }
            QPushButton:pressed { background: #4f46e5; }
            QPushButton:disabled { background: #21262d; color: #484f58; }

            QPushButton#generateBtn { background: #22c55e; font-weight: 700; }
            QPushButton#generateBtn:hover { background: #2dd46a; }
            QPushButton#generateBtn:pressed { background: #16a34a; }

            QPushButton#restoreBtn { background: #3b82f6; font-weight: 700; }
            QPushButton#restoreBtn:hover { background: #60a5fa; }
            QPushButton#restoreBtn:pressed { background: #2563eb; }

            QPushButton#fundBtn { background: #22c55e; font-weight: 700; }
            QPushButton#fundBtn:hover { background: #2dd46a; }
            QPushButton#fundBtn:pressed { background: #16a34a; }

            QPushButton#sendBtn { background: #f59e0b; color: #000; font-weight: 700; }
            QPushButton#sendBtn:hover { background: #fbbf24; }
            QPushButton#sendBtn:pressed { background: #d97706; }

            QPushButton#walletTabBtn {
                background: #21262d;
                color: #7d8590;
                border: 1px solid #2d333b;
                border-radius: 6px;
                padding: 5px 16px;
                font-weight: 700;
                font-size: 13px;
            }
            QPushButton#walletTabBtn:hover { background: #2d333b; color: #c9d1d9; }
            QPushButton#walletTabBtn:checked {
                background: #6366f1;
                color: #fff;
                border-color: #6366f1;
            }
            QPushButton#walletTabBtn:disabled {
                background: #6366f1;
                color: #fff;
                border-color: #6366f1;
                opacity: 0.8;
            }
            QPushButton#splitBtn {
                background: #1c2128;
                color: #a5b4fc;
                border: 1px solid #2d333b;
                border-radius: 6px;
                padding: 5px 16px;
                font-weight: 600;
                font-size: 13px;
            }
            QPushButton#splitBtn:hover { background: #2d333b; color: #c4b5fd; }

            QPushButton#toggleKeyBtn {
                background: #21262d;
                color: #7d8590;
                font-size: 11px;
                padding: 4px 8px;
                border-radius: 5px;
            }
            QPushButton#toggleKeyBtn:hover { background: #30363d; color: #c9d1d9; }

            QLineEdit, QComboBox {
                background: #0d1117;
                border: 1px solid #2d333b;
                border-radius: 7px;
                padding: 5px 7px;
                color: #c9d1d9;
                font-size: 12px;
                selection-background-color: #6366f1;
            }
            QLineEdit:focus, QComboBox:focus { border-color: #6366f1; }

            QTextEdit, QPlainTextEdit {
                background: #0d1117;
                border: 1px solid #2d333b;
                border-radius: 7px;
                padding: 6px;
                color: #c9d1d9;
                selection-background-color: #6366f1;
            }

            QTableWidget {
                background: #0d1117;
                border: 1px solid #2d333b;
                border-radius: 7px;
                gridline-color: #21262d;
                color: #c9d1d9;
                font-size: 11px;
                alternate-background-color: #111820;
            }
            QTableWidget::item:selected {
                background: rgba(99, 102, 241, 0.15);
                color: #a5b4fc;
            }
            QHeaderView::section {
                background: #161b22;
                color: #7d8590;
                padding: 4px 8px;
                border: none;
                border-bottom: 1px solid #2d333b;
                font-weight: 600;
                font-size: 11px;
            }

            QTabWidget::pane {
                background: #161b22;
                border: 1px solid #2d333b;
                border-top: none;
                border-radius: 0 0 8px 8px;
            }
            QTabBar::tab {
                background: #0d1117;
                color: #7d8590;
                border: 1px solid #2d333b;
                border-bottom: none;
                padding: 5px 10px;
                margin-right: 1px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: 600;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background: #161b22;
                color: #a5b4fc;
                border-bottom: 2px solid #6366f1;
            }
            QTabBar::tab:hover:!selected {
                background: #161b22;
                color: #c9d1d9;
            }

            QComboBox::drop-down { border: none; padding-right: 6px; }
            QComboBox QAbstractItemView {
                background: #161b22;
                border: 1px solid #2d333b;
                color: #c9d1d9;
                selection-background-color: rgba(99, 102, 241, 0.2);
            }

            QSplitter::handle { background: #2d333b; }
            QSplitter::handle:horizontal { width: 2px; margin: 6px 3px; }
            QSplitter::handle:vertical { height: 2px; margin: 3px 6px; }

            QScrollBar:vertical {
                background: transparent; width: 5px;
            }
            QScrollBar::handle:vertical {
                background: #2d333b; min-height: 18px; border-radius: 2px;
            }
            QScrollBar::handle:vertical:hover { background: #484f58; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                height: 0; background: none;
            }
            QScrollBar:horizontal {
                background: transparent; height: 5px;
            }
            QScrollBar::handle:horizontal {
                background: #2d333b; min-width: 18px; border-radius: 2px;
            }
            QScrollBar::handle:horizontal:hover { background: #484f58; }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                width: 0; background: none;
            }
        """)
