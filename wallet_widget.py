import json
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from ecdsa import SECP256k1, SigningKey
from mnemonic import Mnemonic

from crypto import (
    bech32_addr,
    calc_fee,
    addr_fee_info,
    compress,
    derive_path,
    fingerprint,
    master,
    p2pkh,
    p2sh,
    sha256,
    validate_address,
)

DEFAULT_ADDR_COUNT = 5
DEFAULT_ACCOUNT = 0
DEFAULT_FEE_RATE = 10


class WalletWidget(QWidget):
    def __init__(self, slot, ledger, get_saved_wallets=None,
                 on_wallet_saved=None, on_name_change=None):
        super().__init__()
        self.slot = slot
        self.ledger = ledger
        self._get_saved_wallets = get_saved_wallets or (lambda: [])
        self._on_wallet_saved = on_wallet_saved
        self._on_name_change = on_name_change
        self.wallet_data = {}
        self.address_tables = {}
        self._private_keys_visible = False
        self._private_key_map = {}
        self._all_addresses = []

        self.ledger.add_listener(self.refresh_balances)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        h_splitter = QSplitter(Qt.Horizontal)
        h_splitter.setChildrenCollapsible(False)
        h_splitter.addWidget(self._build_left_panel())
        h_splitter.addWidget(self._build_right_panel())
        h_splitter.setSizes([280, 520])
        h_splitter.setStretchFactor(0, 0)
        h_splitter.setStretchFactor(1, 1)

        v_splitter = QSplitter(Qt.Vertical)
        v_splitter.setChildrenCollapsible(False)
        v_splitter.addWidget(h_splitter)
        v_splitter.addWidget(self._build_journal_panel())
        v_splitter.setSizes([500, 200])
        v_splitter.setStretchFactor(0, 1)
        v_splitter.setStretchFactor(1, 0)

        root.addWidget(v_splitter)

    def _build_left_panel(self):
        container = QFrame()
        container.setObjectName("panel")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.wallet_title_label = QLabel(f"Кошелёк {self.slot}")
        self.wallet_title_label.setObjectName("walletTitle")

        self.wallet_name_input = QLineEdit()
        self.wallet_name_input.setPlaceholderText("Имя кошелька")

        self.word_count = QComboBox()
        self.word_count.addItems(["12 слов", "24 слова"])

        self.count_input = QLineEdit(str(DEFAULT_ADDR_COUNT))
        self.count_input.setPlaceholderText("Кол-во")

        self.account_input = QLineEdit(str(DEFAULT_ACCOUNT))
        self.account_input.setPlaceholderText("Индекс")

        self.passphrase_input = QLineEdit()
        self.passphrase_input.setPlaceholderText("Необязательно")

        grid = QGridLayout()
        grid.setHorizontalSpacing(6)
        grid.setVerticalSpacing(4)
        grid.setColumnStretch(0, 0)
        grid.setColumnStretch(1, 1)
        grid.addWidget(QLabel("Имя"), 0, 0)
        grid.addWidget(self.wallet_name_input, 0, 1)
        grid.addWidget(QLabel("Фраза"), 1, 0)
        grid.addWidget(self.word_count, 1, 1)
        grid.addWidget(QLabel("Адреса"), 2, 0)
        grid.addWidget(self.count_input, 2, 1)
        grid.addWidget(QLabel("Аккаунт"), 3, 0)
        grid.addWidget(self.account_input, 3, 1)
        grid.addWidget(QLabel("BIP39"), 4, 0)
        grid.addWidget(self.passphrase_input, 4, 1)

        self.generate_button = QPushButton("Создать")
        self.generate_button.setObjectName("generateBtn")
        self.generate_button.clicked.connect(self.create_wallet)
        self.generate_button.setMinimumHeight(34)
        self.generate_button.setCursor(Qt.PointingHandCursor)

        self.restore_button = QPushButton("Восстановить")
        self.restore_button.setObjectName("restoreBtn")
        self.restore_button.clicked.connect(self.restore_wallet)
        self.restore_button.setMinimumHeight(34)
        self.restore_button.setCursor(Qt.PointingHandCursor)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        btn_row.addWidget(self.generate_button)
        btn_row.addWidget(self.restore_button)

        lbl_mn = QLabel("Мнемоника")
        lbl_mn.setObjectName("sectionTitle")

        self.mnemonic_view = QPlainTextEdit()
        self.mnemonic_view.setPlaceholderText("Вставьте фразу или создайте кошелёк")
        self.mnemonic_view.setMaximumHeight(100)

        layout.addWidget(self.wallet_title_label)
        layout.addLayout(grid)
        layout.addSpacing(2)
        layout.addLayout(btn_row)
        layout.addSpacing(4)
        layout.addWidget(lbl_mn)
        layout.addWidget(self.mnemonic_view)
        layout.addStretch()
        return container

    def _build_right_panel(self):
        container = QFrame()
        container.setObjectName("panel")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.view_tabs = QTabWidget()

        self.overview_page = self._build_overview_tab()
        self.addresses_page = self._build_addresses_tab()
        self.tx_page = self._build_transactions_tab()
        self.inspector_page = self._build_inspector_tab()

        self.view_tabs.addTab(self.overview_page, "Обзор")
        self.view_tabs.addTab(self.addresses_page, "Адреса")
        self.view_tabs.addTab(self.tx_page, "Транзакции")
        self.view_tabs.addTab(self.inspector_page, "JSON")

        layout.addWidget(self.view_tabs)
        return container

    # ── Tab builders ──

    def _build_overview_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(8)
        self.wallet_summary = QTextEdit()
        self.wallet_summary.setReadOnly(True)
        layout.addWidget(self._wrap_section("Информация о кошельке", self.wallet_summary))
        return page

    def _build_addresses_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.toggle_keys_button = QPushButton("Приватные ключи")
        self.toggle_keys_button.setObjectName("toggleKeyBtn")
        self.toggle_keys_button.setCursor(Qt.PointingHandCursor)
        self.toggle_keys_button.clicked.connect(self._toggle_private_keys)
        self.toggle_keys_button.setEnabled(False)
        hint = QLabel("Двойной клик — скопировать адрес")
        hint.setObjectName("hintLabel")
        toolbar.addWidget(self.toggle_keys_button)
        toolbar.addStretch()
        toolbar.addWidget(hint)

        self.address_tabs = QTabWidget()
        for std in ("BIP44", "BIP49", "BIP84"):
            t = QTableWidget(0, 5)
            t.setHorizontalHeaderLabels(["#", "Путь", "Адрес", "Баланс (BTC)", "Приватный ключ"])
            t.horizontalHeader().setStretchLastSection(True)
            t.verticalHeader().setVisible(False)
            t.setEditTriggers(QTableWidget.NoEditTriggers)
            t.setSelectionBehavior(QTableWidget.SelectRows)
            t.setAlternatingRowColors(True)
            t.setColumnHidden(4, True)
            t.cellDoubleClicked.connect(self._copy_address_from_table)
            self.address_tabs.addTab(t, std)
            self.address_tables[std] = t

        layout.addLayout(toolbar)
        layout.addWidget(self.address_tabs)
        return page

    def _build_transactions_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        # ── Fund ──
        fund_frame = QFrame()
        fund_frame.setObjectName("section")
        fl = QVBoxLayout(fund_frame)
        fl.setContentsMargins(10, 10, 10, 10)
        fl.setSpacing(6)
        ft = QLabel("Пополнение (coinbase)")
        ft.setObjectName("sectionTitle")
        fl.addWidget(ft)

        fund_row = QHBoxLayout()
        fund_row.setSpacing(6)
        self.fund_combo = QComboBox()
        self.fund_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.fund_amount = QLineEdit()
        self.fund_amount.setPlaceholderText("BTC")
        self.fund_amount.setMaximumWidth(120)
        self.fund_btn = QPushButton("Пополнить")
        self.fund_btn.setObjectName("fundBtn")
        self.fund_btn.setCursor(Qt.PointingHandCursor)
        self.fund_btn.clicked.connect(self._do_fund)
        self.fund_btn.setEnabled(False)
        fund_row.addWidget(self.fund_combo, 1)
        fund_row.addWidget(self.fund_amount)
        fund_row.addWidget(self.fund_btn)
        fl.addLayout(fund_row)

        # ── Send ──
        send_frame = QFrame()
        send_frame.setObjectName("section")
        sl = QVBoxLayout(send_frame)
        sl.setContentsMargins(10, 10, 10, 10)
        sl.setSpacing(6)
        st = QLabel("Перевод (ECDSA)")
        st.setObjectName("sectionTitle")
        sl.addWidget(st)

        sg = QGridLayout()
        sg.setHorizontalSpacing(6)
        sg.setVerticalSpacing(4)
        sg.setColumnStretch(0, 0)
        sg.setColumnStretch(1, 1)

        sg.addWidget(QLabel("С адреса:"), 0, 0)
        self.send_from_combo = QComboBox()
        sg.addWidget(self.send_from_combo, 0, 1)

        sg.addWidget(QLabel("На адрес:"), 1, 0)
        self.send_to_input = QLineEdit()
        self.send_to_input.setPlaceholderText("Адрес получателя")
        sg.addWidget(self.send_to_input, 1, 1)

        sg.addWidget(QLabel("sat/vbyte:"), 2, 0)
        self.fee_rate_input = QLineEdit(str(DEFAULT_FEE_RATE))
        self.fee_rate_input.setMaximumWidth(80)
        sg.addWidget(self.fee_rate_input, 2, 1)

        sg.addWidget(QLabel("Сумма:"), 3, 0)
        send_amt_row = QHBoxLayout()
        self.send_amount = QLineEdit()
        self.send_amount.setPlaceholderText("BTC")
        self.send_amount.setMaximumWidth(120)
        self.send_btn = QPushButton("Отправить")
        self.send_btn.setObjectName("sendBtn")
        self.send_btn.setCursor(Qt.PointingHandCursor)
        self.send_btn.clicked.connect(self._do_send)
        self.send_btn.setEnabled(False)
        send_amt_row.addWidget(self.send_amount)
        send_amt_row.addWidget(self.send_btn)
        send_amt_row.addStretch()
        sg.addLayout(send_amt_row, 3, 1)
        sl.addLayout(sg)

        # ── History ──
        ht = QLabel("История транзакций")
        ht.setObjectName("sectionTitle")

        self.tx_table = QTableWidget(0, 6)
        self.tx_table.setHorizontalHeaderLabels(
            ["txid", "Время", "Откуда", "Куда", "Сумма", "Комиссия"]
        )
        self.tx_table.horizontalHeader().setStretchLastSection(True)
        self.tx_table.verticalHeader().setVisible(False)
        self.tx_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tx_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.tx_table.setAlternatingRowColors(True)

        layout.addWidget(fund_frame)
        layout.addWidget(send_frame)
        layout.addWidget(ht)
        layout.addWidget(self.tx_table)
        return page

    def _build_journal_panel(self):
        container = QFrame()
        container.setObjectName("panel")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 6, 8, 8)
        layout.setSpacing(4)
        lbl = QLabel("Журнал")
        lbl.setObjectName("sectionTitle")
        layout.addWidget(lbl)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Menlo", 11))
        layout.addWidget(self.console)
        return container

    def _build_inspector_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.inspector = QPlainTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setFont(QFont("Menlo", 10))
        layout.addWidget(self.inspector)
        return page

    def _wrap_section(self, title, widget):
        frame = QFrame()
        frame.setObjectName("section")
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)
        lbl = QLabel(title)
        lbl.setObjectName("sectionTitle")
        layout.addWidget(lbl)
        layout.addWidget(widget)
        return frame

    # ── Logging ──

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{ts}]  {msg}")

    # ── Validation ──

    def _validate_inputs(self):
        try:
            count = int(self.count_input.text().strip() or DEFAULT_ADDR_COUNT)
            account = int(self.account_input.text().strip() or DEFAULT_ACCOUNT)
            if count <= 0 or account < 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Кол-во адресов > 0, аккаунт >= 0.")
            return None
        return count, account

    # ── Wallet creation / restoration ──

    def create_wallet(self):
        wallet_name = self.wallet_name_input.text().strip()
        if not wallet_name:
            QMessageBox.warning(self, "Ошибка", "Введите имя кошелька.")
            return

        params = self._validate_inputs()
        if params is None:
            return
        count, account = params

        self.console.clear()

        strength = 256 if "24" in self.word_count.currentText() else 128
        passphrase = self.passphrase_input.text()

        self.log("╔══════════════════════════════════════════╗")
        self.log("║     Создание нового HD-кошелька Bitcoin  ║")
        self.log("╚══════════════════════════════════════════╝")
        self.log("")
        self.log("Шаг 1 · Генерация мнемонической фразы (BIP39)")
        self.log("─────────────────────────────────────────────")
        self.log(f"  Энтропия: {strength} бит из os.urandom.")
        self.log(f"  + контрольная сумма {strength // 32} бит (SHA-256).")
        self.log(f"  {strength + strength // 32} бит → {(strength + strength // 32) // 11} слов из словаря BIP39.")

        gen = Mnemonic("english")
        words = gen.generate(strength)
        self.log(f"  Результат: {len(words.split())} слов.")
        self.log("")

        self._build_wallet(words, passphrase, count, account)
        self.mnemonic_view.setPlainText(words)

    def restore_wallet(self):
        words = self.mnemonic_view.toPlainText().strip()
        if not words:
            QMessageBox.warning(self, "Ошибка", "Введите мнемоническую фразу.")
            return

        words = " ".join(words.split())
        gen = Mnemonic("english")
        if not gen.check(words):
            QMessageBox.warning(
                self, "Ошибка",
                "Мнемоническая фраза невалидна.\n"
                "Проверьте слова и их количество (12 или 24).",
            )
            return

        passphrase = self.passphrase_input.text()
        seed = gen.to_seed(words, passphrase=passphrase)
        fp = fingerprint(seed)

        from storage import find_wallet_by_fingerprint
        saved = find_wallet_by_fingerprint(self._get_saved_wallets(), fp)
        if saved:
            self.wallet_name_input.setText(saved.get("name", ""))
            self.count_input.setText(str(saved.get("addresses_per_standard", DEFAULT_ADDR_COUNT)))
            self.account_input.setText(str(saved.get("account", DEFAULT_ACCOUNT)))

        if not self.wallet_name_input.text().strip():
            QMessageBox.warning(self, "Ошибка", "Введите имя кошелька.")
            return

        params = self._validate_inputs()
        if params is None:
            return
        count, account = params

        self.console.clear()

        self.log("╔══════════════════════════════════════════════╗")
        self.log("║   Восстановление кошелька из мнемоники       ║")
        self.log("╚══════════════════════════════════════════════╝")
        self.log("")
        self.log("Шаг 1 · Проверка мнемонической фразы (BIP39)")
        self.log("─────────────────────────────────────────────")
        self.log(f"  Фраза: {len(words.split())} слов, контрольная сумма совпала.")
        self.log("  Одна мнемоника → один seed → одни и те же ключи и адреса.")
        if saved:
            self.log(f"  Найден сохранённый кошелёк: «{saved.get('name', '')}»")
        else:
            self.log("  Сохранённый кошелёк не найден — создаётся новый.")
        self.log("")

        self._build_wallet(words, passphrase, count, account, seed=seed)

    def _build_wallet(self, words, passphrase, count, account, seed=None):
        gen = Mnemonic("english")

        self.log("Шаг 2 · Seed (BIP39)")
        self.log("─────────────────────")
        self.log("  PBKDF2-HMAC-SHA512(mnemonic, salt=passphrase, iter=2048) → 512 бит.")
        if passphrase:
            self.log("  BIP39-фраза задана — seed отличается от базового.")
        else:
            self.log("  BIP39-фраза не задана (пустая по умолчанию).")

        if seed is None:
            seed = gen.to_seed(words, passphrase=passphrase)
        fp = fingerprint(seed)
        self.log(f"  Seed: {len(seed)} байт. Отпечаток: {fp}")
        self.log("  Отпечаток — первые 64 бита SHA-256 от seed.")
        self.log("  Короткий идентификатор: совпадает = тот же seed = те же ключи.")
        self.log("")

        self.log("Шаг 3 · Мастер-ключ (BIP32)")
        self.log("────────────────────────────")
        self.log("  HMAC-SHA512(key=«Bitcoin seed», data=seed)")
        self.log("  → 256 бит приватный ключ + 256 бит chain code.")

        root = master(seed)
        self.log("  Мастер-ключ получен.")
        self.log("")

        standards = {
            "BIP44": {
                "base": f"m/44'/0'/{account}'/0/",
                "type": "Legacy P2PKH",
                "prefix": "1",
                "desc": "P2PKH: SHA-256 → RIPEMD-160 → Base58Check.",
            },
            "BIP49": {
                "base": f"m/49'/0'/{account}'/0/",
                "type": "Nested SegWit",
                "prefix": "3",
                "desc": "P2SH-P2WPKH: witness внутри P2SH.",
            },
            "BIP84": {
                "base": f"m/84'/0'/{account}'/0/",
                "type": "Native SegWit",
                "prefix": "bc1",
                "desc": "bech32: нативный SegWit.",
            },
        }

        self.log("Шаг 4 · Деривация адресов")
        self.log("─────────────────────────")
        self.log(f"  Аккаунт: {account}, адресов: {count}")
        self.log("")

        addresses = {}
        self._private_key_map = {}
        self._all_addresses = []

        for standard, config in standards.items():
            self.log(f"  ┌── {standard} ({config['type']}) ──")
            self.log(f"    {config['desc']}")
            derived = []
            for idx in range(count):
                path = f"{config['base']}{idx}"
                node = derive_path(root, path)
                cpub = compress(node.pub)
                if standard == "BIP44":
                    addr = p2pkh(cpub)
                elif standard == "BIP49":
                    addr = p2sh(cpub)
                else:
                    addr = bech32_addr(cpub)

                derived.append({
                    "index": idx,
                    "path": path,
                    "address": addr,
                    "private_key_hex": node.k.hex(),
                })
                self._private_key_map[addr] = node.k.hex()
                self._all_addresses.append(addr)
                self.log(f"    {path}  →  {addr}")

            addresses[standard] = {"label": config["type"], "items": derived}
            self.log(f"  └── {count} адресов")
            self.log("")

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = count * len(standards)
        self.log("═══════════════════════════════════════════")
        self.log(f"  Кошелёк готов. {total} адресов.")
        self.log("═══════════════════════════════════════════")

        self.wallet_data = {
            "created_at": created_at,
            "mnemonic": words,
            "word_count": len(words.split()),
            "passphrase_used": bool(passphrase),
            "seed_hex": seed.hex(),
            "seed_fingerprint": fp,
            "account": account,
            "addresses_per_standard": count,
            "addresses": addresses,
        }

        self.toggle_keys_button.setEnabled(True)
        self.fund_btn.setEnabled(True)
        self.send_btn.setEnabled(True)

        self._update_all()

        display_name = self.wallet_name_input.text().strip() or f"Кошелёк {self.slot}"
        self.wallet_title_label.setText(display_name)

        wallet_info = {
            "name": display_name,
            "mnemonic": words,
            "word_count": len(words.split()),
            "passphrase": passphrase,
            "account": account,
            "addresses_per_standard": count,
            "seed_fingerprint": fp,
            "created_at": created_at,
        }
        if self._on_wallet_saved:
            self._on_wallet_saved(wallet_info)
        if self._on_name_change:
            self._on_name_change(self.slot, display_name)

    # ── Transactions ──

    def _do_fund(self):
        addr = self.fund_combo.currentData()
        if not addr:
            QMessageBox.warning(self, "Ошибка", "Сначала создайте кошелёк.")
            return
        try:
            amount = float(self.fund_amount.text().strip())
            if amount <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Введите корректную сумму > 0.")
            return

        self.log("")
        self.log("── Coinbase-транзакция ──")
        self.log("  Inputs:  нет (coinbase — средства из награды за блок)")
        self.log("  Outputs:")
        self.log(f"    [0] → {addr}")
        self.log(f"         {amount:.8f} BTC")
        self.log("  Комиссия: 0")

        tx = self.ledger.fund(addr, amount)

        self.log(f"  txid: {tx['txid']}")
        self.log(f"  Баланс адреса: {self.ledger.get_balance(addr):.8f} BTC")
        self.log("")
        self.fund_amount.clear()

    def _do_send(self):
        from_addr = self.send_from_combo.currentData()
        to_addr = self.send_to_input.text().strip()
        if not from_addr:
            QMessageBox.warning(self, "Ошибка", "Выберите адрес отправителя.")
            return
        if not to_addr:
            QMessageBox.warning(self, "Ошибка", "Введите адрес получателя.")
            return

        valid, addr_info = validate_address(to_addr)
        if not valid:
            QMessageBox.warning(
                self, "Невалидный адрес",
                f"Адрес получателя не прошёл проверку.\n{addr_info}",
            )
            return

        try:
            amount = float(self.send_amount.text().strip())
            if amount <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Введите корректную сумму > 0.")
            return

        try:
            fee_rate = int(self.fee_rate_input.text().strip() or DEFAULT_FEE_RATE)
            if fee_rate <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Ставка комиссии — целое число > 0.")
            return

        priv_hex = self._private_key_map.get(from_addr)
        if not priv_hex:
            QMessageBox.warning(self, "Ошибка", "Приватный ключ отправителя не найден.")
            return

        fee_btc, fee_sats, vbytes = calc_fee(from_addr, fee_rate)
        atype, atype_label, _ = addr_fee_info(from_addr)
        bal_before = self.ledger.get_balance(from_addr)
        total_needed = amount + fee_btc

        if bal_before < total_needed:
            QMessageBox.warning(
                self, "Ошибка",
                f"Недостаточно средств.\n"
                f"Баланс: {bal_before:.8f} BTC\n"
                f"Нужно: {amount:.8f} + {fee_btc:.8f} = {total_needed:.8f} BTC",
            )
            return

        change = bal_before - total_needed

        self.log("")
        self.log("╔═══════════════════════════════════════╗")
        self.log("║         Перевод средств               ║")
        self.log("╚═══════════════════════════════════════╝")
        self.log("")

        self.log("Шаг 1 · Формирование транзакции")
        self.log("───────────────────────────────")
        self.log(f"  Адрес получателя валиден: {addr_info}")
        self.log(f"  Тип адреса отправителя: {atype} — {atype_label}")
        self.log(f"  Размер: ~{vbytes} vbyte × {fee_rate} sat/vbyte = {fee_sats} sat")
        self.log(f"  Комиссия: {fee_btc:.8f} BTC")
        self.log("")
        self.log("  Inputs (входы):")
        self.log(f"    [0] {from_addr}")
        self.log(f"        UTXO: {bal_before:.8f} BTC")
        self.log("")
        self.log("  Outputs (выходы):")
        self.log(f"    [0] → {to_addr}")
        self.log(f"         {amount:.8f} BTC (получатель)")
        if change > 1e-12:
            self.log(f"    [1] → {from_addr}")
            self.log(f"         {change:.8f} BTC (сдача)")
        self.log("")
        self.log(f"  Комиссия = sum(inputs) − sum(outputs) = {fee_btc:.8f} BTC")
        self.log("")

        tx_message = f"{from_addr}:{to_addr}:{amount:.8f}:{fee_btc:.8f}:{datetime.now().isoformat()}".encode()
        tx_hash = sha256(tx_message)

        self.log("Шаг 2 · ECDSA-подпись (secp256k1)")
        self.log("──────────────────────────────────")
        self.log(f"  SHA-256 транзакции: {tx_hash.hex()}")
        self.log("  Подпись (r, s) по RFC 6979 — детерминированный nonce.")

        sk = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
        signature = sk.sign_deterministic(tx_hash)

        self.log(f"  Подпись: {signature.hex()[:48]}...")
        self.log("")

        self.log("Шаг 3 · Верификация")
        self.log("────────────────────")
        vk = sk.verifying_key
        pub_hex = vk.to_string().hex()
        self.log(f"  Публичный ключ: {pub_hex[:32]}...")

        try:
            vk.verify(signature, tx_hash)
            self.log("  Подпись валидна.")
        except Exception:
            self.log("  ОШИБКА: подпись невалидна!")
            return
        self.log("")

        self.log("Шаг 4 · Обновление балансов")
        self.log("───────────────────────────")

        try:
            tx = self.ledger.transfer(
                from_addr, to_addr, amount, fee_btc, signature.hex(), pub_hex,
            )
        except ValueError as e:
            self.log(f"  ОШИБКА: {e}")
            return

        self.log(f"  Отправитель: {bal_before:.8f} → {self.ledger.get_balance(from_addr):.8f} BTC")
        self.log(f"  Получатель:  → {self.ledger.get_balance(to_addr):.8f} BTC")
        self.log(f"  Комиссия:    {fee_btc:.8f} BTC (сожжена)")
        self.log(f"  txid: {tx['txid']}")
        self.log("")

        self.send_amount.clear()
        self.send_to_input.clear()

    # ── UI refresh ──

    def refresh_balances(self):
        if not self.wallet_data:
            return
        for std, table in self.address_tables.items():
            items = self.wallet_data["addresses"][std]["items"]
            for row, it in enumerate(items):
                bal = self.ledger.get_balance(it["address"])
                table.setItem(row, 3, QTableWidgetItem(f"{bal:.8f}"))
        self._populate_combos()
        self._update_tx_table()
        self._update_overview()
        self._update_inspector()

    def _update_all(self):
        self._update_tables()
        self._populate_combos()
        self._update_tx_table()
        self._update_overview()
        self._update_inspector()

    def _update_overview(self):
        if not self.wallet_data:
            return
        total_bal = self.ledger.total_balance(self._all_addresses)

        std_bals = []
        for std, cfg in self.wallet_data["addresses"].items():
            addrs = [it["address"] for it in cfg["items"]]
            bal = self.ledger.total_balance(addrs)
            std_bals.append(f"  {std} ({cfg['label']}): {bal:.8f} BTC")

        first_addrs = []
        for std, cfg in self.wallet_data["addresses"].items():
            first_addrs.append(f"  {std}: {cfg['items'][0]['address']}")

        lines = [
            f"Общий баланс: {total_bal:.8f} BTC",
            "",
            f"Создан: {self.wallet_data['created_at']}",
            f"Слов: {self.wallet_data['word_count']}",
            f"BIP39-фраза: {'да' if self.wallet_data['passphrase_used'] else 'нет'}",
            f"Аккаунт: {self.wallet_data['account']}",
            f"Отпечаток seed: {self.wallet_data['seed_fingerprint']}",
            "",
            "Балансы по стандартам:",
            *std_bals,
            "",
            "Первые адреса:",
            *first_addrs,
        ]
        self.wallet_summary.setPlainText("\n".join(lines))

    def _update_tables(self):
        for std, table in self.address_tables.items():
            items = self.wallet_data["addresses"][std]["items"]
            table.setRowCount(len(items))
            for row, it in enumerate(items):
                table.setItem(row, 0, QTableWidgetItem(str(it["index"])))
                table.setItem(row, 1, QTableWidgetItem(it["path"]))
                table.setItem(row, 2, QTableWidgetItem(it["address"]))
                bal = self.ledger.get_balance(it["address"])
                table.setItem(row, 3, QTableWidgetItem(f"{bal:.8f}"))
                table.setItem(row, 4, QTableWidgetItem(it["private_key_hex"]))
            table.resizeColumnsToContents()

    def _populate_combos(self):
        fund_cur = self.fund_combo.currentData()
        send_cur = self.send_from_combo.currentData()

        self.fund_combo.clear()
        self.send_from_combo.clear()

        for addr in self._all_addresses:
            bal = self.ledger.get_balance(addr)
            label = f"{addr[:8]}…{addr[-4:]}  ({bal:.8f})"
            self.fund_combo.addItem(label, addr)
            self.send_from_combo.addItem(label, addr)

        if fund_cur:
            idx = self.fund_combo.findData(fund_cur)
            if idx >= 0:
                self.fund_combo.setCurrentIndex(idx)
        if send_cur:
            idx = self.send_from_combo.findData(send_cur)
            if idx >= 0:
                self.send_from_combo.setCurrentIndex(idx)

    def _update_tx_table(self):
        txs = list(reversed(self.ledger.history))
        self.tx_table.setRowCount(len(txs))
        for row, tx in enumerate(txs):
            txid = tx.get("txid", "")[:10] + "…"
            self.tx_table.setItem(row, 0, QTableWidgetItem(txid))
            self.tx_table.setItem(row, 1, QTableWidgetItem(tx["time"]))
            if tx["inputs"]:
                src = tx["inputs"][0]["address"][:10] + "…"
            else:
                src = "Coinbase"
            dst = tx["outputs"][0]["address"][:10] + "…"
            self.tx_table.setItem(row, 2, QTableWidgetItem(src))
            self.tx_table.setItem(row, 3, QTableWidgetItem(dst))
            self.tx_table.setItem(row, 4, QTableWidgetItem(f"{tx['amount']:.8f}"))
            fee = tx.get("fee", 0.0)
            self.tx_table.setItem(row, 5, QTableWidgetItem(f"{fee:.8f}" if fee else "—"))
        self.tx_table.resizeColumnsToContents()

    def _update_inspector(self):
        data = dict(self.wallet_data)
        if self._all_addresses:
            data["balances"] = {a: self.ledger.get_balance(a) for a in self._all_addresses}
            data["total_balance"] = self.ledger.total_balance(self._all_addresses)
        data["transactions"] = self.ledger.history
        self.inspector.setPlainText(json.dumps(data, indent=2, ensure_ascii=False))

    # ── Misc actions ──

    def _toggle_private_keys(self):
        self._private_keys_visible = not self._private_keys_visible
        for table in self.address_tables.values():
            table.setColumnHidden(4, not self._private_keys_visible)
            if self._private_keys_visible:
                table.resizeColumnsToContents()
        self.toggle_keys_button.setText(
            "Скрыть ключи" if self._private_keys_visible else "Приватные ключи"
        )

    def _copy_address_from_table(self, row, _col):
        table = self.sender()
        if table is None:
            return
        item = table.item(row, 2)
        if item:
            QApplication.clipboard().setText(item.text())
