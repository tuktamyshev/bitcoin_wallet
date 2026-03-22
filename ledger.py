from datetime import datetime

from crypto import compute_txid


class Ledger:
    def __init__(self):
        self.balances = {}
        self.history = []
        self._listeners = []

    def add_listener(self, fn):
        self._listeners.append(fn)

    def _notify(self):
        for fn in self._listeners:
            fn()

    def get_balance(self, addr):
        return self.balances.get(addr, 0.0)

    def total_balance(self, addresses):
        return sum(self.get_balance(a) for a in addresses)

    def fund(self, addr, amount):
        self.balances[addr] = self.get_balance(addr) + amount
        tx = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "coinbase",
            "inputs": [],
            "outputs": [{"address": addr, "value": amount}],
            "amount": amount,
            "fee": 0.0,
        }
        tx["txid"] = compute_txid(tx)
        self.history.append(tx)
        self._notify()
        return tx

    def transfer(self, from_addr, to_addr, amount, fee, signature_hex, pub_key_hex):
        bal = self.get_balance(from_addr)
        total = amount + fee
        if amount <= 0:
            raise ValueError("Сумма должна быть больше нуля")
        if bal < total:
            raise ValueError(f"Недостаточно средств: {bal:.8f} < {total:.8f}")
        change = bal - total
        self.balances[from_addr] = change
        self.balances[to_addr] = self.get_balance(to_addr) + amount

        outputs = [{"address": to_addr, "value": amount}]
        if change > 0:
            outputs.append({"address": from_addr, "value": change})

        tx = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "transfer",
            "inputs": [{"address": from_addr, "value": bal}],
            "outputs": outputs,
            "amount": amount,
            "fee": fee,
            "signature": signature_hex,
            "pubkey": pub_key_hex,
        }
        tx["txid"] = compute_txid(tx)
        self.history.append(tx)
        self._notify()
        return tx
