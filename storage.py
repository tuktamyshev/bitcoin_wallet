import json
import os

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.json")

_EMPTY = {"wallets": [], "ledger": {"balances": {}, "history": []}}


def load_data():
    if not os.path.exists(DATA_FILE):
        return dict(_EMPTY)
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return dict(_EMPTY)


def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def find_wallet_by_fingerprint(wallets, fp):
    for w in wallets:
        if w.get("seed_fingerprint") == fp:
            return w
    return None


def upsert_wallet(data, wallet_info):
    fp = wallet_info["seed_fingerprint"]
    wallets = data.setdefault("wallets", [])
    for i, w in enumerate(wallets):
        if w.get("seed_fingerprint") == fp:
            wallets[i] = wallet_info
            return
    wallets.append(wallet_info)
