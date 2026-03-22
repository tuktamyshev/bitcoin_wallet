import hashlib
import hmac
import json

import base58
from bech32 import bech32_decode, bech32_encode, convertbits
from ecdsa import SECP256k1

HARDENED_OFFSET = 0x80000000
CURVE = SECP256k1
N = CURVE.order

TX_VBYTES = {"P2PKH": 226, "P2SH-P2WPKH": 167, "P2WPKH": 141}


# ─── Hash helpers ───


def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def ripemd160(data):
    return hashlib.new("ripemd160", data).digest()


# ─── Key / address helpers ───


def pubkey(priv_key):
    from ecdsa import SigningKey
    signing_key = SigningKey.from_string(priv_key, curve=CURVE)
    return b"\x04" + signing_key.verifying_key.to_string()


def compress(pub):
    return (b"\x02" if pub[-1] % 2 == 0 else b"\x03") + pub[1:33]


def base58check(prefix, payload):
    data = prefix + payload
    checksum = sha256(sha256(data))[:4]
    return base58.b58encode(data + checksum).decode()


def p2pkh(pub):
    return base58check(b"\x00", ripemd160(sha256(pub)))


def p2sh(pub):
    witness_key_hash = ripemd160(sha256(pub))
    redeem_script = b"\x00\x14" + witness_key_hash
    return base58check(b"\x05", ripemd160(sha256(redeem_script)))


def bech32_addr(pub):
    witness_key_hash = ripemd160(sha256(pub))
    data = [0] + list(convertbits(witness_key_hash, 8, 5))
    return bech32_encode("bc", data)


# ─── BIP32 ───


class Node:
    def __init__(self, key, chain_code):
        self.k = key
        self.c = chain_code

    @property
    def pub(self):
        return pubkey(self.k)


def master(seed):
    payload = hmac_sha512(b"Bitcoin seed", seed)
    return Node(payload[:32], payload[32:])


def derive(node, index):
    if index >= HARDENED_OFFSET:
        data = b"\x00" + node.k + index.to_bytes(4, "big")
    else:
        data = node.pub + index.to_bytes(4, "big")

    payload = hmac_sha512(node.c, data)
    child_key = (int.from_bytes(payload[:32], "big") + int.from_bytes(node.k, "big")) % N
    return Node(child_key.to_bytes(32, "big"), payload[32:])


def derive_path(root, path):
    node = root
    for part in path.split("/")[1:]:
        index = int(part[:-1]) + HARDENED_OFFSET if part.endswith("'") else int(part)
        node = derive(node, index)
    return node


def fingerprint(seed):
    return sha256(seed).hex()[:16].upper()


# ─── Fee helpers ───


def addr_fee_info(addr):
    if addr.startswith("bc1"):
        return "P2WPKH", "Native SegWit (BIP84)", 141
    if addr.startswith("3"):
        return "P2SH-P2WPKH", "Nested SegWit (BIP49)", 167
    return "P2PKH", "Legacy (BIP44)", 226


def calc_fee(addr, fee_rate):
    _, _, vbytes = addr_fee_info(addr)
    sats = vbytes * fee_rate
    return sats / 1e8, sats, vbytes


# ─── Validation ───


def validate_address(addr):
    if not addr:
        return False, "Адрес пустой"
    if addr.startswith("bc1"):
        hrp, data = bech32_decode(addr)
        if hrp == "bc" and data is not None:
            return True, "bech32 (Native SegWit)"
        return False, "Невалидный bech32-адрес: HRP или данные повреждены"
    if addr.startswith("1") or addr.startswith("3"):
        try:
            decoded = base58.b58decode_check(addr)
            if addr.startswith("1") and decoded[0:1] == b"\x00":
                return True, "Base58Check P2PKH (Legacy)"
            if addr.startswith("3") and decoded[0:1] == b"\x05":
                return True, "Base58Check P2SH (Nested SegWit)"
            return False, "Неверный байт версии"
        except Exception:
            return False, "Невалидная контрольная сумма Base58Check"
    return False, "Неизвестный формат адреса"


def compute_txid(tx_dict):
    raw = json.dumps(tx_dict, sort_keys=True, default=str).encode()
    return sha256(sha256(raw)).hex()
