import base64
import struct
from stellar_base.builder import Builder
from stellar_base.address import Address
from stellar_base.stellarxdr import Xdr
from stellar_base.keypair import Keypair
from crc16 import crc16xmodem

from utils import eddsa_sign

class RawKeypair(Keypair):
    def __init__(self, signing_key) -> None:
        self.signing_key = signing_key
        self.verify_key = eddsa_sign.private_key_to_public_key(signing_key)
    
    def xdr_public_key(self) -> Xdr.types.PublicKey:
        return Xdr.types.PublicKey(Xdr.const.KEY_TYPE_ED25519, self.verify_key)

    def raw_public_key(self) -> bytes:
        return self.verify_key

    def signature_hint(self) -> bytes:
        return bytes(self.xdr_public_key().ed25519[-4:])

    def sign(self, data: bytes) -> bytes:
        return eddsa_sign.eddsa_sign(self.signing_key, data)

def withdraw(key, to_address, amount = None, dst_tag = None):
    keypair = RawKeypair(key)
    builder = Builder(address=public_key_to_address(keypair.raw_public_key()), network='PUBLIC')

    if amount is None:
        builder.append_account_merge_op(to_address)
    else:
        builder.append_payment_op(to_address, str(round(float(amount),7)), 'XLM')
    if not dst_tag is None:
        builder.add_text_memo(dst_tag) 
    builder.keypair = keypair
    builder.sign()
    ret = builder.submit()
    if ret['successful']:
        return ret['hash']
    print(ret)
    return None

def getBalance(addr):
    address = Address(address=addr, network='PUBLIC')
    address.get()
    balance = 0
    for b in address.balances:
        if b['asset_type'] == 'native':
            balance = float(b['balance'])
            break
    return balance

def public_key_to_address(public_key: bytes) -> str:
    if public_key is None:
        raise ValueError("cannot encode null public_key")

    version_byte = b'0'
    payload = version_byte + public_key
    crc = struct.pack("<H", crc16xmodem(payload))
    return base64.b32encode(payload + crc).decode("utf-8").rstrip("=")

def xpub_to_address(xpub: str, account: int) -> str:
    path = '44/146/{}/0/0'.format(account)
    _, pub = eddsa_sign.eddsa_derive(xpub, path)
    return public_key_to_address(pub)

def withdraw_from_account(xpriv: str, account: int, to_address : str, amount: float = None, dst_tag: str = None) -> str:
    path = '44/146/{}/0/0'.format(account)
    priv, _ = eddsa_sign.eddsa_derive(xpriv, path)
    return withdraw(priv, to_address, amount, dst_tag)
