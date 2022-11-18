import base64
import struct
import requests
from crc16 import crc16xmodem
from stellar_sdk import stellar_xdr, Server, Network, Asset,  Keypair, SignerKey, SignerKeyType, TransactionBuilder
from utils import eddsa_sign


"""
Set the variables `NETWORK_PASSPHRASE`, `RPC_URL`, and `EXPLORER_URL` for the appropriate chain.
"""

# Network passphrase
XLM_LIVENET_PASSPHRASE = Network.PUBLIC_NETWORK_PASSPHRASE
XLM_TESTNET_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE
XDB_LIVENET_PASSPHRASE = 'LiveNet Global DigitalBits Network ; February 2021'
XDB_TESTNET_PASSPHRASE = 'TestNet Global DigitalBits Network ; December 2020'
NETWORK_PASSPHRASE = XLM_LIVENET_PASSPHRASE

# RPC URL
XLM_LIVENET_RPC_URL = 'https://horizon.stellar.org'
XLM_TESTNET_RPC_URL = 'https://horizon-testnet.stellar.org'
XDB_LIVENET_RPC_URL = 'https://frontier.livenet.digitalbits.io'
XDB_TESTNET_RPC_URL = 'https://frontier.testnet.digitalbits.io'
RPC_URL = XLM_LIVENET_RPC_URL

# Explorer URL
XLM_EXPLORER_URL = 'https://stellarchain.io/transactions'
XDB_EXPLORER_URL = 'https://xdbexplorer.com/transaction'
EXPLORER_URL = XLM_EXPLORER_URL


class RawKeypair(Keypair):
    def __init__(self, signing_key) -> None:
        self.signing_key = signing_key
        self.verify_key = eddsa_sign.private_key_to_public_key(signing_key)

    def xdr_signing_key(self) -> SignerKey:
        return SignerKey(self.signing_key, SignerKeyType.SIGNER_KEY_TYPE_ED25519)

    def xdr_public_key(self) -> stellar_xdr.PublicKey:
        return stellar_xdr.PublicKey(SignerKeyType.SIGNER_KEY_TYPE_ED25519, self.verify_key)

    def raw_public_key(self) -> bytes:
        return self.verify_key

    def signature_hint(self) -> bytes:
        return bytes(self.xdr_public_key().ed25519[-4:])

    def sign(self, data: bytes) -> bytes:
        return eddsa_sign.eddsa_sign(self.signing_key, data)


def withdraw(key, to_address, amount=None, dst_tag=None):
    server = Server(horizon_url=RPC_URL)

    keypair = RawKeypair(key)

    builder = TransactionBuilder(
        source_account=server.load_account(keypair),
        network_passphrase=NETWORK_PASSPHRASE,
        base_fee=100
    )

    if amount is None:
        builder.append_account_merge_op(to_address)
    else:
        builder.append_payment_op(
            to_address, Asset.native(), str(round(float(amount), 7)))

    if dst_tag is not None:
        builder.add_text_memo(dst_tag)

    tx = builder.build()

    tx.sign(keypair)

    res = server.submit_transaction(tx)

    if res['successful']:
        print(f"{EXPLORER_URL}/{res['hash']}")
        return res['hash']
    print(res)


def get_balance(addr):
    url = f'{RPC_URL}/accounts/{addr}'

    res = requests.get(url)

    if res.status_code == 404:
        raise Exception('Account not found')

    account = res.json()

    balance = 0

    for b in account['balances']:
        if b['asset_type'] == 'native':
            balance = float(b['balance'])
            break

    return balance


def public_key_to_address(public_key: bytes) -> str:
    if public_key is None:
        raise ValueError("cannot encode null public_key")

    version_byte = b'0'
    payload = version_byte + public_key
    unpacked_crc = crc16xmodem(payload)
    crc = struct.pack("<H", unpacked_crc)
    addr = base64.b32encode(payload + crc).decode("utf-8").rstrip("=")
    return addr


def get_derivation_path(account: int) -> str:
    return f'44/146/{account}/0/0'


def xpub_to_address(xdb_pub: str, account: int) -> str:
    path = get_derivation_path(account)
    _, pub = eddsa_sign.eddsa_derive(xdb_pub, path)
    return public_key_to_address(pub)


def withdraw_from_account(xpriv: str, account: int, to_address: str, amount: float = None, dst_tag: str = None) -> str:
    path = get_derivation_path(account)
    priv, _ = eddsa_sign.eddsa_derive(xpriv, path)
    return withdraw(priv, to_address, amount, dst_tag)
