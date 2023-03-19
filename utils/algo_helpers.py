from algosdk.v2client import algod
from algosdk import encoding
from algosdk import constants
from algosdk.future.transaction import PaymentTxn, SignedTransaction, AssetTransferTxn
import base64
from utils import eddsa_sign

BIP_44_CONSTANT = 44
ALGO_ASSET_NUM = 283
CHANGE = 0
ADDR_INDEX = 0

# change the following settings to your Algorand node's URL and its token
# these settings work with the Algorand Sandbox: https://github.com/algorand/sandbox
algod_address = "http://localhost:4001"
algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
algod_client = algod.AlgodClient(algod_token, algod_address)


def withdraw(priv, pub, to_address, amount, asset_id: int, decimals: int):
    from_address = public_key_to_address(pub)

    params = algod_client.suggested_params()
    # remove the next 2 lines to use suggested fees
    params.flat_fee = True
    params.fee = 1000

    note = None  # optional note e.g. note = "TXID".encode()
    if asset_id:
        unsigned_txn = AssetTransferTxn(from_address, params, to_address, int(amount * decimals), asset_id, None, note)
    else:
        unsigned_txn = PaymentTxn(from_address, params, to_address, int(amount * 1e6), None, note)

    txn = encoding.msgpack_encode(unsigned_txn)
    to_sign = constants.txid_prefix + base64.b64decode(txn)
    sig = eddsa_sign.eddsa_sign(priv, to_sign)
    sig = base64.b64encode(sig).decode()
    signed_txn = SignedTransaction(unsigned_txn, sig)
    tx_id = algod_client.send_transaction(signed_txn)

    print("Sent transaction with txID: {}".format(tx_id))

    return tx_id


def get_balance(addr):
    account_info = algod_client.account_info(addr)
    if account_info is None: return 0
    return account_info.get('amount') / 1e6


def public_key_to_address(public_key: bytes) -> str:
    return encoding.encode_address(public_key)


def xpub_to_address(xpub: str, account: int) -> str:
    path = f'{BIP_44_CONSTANT}/{ALGO_ASSET_NUM}/{account}/{CHANGE}/{ADDR_INDEX}'
    _, pub = eddsa_sign.eddsa_derive(xpub, path)
    return public_key_to_address(pub)


def withdraw_from_account(fprv: str, account: int, to_address: str, amount: float, asset_id: int = 0,
                          decimals: int = 1e6) -> str:
    """
    :param fprv: Your extracted FPRV.
    :param account: Your vault Id.
    :param to_address: Assets receiver.
    :param amount: Amount of assets to send. Int for tokens.
    :param asset_id: (Optional) Your asset Id. For example, 31566704 for USDC.
    :param decimals: (Optional) Decimals of your asset. For example, 1e6 for USDC.
    :return:
    """
    path = f'{BIP_44_CONSTANT}/{ALGO_ASSET_NUM}/{account}/{CHANGE}/{ADDR_INDEX}'
    priv, pub = eddsa_sign.eddsa_derive(fprv, path)
    return withdraw(priv, pub, to_address, amount, asset_id, decimals)
