import near_api.signer as signer
import near_api.providers as providers
import near_api.account as account

import utils.eddsa_sign as eddsa_sign
from utils.eddsa_sign import eddsa_derive

import base58

NEAR_TO_YNEAR = 1000000000000000000000000
RPC_URL_NODE = "" # Use your RPC NODE url or the official RPC Node https://docs.near.org/api/rpc/providers

def hex_to_base58(hex_string):
    bytes_str = bytes.fromhex(hex_string)
    base58_str = base58.b58encode(bytes_str)
    return base58_str.decode("UTF-8")


def xpub_to_address(fpub: str, account: int) -> str:
    """
    Returns an address derived from a public key
    Args:
        fpub: the public key
        account: the account for which the path must be derived from

    Returns:
        the address correspondent to the public key

    """
    path = f'44/397/{account}/0/0'
    _, pub = eddsa_derive(fpub, path)
    return pub.hex()


def public_key_to_address(pub: bytes) -> str:
    """
    Converts a public key to an address
    Args:
        pub: the public key in bytes

    Returns:
        the address correspondent to the public key
    """
    return pub.hex()


def withdraw(prv: str, pub: str, to_address: str, amount: float):
    """
    Withdraw assets from a give private-public key pair
    Args:
        prv: private key (hex)
        pub: public key (hex)
        to_address: the destination address to which the funds will be sent to
        amount: the amount to be sent
    Returns:
        the JSON response from the REST node.
    """
    if RPC_URL_NODE == "":
        raise "Please specify RPC url"
    near_provider = providers.JsonProvider(RPC_URL_NODE)

    def custom_sign(message: str):
        return eddsa_sign.eddsa_sign(int.from_bytes(bytes.fromhex(prv), byteorder="big"), message)

    secret_key = hex_to_base58(prv + pub)
    key = "ed25519:" + secret_key
    sender_key_pair = signer.KeyPair(key)
    sender_signer = signer.Signer(pub, sender_key_pair)
    sender_signer.sign = custom_sign
    sender_account = account.Account(near_provider, sender_signer, account_id= pub)
    yocto_near_amount = int(amount * NEAR_TO_YNEAR)
    return sender_account.send_money(to_address, yocto_near_amount)


def withdraw_from_account(fprv: str, account: int, to_address: str, amount: float) -> str:
    """
    Withdraw funds from the account correspondent to the fprv
    Args:
        fprv: the private key
        account: the account in which the funds are stored
        to_address: the destination address to which the funds will be sent to
        amount: the amount of funds to be transferred
    Returns:
        the JSON response from the REST node.
    """
    path = f'44/397/{account}/0/0'
    prv, pub = eddsa_derive(fprv, path)
    prv_hex = hex(prv)
    prv_hex = prv_hex[2:]

    pub_hex = pub.hex()

    if len(prv_hex) % 2 == 1:
        prv_hex = "0" + prv_hex

    return withdraw(prv_hex, pub_hex, to_address, amount)

