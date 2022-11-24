import base64
import hashlib
import json
import math
from datetime import datetime
from pprint import pprint

from Crypto import Random
from Crypto.Hash import RIPEMD160, keccak
import requests

from utils import eddsa_sign, ed25519
from utils.eddsa_sign import _ed25519_serialize

MAINNET_NETWORK_ID = 104
TESTNET_NETWORK_ID = -104
MIJIN_NETWORK_ID = 96

XEM_NEM_DECIMALS = 1000000
FEE_FACTOR = 0.05

BIP_44_CONSTANT = 44
XLM_ASSET_NUM = 43
CHANGE = 0
ADDR_INDEX = 0

URL = None  # Change to the URL of the REST NEM Server


def create_timestamp() -> int:
    """
    Gets the current time in a timestamp format.
    NEM doesn't use epoch, but instead the below specified timestamp.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/utils/helpers.js#L107

    Returns:
        an int representing the timestamp.
    """
    return math.floor(datetime.now().timestamp() - 1427587585)  # NEM Timestamp


def get_version(network: int) -> int:
    """
    Calculates the version according to the network id.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/network.js#L83

    Args:
        network: the network id.

    Returns:
        an int for the version
    """
    if network == MAINNET_NETWORK_ID:
        return 0x68000000 | 1
    elif network == TESTNET_NETWORK_ID:
        return 0x98000000 | 1

    return 0x60000000 | 1


def calc_minimal_fee(amount) -> int:
    """
    Calculates the fee to use for a transaction based off the amount of the tx.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/fees.js#L150
    Args:
        amount: the amount of the transaction

    Returns:
        a minimal fee to use
    """
    nominal_fee = math.floor(max(1, amount / 10000))
    return nominal_fee if nominal_fee <= 25 else 25


def create_tx(to: str = None, amount: float = -1, msg: str = None):
    """
    Creates a basic tx object
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/objects/transactions.js#L10

    Args:
        to: to who should the tx be
        amount: the amount of the tx
        msg: the message to put in the tx

    Returns:
        an object containing the above labeled.
    """
    return {
        "amount": amount if amount > 0 else 0,
        "recipient": to if to is not None else "",
        "recipientPublicKey": "",
        "message": msg if msg is not None else "",
        "messageType": 1,
    }


def generate_message_object(msg):
    """
    Converts a message to the relevant object.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/transactions/message.js#L31
    Args:
        msg: the message to convert.

    Returns:
        An object representing the message, the payload is the hex of the message.

    """
    return {
        'type': 1,
        'payload': ''.join([hex(ord(x))[2:] for x in msg])
    }


def construct_tx(sender: str, receiver: str, amount: float, msg: any, msg_fee: int, due: int, network: int):
    """
    Given some data for the transaction, construct the transaction object.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/transactions/transferTransaction.js#L80

    Args:
        sender: the public key (hex) of the sender
        receiver: the address (not public key) of the receiver
        amount: the amount to send
        msg: the message
        msg_fee: the fee calculated for the message (not the transaction itself)
        due: until when should this transaction pass
        network: the network to send this transaction on

    Returns:
        A constructed transaction object.

    """
    ts = create_timestamp()
    version = get_version(network)
    data = create_common_tx(257, version, sender, ts, due)
    fee = FEE_FACTOR * calc_minimal_fee(amount / XEM_NEM_DECIMALS)
    total_fee = math.floor((msg_fee + fee) * XEM_NEM_DECIMALS)
    data_keys = data.keys()
    if 'recipient' not in data_keys:
        data['recipient'] = receiver.upper().replace('-', '')
    if 'amount' not in data_keys:
        data['amount'] = amount
    if 'fee' not in data_keys:
        data['fee'] = total_fee
    if 'message' not in data_keys:
        data['message'] = msg

    return data


def prepare_tx(common: any, tx: any, network: int):
    """
    Given a transaction and several other inputs, prepare the transaction by calculating some values and running
    the construct_tx function.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/transactions/transferTransaction.js#L19

    Args:
        common: a "common" object, see create_common
        tx: an unprepared tx object, see create_tx
        network: the network this transaction will be sent on

    Returns:
        A prepared transaction
    """
    sender = common['publicKey']
    receiver = tx['recipient']
    amount = tx['amount'] * XEM_NEM_DECIMALS
    msg = generate_message_object(tx['message'])
    msg_fee = FEE_FACTOR * (math.floor((len(msg['payload']) / 2) / 32) + 1) if (
            msg['payload'] and len(msg['payload']) > 0) else 0
    due = 60 if network == TESTNET_NETWORK_ID else 24 * 60

    return construct_tx(sender, receiver, amount, msg, msg_fee, due, network)


def create_common_tx(tx_type: int = None, version: int = None, sender_pubkey: str = None, ts: int = None,
                     due_in_seconds: int = None):
    """
    Create the common part of a transaction, this is a basic structure for transaction onto which more details
    are added as part of the tx construction.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/objects/transactions.js#L147

    Args:
        tx_type: the type of the transaction, always 257 in this scenario (all types: https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/transactionTypes.js)
        version: the version, see get_version
        sender_pubkey: the sender's public key (hex)
        ts: the timestamp at which this transaction is created
        due_in_seconds: deadline for transaction execution.

    Returns:
        a common tx object with the above labeled.
    """
    return {
        'type': tx_type if tx_type is not None else "",
        'version': version if version is not None else "",
        'signer': sender_pubkey if sender_pubkey is not None else "",
        'timeStamp': ts if ts is not None else "",
        'deadline': (int(ts) + (int(due_in_seconds) * 60)) if (ts is not None and due_in_seconds is not None) else ""
    }


def create_common(prv_key, pub_key, addr):
    """
    A common object, containing all the wallet information (address and keypair).
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/objects/miscellaneous.js#L25

    Args:
        prv_key: private key
        pub_key: public key
        addr: the address

    Returns:
        A common object with the above labeled
    """
    return {
        "privateKey": prv_key,
        "publicKey": pub_key,
        "address": addr
    }


def id_to_prefix(network_id: int) -> int:
    """
    Given a network id, get the number corresponding to that id.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/network.js#L31

    Args:
        network_id: the network id.

    Returns:
        A number for the id.
    """
    if network_id == MAINNET_NETWORK_ID:
        return 68
    elif network_id == TESTNET_NETWORK_ID:
        return 98
    else:
        return 60


def serialize_tx(tx):
    """
    Given a constructed transaction object, serialize it.
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/utils/serialization.js#L278 (only transfer)

    Args:
        tx: the unprepared tx object

    Returns:
        bytes with the tx serialized.
    """

    # NEM SDK uses a trick with 8bit and 32bit buffers onto a shared array and plays with the indexes.
    # Since there's no strong distinction between 32bit and 8bit numbers in python (other than using bytes or unpack)
    # We build everything as a 32bit number and then convert it to an 8bit list as the response.
    # That's why multiple places use int.from_bytes(bytearray(...)).

    d = [tx['type'], tx['version'], tx['timeStamp']]

    signer_array = [int(tx['signer'][i:i + 2], 16) for i in range(0, len(tx['signer']), 2)]
    d.append(int(len(signer_array)))
    for i in range(0, len(signer_array), 4):
        d.append(int.from_bytes(bytearray(signer_array[i:i + 4]), byteorder='little'))

    d.append(tx['fee'])
    d.append(math.floor((tx['fee'] / 0x100000000)))
    d.append(tx['deadline'])

    d.append(int(len(tx['recipient'])))
    for j in range(0, len(tx['recipient']), 4):
        d.append(int.from_bytes(bytearray([ord(tx['recipient'][i]) for i in range(j, j + 4)]), byteorder='little'))

    d.append(int(tx['amount']))
    d.append(math.floor((tx['amount'] / 0x100000000)))

    payload_array = [int(tx['message']['payload'][i:i + 2], 16) for i in range(0, len(tx['message']['payload']), 2)]
    if len(payload_array) == 0:
        d.append(0)
    else:
        d.append(8 + len(payload_array))
        d.append(tx['message']['type'])
        d.append(int(len(payload_array)))
        for j in range(0, len(payload_array), 4):
            d.append(int.from_bytes(bytearray(payload_array[j:j + 4]), byteorder='little'))

    # convert to 8bit array
    res = bytearray()
    for i in range(0, len(d)):
        res.extend(d[i].to_bytes(4, byteorder='little'))

    return res


def withdraw(prv: str, pub: str, to_address: str, amount: float, network: int, message: str):
    """
    Withdraw assets from a give private-public key pair
    Args:
        prv: private key (hex)
        pub: public key (hex)
        to_address: the recipient
        amount: the amount
        network: the network to send the tx on
        message: the message to include

    Returns:
        a JSON response from the REST node.
    """
    prepared_tx = prepare_tx(
        create_common(prv, pub, public_key_to_address(bytes.fromhex(pub), network)),
        create_tx(to_address, amount, message),
        network
    )
    pprint(prepared_tx)
    serialized_tx = serialize_tx(prepared_tx)
    sig = nem_sign(int(prv, 16), serialized_tx)
    tx = {
        'data': serialized_tx.hex(),
        'signature': sig.hex()
    }

    res = requests.post(
        url=f"{URL}/transaction/announce",
        json=tx,
    )

    return res.json()


def nem_sign(private_key, message):
    """
    NEM uses EDDSA but the hash function they use is CryptoJS's SHA3 with 512 digest bits.
    https://github.com/brix/crypto-js/issues/92

    So in order to resolve it, we simply copy the eddsa_sign and alter the hash function used to keccak.
    """
    if type(message) == str:
        message = message.encode('utf-8')
    privkey = private_key
    if type(private_key) != int:
        privkey = int.from_bytes(private_key, byteorder='big')
    seed = Random.get_random_bytes(32)
    sha = keccak.new(digest_bits=512)
    sha.update(seed)
    sha.update(privkey.to_bytes(32, byteorder="little"))
    sha.update(message)
    nonce = int.from_bytes(sha.digest(), byteorder="little") % ed25519.l
    R = ed25519.scalarmult(ed25519.B, nonce)
    A = ed25519.scalarmult(ed25519.B, privkey)
    sha = keccak.new(digest_bits=512)
    sha.update(_ed25519_serialize(R))
    sha.update(_ed25519_serialize(A))
    sha.update(message)
    hram = int.from_bytes(sha.digest(), byteorder='little') % ed25519.l
    s = (hram * privkey + nonce) % ed25519.l
    return _ed25519_serialize(R) + s.to_bytes(32, byteorder="little")


def public_key_to_address(pub: bytes, network_id: int) -> str:
    """
    Converts a public key to an address
    Matches - https://github.com/QuantumMechanics/NEM-sdk/blob/master/src/model/address.js#L83

    Args:
        pub: the public key in bytes
        network_id: the network id we want to get the address from (testnet, mainnet, etc)

    Returns:
        a string of the address.
    """
    first_hash = keccak.new(digest_bits=256)
    first_hash.update(pub)
    first_hash = first_hash.digest()
    second_hash = RIPEMD160.new(first_hash).hexdigest()
    complete_second_hash = str(id_to_prefix(network_id)) + second_hash
    checksum_hash = keccak.new(digest_bits=256)
    checksum_hash.update(bytearray.fromhex(complete_second_hash))
    checksum = checksum_hash.hexdigest()[0:8]
    print(complete_second_hash + checksum)
    return base64.b32encode(bytearray.fromhex(complete_second_hash + checksum)).decode('utf-8')


def xpub_to_address(fpub: str, account: int, network: int) -> str:
    """
    Given a fprv, get the address
    Args:
        fpub: the fpub
        account: the account for the derivation path
        network: the network to get the address for

    Returns:
        a string of the address

    """
    path = f'44/43/{account}/0/0'
    _, pub = eddsa_sign.eddsa_derive(fpub, path)
    return public_key_to_address(pub, network)


def withdraw_from_account(fprv: str, account: int, to_address: str, amount: float = None, memo: str = None,
                          network_id: int = MAINNET_NETWORK_ID) -> str:
    """
    Withdraw assets from a specific account.
    Args:
        fprv: the fprv
        account: the account to use for the derivation path
        to_address: the recipient
        amount: the amount to send
        memo: the message to put
        network_id: the network id to use

    Returns:
        the json response from the rest server
    """
    path = f'{BIP_44_CONSTANT}/{XLM_ASSET_NUM}/{account}/{CHANGE}/{ADDR_INDEX}'
    prv, pub = eddsa_sign.eddsa_derive(fprv, path)
    prv_hex = hex(prv)[2:]
    pub_hex = pub.hex()
    return withdraw(prv_hex, pub_hex, to_address, amount, network_id, memo)
