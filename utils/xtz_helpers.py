import pysodium
import eddsa_sign
from decimal import Decimal
from pytezos import pytezos
from pyblake2 import blake2b
from pytezos.operation.group import OperationGroup
from base58 import b58encode_check, b58decode_check


BIP_44_CONSTANT = 44
XTZ_ASSET_NUM = 1729
CHANGE = 0
ADDR_INDEX = 0
RPC = "https://rpc.tzbeta.net/"


def traceback(num_list):
    return b''.join(map(lambda num: num.to_bytes(1, 'big'), num_list))


base58_encodings = [
    #    Encoded   |               Decoded             |
    # prefix | len | prefix                      | len | Data type
    (b"B", 51, traceback([1, 52]), 32, u"block hash"),
    (b"o", 51, traceback([5, 116]), 32, u"operation hash"),
    (b"Lo", 52, traceback([133, 233]), 32, u"operation list hash"),
    (b"LLo", 53, traceback([29, 159, 109]), 32, u"operation list list hash"),
    (b"P", 51, traceback([2, 170]), 32, u"protocol hash"),
    (b"Co", 52, traceback([79, 199]), 32, u"context hash"),

    (b"tz1", 36, traceback([6, 161, 159]), 20, u"ed25519 public key hash"),
    (b"tz2", 36, traceback([6, 161, 161]), 20, u"secp256k1 public key hash"),
    (b"tz3", 36, traceback([6, 161, 164]), 20, u"p256 public key hash"),
    (b"KT1", 36, traceback([2, 90, 121]), 20, u"Originated address"),

    (b"id", 30, traceback([153, 103]), 16, u"cryptobox public key hash"),

    (b"edsk", 54, traceback([13, 15, 58, 7]), 32, u"ed25519 seed"),
    (b"edpk", 54, traceback([13, 15, 37, 217]), 32, u"ed25519 public key"),
    (b"spsk", 54, traceback([17, 162, 224, 201]), 32, u"secp256k1 secret key"),
    (b"p2sk", 54, traceback([16, 81, 238, 189]), 32, u"p256 secret key"),

    (b"edesk", 88, traceback([7, 90, 60, 179, 41]), 56, u"ed25519 encrypted seed"),
    (b"spesk", 88, traceback([9, 237, 241, 174, 150]), 56, u"secp256k1 encrypted secret key"),
    (b"p2esk", 88, traceback([9, 48, 57, 115, 171]), 56, u"p256_encrypted_secret_key"),

    (b"sppk", 55, traceback([3, 254, 226, 86]), 33, u"secp256k1 public key"),
    (b"p2pk", 55, traceback([3, 178, 139, 127]), 33, u"p256 public key"),
    (b"SSp", 53, traceback([38, 248, 136]), 33, u"secp256k1 scalar"),
    (b"GSp", 53, traceback([5, 92, 0]), 33, u"secp256k1 element"),

    (b"edsk", 98, traceback([43, 246, 78, 7]), 64, u"ed25519 secret key"),
    (b"edsig", 99, traceback([9, 245, 205, 134, 18]), 64, u"ed25519 signature"),
    (b"spsig", 99, traceback([13, 115, 101, 19, 63]), 64, u"secp256k1 signature"),
    (b"p2sig", 98, traceback([54, 240, 44, 52]), 64, u"p256 signature"),
    (b"sig", 96, traceback([4, 130, 43]), 64, u"generic signature"),

    (b'Net', 15, traceback([87, 82, 0]), 4, u"chain id")
]

validation_passes = {
    'endorsement': 0,
    'proposal': 1,
    'ballot': 1,
    'seed_nonce_revelation': 2,
    'double_endorsement_evidence': 2,
    'double_baking_evidence': 2,
    'activate_account': 2,
    'reveal': 3,
    'transaction': 3,
    'origination': 3,
    'delegation': 3
}


def base58_encode(v: bytes, prfx: bytes) -> bytes:
    try:
        encoding = next(
            encoding
            for encoding in base58_encodings
            if len(v) == encoding[3] and prfx == encoding[0]
        )
    except StopIteration:
        raise ValueError('Invalid encoding, prefix or length mismatch.')

    return b58encode_check(encoding[2] + v)


def base58_decode(v: bytes) -> bytes:
    try:
        prefix_len = next(
            len(encoding[2])
            for encoding in base58_encodings
            if len(v) == encoding[1] and v.startswith(encoding[0])
        )
    except StopIteration:
        raise ValueError('Invalid encoding, prefix or length mismatch.')

    return b58decode_check(v)[prefix_len:]


def get_xtz_pub_key(public_key: bytes) -> bytes:
    return b58encode_check(b'\r\x0f%\xd9' + public_key)


def get_xtz_address(xtz_pub_key: bytes, curve: bytes = b'ed') -> str:
    encoded_key = base58_decode(xtz_pub_key)
    pkh = blake2b(data=encoded_key, digest_size=20).digest()
    prefix = {b'ed': b'tz1', b'sp': b'tz2', b'p2': b'tz3'}[curve]
    return base58_encode(pkh, prefix).decode()


def scrub_input(v) -> bytes:
    if isinstance(v, str) and not isinstance(v, bytes):
        try:
            _ = int(v, 16)
        except ValueError:
            v = v.encode('ascii')
        else:
            if v.startswith('0x'):
                v = v[2:]
            v = bytes.fromhex(v)

    if not isinstance(v, bytes):
        raise TypeError(
            "a bytes-like object is required (also str), not '%s'" %
            type(v).__name__)

    return v


def prepare_tx(derived_prv: str, derived_pub: bytes, xtz_amount: str, xtz_destination: str) -> OperationGroup:
    """

    :param derived_prv:
    :param derived_pub:
    :param xtz_amount:
    :param xtz_destination:
    :return:
    """
    xtz_address = get_xtz_address(derived_pub)
    pytezos - pytezos.using(shell=RPC, key=xtz_address)
    transaction_opg = pytezos.transaction(destination=xtz_destination, amount=Decimal(xtz_amount))
    filled_transaction_opg = transaction_opg.autofill()
    # *** 1. Watermark message ***
    validation_pass = validation_passes[filled_transaction_opg.contents[0]['kind']]
    if any(map(lambda x: validation_passes[x['kind']] != validation_pass, filled_transaction_opg.contents)):
        raise ValueError('Mixed validation passes')

    print(validation_pass, "is the validation pass")
    if validation_pass == 0:
        chain_watermark = bytes.fromhex(filled_transaction_opg.shell.chains.main.watermark())
        watermark = b'\x02' + chain_watermark
    else:
        watermark = b'\x03'

    watermarked_message = watermark + bytes.fromhex(filled_transaction_opg.forge())
    # *** 2. Scrub Input on message ***
    scrubbed_message = scrub_input(watermarked_message)
    # *** 3. Digest the message ***
    sodium_digest = pysodium.crypto_generichash(scrubbed_message)
    # *** 4. Sign it ***
    msg_signature = eddsa_sign.eddsa_sign(derived_prv, sodium_digest)
    # *** 5. Prepare for adding it into message ***
    curve = b'ed'
    sig_bytes = b'sig'
    final_sig = base58_encode(msg_signature, curve + sig_bytes).decode()
    # *** 6. Add to opg1 with _spawn
    ready_transaction = filled_transaction_opg._spawn(signature=final_sig)

    return ready_transaction


def withdraw_funds(fprv: str, account_id: str, amount: str, destination: str):
    path = f"{BIP_44_CONSTANT}/{XTZ_ASSET_NUM}/{account_id}/{CHANGE}/{ADDR_INDEX}"
    prv, pub = eddsa_sign.eddsa_derive(fprv, path)
    transaction = prepare_tx(prv, pub, amount, destination)
    return transaction.inject()
