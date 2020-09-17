from utils import ed25519
from Crypto import Random
import hashlib
import hmac
import base58

def _ed25519_serialize(p):
    if (p[0] & 1):
        return (p[1] + 2**255).to_bytes(32, byteorder="little")
    else:
        return (p[1]).to_bytes(32, byteorder="little")

def _hash_for_derive(pubkey, chaincode, child_num):
    ctx = hmac.new(chaincode, digestmod = hashlib.sha512)
    ctx.update(_ed25519_serialize(pubkey))
    ctx.update(b'\0')
    ctx.update(child_num.to_bytes(4, byteorder="big"))
    return ctx.digest()

def _derive_next_key_level(pubkey, privkey, chaincode, child_num):
    hash = _hash_for_derive(pubkey, chaincode, child_num)
    derived_chaincode = hash[32:]
    exp = int.from_bytes(hash[:32], byteorder="big")
    tmp_point = ed25519.scalarmult(ed25519.B, exp)
    derived_pubkey = ed25519.edwards(pubkey, tmp_point)
    derived_privkey = (privkey + exp) % ed25519.l
    return (derived_pubkey, derived_privkey, derived_chaincode)

def eddsa_sign(private_key, message):
    if type(message) == str:
        message = message.encode('utf-8')
    privkey = private_key
    if type(private_key) != int:
        privkey = int.from_bytes(private_key, byteorder='big')
    seed = Random.get_random_bytes(32)
    sha = hashlib.sha512()
    sha.update(seed)
    sha.update(privkey.to_bytes(32, byteorder="little"))
    sha.update(message)
    nonce = int.from_bytes(sha.digest(), byteorder="little") % ed25519.l
    R = ed25519.scalarmult(ed25519.B, nonce)
    A = ed25519.scalarmult(ed25519.B, privkey)
    sha = hashlib.sha512()
    sha.update(_ed25519_serialize(R))
    sha.update(_ed25519_serialize(A))
    sha.update(message)
    hram = int.from_bytes(sha.digest(), byteorder='little') % ed25519.l
    s = (hram * privkey + nonce) % ed25519.l
    return _ed25519_serialize(R) + s.to_bytes(32, byteorder="little")

def eddsa_derive(fkey, derivation_path):
    path = derivation_path.split('/')
    if len(path) != 5 or path[0] != '44':
        raise Exception(derivation_path + " is not valid bip44 path")
    decoded_key = base58.b58decode_check(fkey)
    if len(decoded_key) != 78:
        raise Exception(fkey + " is not valid Fireblocks-formatted key")
    prefix = int.from_bytes(decoded_key[:4], byteorder='big')
    is_private = False
    if prefix == 0x03273a10:
        is_private = True
    elif prefix == 0x03273e4b:
        is_private = False
    else:
        raise Exception(fkey + " is not valid FPRV nor FPUB")
    chaincode = decoded_key[13:45]
    priv = int.from_bytes(decoded_key[46:], byteorder='big')
    if is_private:
        pub = ed25519.scalarmult(ed25519.B, priv)
    else:
        pub = ed25519.decodepoint(priv.to_bytes(32, 'big'))
        priv = 0

    for index in path:
        (pub, priv, chaincode) = _derive_next_key_level(pub, priv, chaincode, int(index))
    if not is_private:
        priv = None
    return (priv, _ed25519_serialize(pub))

def fprv_eddsa_sig(fprv, derivation_path, message):
    fprv_decoded = base58.b58decode_check(fprv)
    if len(fprv_decoded) != 78 or int.from_bytes(fprv_decoded[:4], byteorder='big') != 0x03273a10:
        raise Exception(fprv + " is not valid FPRV")
    (priv, pub) = eddsa_derive(fprv, derivation_path)
    return eddsa_sign(priv, message)

def private_key_to_public_key(private_key):
    return _ed25519_serialize(ed25519.scalarmult(ed25519.B, private_key))