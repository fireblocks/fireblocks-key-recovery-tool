from utils import ed25519
from Crypto.Random import random
import hashlib

def _ed25519_serialize(p):
    if (p[0] & 1):
        return (p[1] + 2**255).to_bytes(32, byteorder="little")
    else:
        return (p[1]).to_bytes(32, byteorder="little")

def eddsa_sign(private_key, message):
    privkey = private_key
    if type(private_key) != int:
        privkey = int.from_bytes(private_key, byteorder='big')
    nonce = random.randrange(ed25519.l)
    R = ed25519.scalarmult(ed25519.B, nonce)
    A = ed25519.scalarmult(ed25519.B, privkey)
    sha = hashlib.sha512()
    sha.update(_ed25519_serialize(R))
    sha.update(_ed25519_serialize(A))
    sha.update(message.encode('utf-8'))
    hram = int.from_bytes(sha.digest(), byteorder='little') % ed25519.l
    s = (hram * privkey + nonce) % ed25519.l
    return _ed25519_serialize(R) + s.to_bytes(32, byteorder="little")