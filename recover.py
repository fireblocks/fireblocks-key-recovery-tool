import sys
import hashlib
import json
import helper
import uuid
import struct
from curve import secp256k1
from point import Point
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from zipfile import ZipFile

def help():
    msg = """usage: fb_recover_keys.py <<backup zip pathname>> <<rsa key file path>> <<user recovery passphrase>> <options>

Options:
--prv - reveal private key. Otherwise only the public address of the
--help (-h) - print this message    """

    print(msg)

def unpad(text, k = 16):
    nl = len(text)
    val = int(text[-1])
    if val > k:
        raise ValueError('Input is not padded or padding is corrupt')
    if not all([x==val for x in text[nl-val:nl]]):
        raise ValueError('Input is not padded or padding is corrupt')
    l = nl - val
    return text[:l]

def decrypt_mobile_private_key(recovery_password, user_id, encrypted_key):
    wrap_key = hashlib.pbkdf2_hmac("sha1", recovery_password, user_id, 10000, 32)
    iv = chr(0) * 16
    cipher = AES.new(wrap_key, AES.MODE_CBC, iv)
    prv_key = unpad(cipher.decrypt(encrypted_key))
    return prv_key


def key_to_extended_key(key, chain_code, is_pub):
    if is_pub:
        extended_key = (0x0488B21E).to_bytes(4, byteorder='big') # prefix
    else:
        extended_key = (0x0488ADE4).to_bytes(4, byteorder='big') # prefix
    extended_key += bytes(1) # depth
    extended_key += bytes(4) # fingerprint
    extended_key += bytes(4) # child number
    extended_key += chain_code # chain code

    if not is_pub:
        extended_key += bytes(1)
    extended_key += key
    return extended_key

def get_player_id(key_id, cosigner_id, is_cloud):
    if is_cloud:
        key_id_first_dword = uuid.UUID(key_id).int.to_bytes(16, 'big')[0:4]
        player_id = int(cosigner_id) << 32 | struct.unpack("I", key_id_first_dword)[0]
    else:
        cosigner_prefix = list(uuid.UUID(cosigner_id).int.to_bytes(16, 'big')[0:6])
        cosigner_prefix.reverse()
        player_id = struct.unpack("Q", bytes(cosigner_prefix) + struct.pack("h", 0))[0]
    return player_id

def prime_mod_inverse(x, p):
    return pow(x, p-2, p)

def lagrange_coefficient(my_id, ids, field):
    coefficient = 1
    for id in ids:
        if id == my_id:
            continue

        tmp = prime_mod_inverse((id - my_id) % field, field)
        tmp = (tmp * id) % field
        coefficient *= tmp
    return coefficient

def main():
    privkey = 0
    chain_code = None
    key_id = None
    metadata_public_key = None
    players_data = {}

    if len(sys.argv) < 4:
        help()
        exit(0)
    with open(sys.argv[2], 'r') as _file:
        key_pem = _file.read()
    key = RSA.importKey(key_pem)
    cipher = PKCS1_OAEP.new(key)
    with ZipFile(sys.argv[1], 'r') as zipfile:
        if "metadata.json" not in zipfile.namelist():
            print("ERROR: backup zip doesn't contain metadata.json")
            exit(-1) 
        with zipfile.open("metadata.json") as file:
            obj = json.loads(file.read())
            chain_code = bytes.fromhex(obj["chainCode"])
            key_id = obj["keyId"]
            metadata_public_key = obj["publicKey"]
        for name in zipfile.namelist():
            with zipfile.open(name) as file:
                if name == "MOBILE":
                    obj = json.loads(file.read())
                    if obj["keyId"] != key_id:
                        print("ERROR: mobile keyId confilicts with metadata.json")
                        exit(-1)
                    data = decrypt_mobile_private_key(sys.argv[3].encode(), obj["userId"].encode(), bytes.fromhex(obj["encryptedKey"]))
                    players_data[get_player_id(key_id, obj["deviceId"], False)] = int.from_bytes(data, byteorder='big')
                elif name == "metadata.json":
                    continue
                else:
                    data = cipher.decrypt(file.read())
                    players_data[get_player_id(key_id, name, True)] = int.from_bytes(data, byteorder='big')

    for key, value in players_data.items():
        privkey = (privkey + value * lagrange_coefficient(key, players_data.keys(), secp256k1.q)) % secp256k1.q

    pubkey = secp256k1.G * privkey

    pub = pubkey.serialize()

    if (metadata_public_key != pub):
        print("ERROR: metadata.json public key doesn't metch the calculated one")
        exit(-1) 
    
    if (not chain_code or len(chain_code) != 32):
        print("ERROR: metadata.json doesn't contain valid chain code")
        exit(-1)
    
    if "--prv" in sys.argv:
        print("expriv:\t" + helper.encode_base58_checksum(key_to_extended_key(privkey.to_bytes(32, byteorder='big'), chain_code, False)))
    print("expub:\t" + helper.encode_base58_checksum(key_to_extended_key(bytes.fromhex(pub), chain_code, True)))

if __name__== "__main__" :
    main()
