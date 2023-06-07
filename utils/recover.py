# -*- coding: utf-8 -*-

import hashlib
import json
import uuid
import struct
from collections import defaultdict
from .curve import secp256k1
from .errors import RecoveryError, RecoveryErrorRSAKeyImport, RecoveryErrorMetadataNotFound
from .helper import encode_base58_checksum
from .metadata import parse_metadata_file
from utils import ed25519
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from zipfile import ZipFile

pubkey_prefix = {
    'MPC_ECDSA_SECP256K1': 0x0488B21E,
    'MPC_CMP_ECDSA_SECP256K1': 0x0488B21E,
    'MPC_EDDSA_ED25519': 0x03273e4b,
    'MPC_CMP_EDDSA_ED25519': 0x03273e4b,
}

privkey_prefix = {
    'MPC_ECDSA_SECP256K1': 0x0488ADE4,
    'MPC_CMP_ECDSA_SECP256K1': 0x0488ADE4,
    'MPC_EDDSA_ED25519': 0x03273a10,
    'MPC_CMP_EDDSA_ED25519': 0x03273a10,
}

algorithm_enum_mapping = {
    'MPC_ECDSA_SECP256K1': 0,
    'MPC_CMP_ECDSA_SECP256K1': 0,
    'MPC_EDDSA_ED25519': 1,
    'MPC_CMP_EDDSA_ED25519': 1,
}


class RecoveryErrorPublicKeyNoMatch(RecoveryError):
    pass


class RecoveryErrorKeyIdNotInMetadata(RecoveryError):
    def __init__(self, key_id: str):
        super().__init__(f"Found key id {key_id} in zip file, but it doesn't exist in metadata.json")


class RecoveryErrorKeyIdMissing(RecoveryError):
    def __init__(self, key_id: str):
        super().__init__(f"metadata.json contains key id {key_id}, which wasn't found in zip file")


class RecoveryErrorUnknownAlgorithm(RecoveryError):
    def __init__(self, algo):
        super().__init__(f"metadata.json contains unsupported signature algorithm {algo}")


class RecoveryErrorMobileKeyDecrypt(RecoveryError):
    pass


class RecoveryErrorMobileRSAKeyImport(RecoveryError):
    pass


class RecoveryErrorMobileRSADecrypt(RecoveryError):
    pass


def _unpad(text, k = 16):
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
    iv = bytes(chr(0) * 16, 'utf-8')
    cipher = AES.new(wrap_key, AES.MODE_CBC, iv)
    prv_key = _unpad(cipher.decrypt(encrypted_key))
    return prv_key

def _ed25519_point_serialize(p):
    if (p[0] & 1):
        return (p[1] + 2**255).to_bytes(32, byteorder="little").hex()
    else:
        return (p[1]).to_bytes(32, byteorder="little").hex()

def get_player_id(key_id, cosigner_id, is_cloud):
    if is_cloud:
        key_id_first_dword = uuid.UUID(key_id).int.to_bytes(16, 'big')[0:4]
        player_id = int(cosigner_id) << 32 | struct.unpack("I", key_id_first_dword)[0]
    else:
        cosigner_prefix = list(uuid.UUID(cosigner_id).int.to_bytes(16, 'big')[0:6])
        cosigner_prefix.reverse()
        player_id = struct.unpack("Q", bytes(cosigner_prefix) + struct.pack("h", 0))[0]
    return player_id

def _prime_mod_inverse(x, p):
    return pow(x, p-2, p)

def lagrange_coefficient(my_id, ids, field):
    coefficient = 1
    for id in ids:
        if id == my_id:
            continue

        tmp = _prime_mod_inverse((id - my_id) % field, field)
        tmp = (tmp * id) % field
        coefficient *= tmp
    return coefficient

def calculate_keys(key_id, player_to_data, algo):
    if algo == "MPC_ECDSA_SECP256K1":
        privkey = 0
        for key, value in player_to_data.items():
            privkey = (privkey + value * lagrange_coefficient(key, player_to_data.keys(), secp256k1.q)) % secp256k1.q

        pubkey = secp256k1.G * privkey
        return privkey, pubkey.serialize()
    elif algo == "MPC_EDDSA_ED25519":
        privkey = 0
        for key, value in player_to_data.items():
            privkey = (privkey + value * lagrange_coefficient(key, player_to_data.keys(), ed25519.l)) % ed25519.l

        pubkey = ed25519.scalarmult(ed25519.B, privkey)
        return privkey, _ed25519_point_serialize(pubkey)
    if algo == "MPC_CMP_ECDSA_SECP256K1":
        privkey = 0
        for key, value in player_to_data.items():
            privkey = (privkey + value) % secp256k1.q

        pubkey = secp256k1.G * privkey
        return privkey, pubkey.serialize()
    elif algo == "MPC_CMP_EDDSA_ED25519":
        privkey = 0
        for key, value in player_to_data.items():
            privkey = (privkey + value) % ed25519.l

        pubkey = ed25519.scalarmult(ed25519.B, privkey)
        return privkey, _ed25519_point_serialize(pubkey)
    else:
        raise RecoveryErrorUnknownAlgorithm(algo)

def restore_key_and_chaincode(zip_path, private_pem_path, passphrase, key_pass=None, mobile_key_pem_path = None, mobile_key_pass = None):
    privkeys = {}
    players_data = defaultdict(dict)
    signing_keys = {}

    with open(private_pem_path, 'r') as _file:
        key_pem = _file.read()
    try:
        key = RSA.importKey(key_pem, passphrase=key_pass)
    except ValueError:
        raise RecoveryErrorRSAKeyImport()

    cipher = PKCS1_OAEP.new(key)
    with ZipFile(zip_path, 'r') as zipfile:
        if "metadata.json" not in zipfile.namelist():
            raise RecoveryErrorMetadataNotFound(zip_path)

        with zipfile.open("metadata.json") as file:
            signing_keys = parse_metadata_file(file).signing_keys

        for name in zipfile.namelist():
            with zipfile.open(name) as file:
                if name.startswith("MOBILE"):
                    obj = json.loads(file.read())
                    key_id = obj["keyId"]
                    if key_id not in signing_keys:
                        raise RecoveryErrorKeyIdNotInMetadata(key_id)
                    try:
                        if (passphrase):
                            data = decrypt_mobile_private_key(passphrase.encode(), obj["userId"].encode(), bytes.fromhex(obj["encryptedKey"]))
                        else:
                            with open(mobile_key_pem_path, 'r') as _file:
                                mobile_key_pem = _file.read()
                            try:
                                mobile_key = RSA.importKey(mobile_key_pem, passphrase=mobile_key_pass)
                                mobile_cipher = PKCS1_OAEP.new(mobile_key, SHA256)
                            except ValueError:
                                raise RecoveryErrorMobileRSAKeyImport()
                            try:
                                data = mobile_cipher.decrypt(bytes.fromhex(obj["encryptedKey"]))
                            except ValueError:
                                raise RecoveryErrorMobileRSADecrypt()
                    except ValueError:
                        raise RecoveryErrorMobileKeyDecrypt()

                    # if the dycrypted data is a json object try to decode it and use the "key" value
                    try:
                        recover_data_object = json.loads(data.decode())
                        data = bytearray.fromhex(recover_data_object['key'])
                    except:
                        pass

                    if len(data) == 36: # the first 4 bytes encode the algorithm, and the rest is the private share
                        algo = int.from_bytes(data[:4], byteorder='little')
                        if algorithm_enum_mapping[signing_keys[key_id].algorithm] != algo:
                            raise RecoveryErrorUnknownAlgorithm(algo)
                        data = data[4:]
                    players_data[key_id][get_player_id(key_id, obj["deviceId"], False)] = int.from_bytes(data, byteorder='big')
                elif name == "metadata.json":
                    continue
                else:
                    if '_' in name:
                        cosigner_id, key_id = name.split('_')
                    else:
                        #backward compatibility: backup includes just one ECDSA key
                        if len(signing_keys) == 1:  # len > 1 means new format, so ignore old format files
                            cosigner_id = name
                            key_id = list(signing_keys.keys())[0]
                        else:
                            key_id = None

                    if key_id is not None and key_id in signing_keys:
                        data = cipher.decrypt(file.read())
                        players_data[key_id][get_player_id(key_id, cosigner_id, True)] = int.from_bytes(data, byteorder='big')

    for key_id in signing_keys:
        if key_id not in players_data:
            raise RecoveryErrorKeyIdMissing(key_id)

    for key_id, key_players_data in players_data.items():
        algo = signing_keys[key_id].algorithm
        chain_code_for_this_key = signing_keys[key_id].chain_code
        privkey, pubkey_str = calculate_keys(key_id, key_players_data, algo)

        pub_from_metadata = signing_keys[key_id].public_key
        if pub_from_metadata != pubkey_str:
            print(f"Failed to recover {algo} key, expected public key is: {pub_from_metadata} calculated public key is: {pubkey_str}")
            privkeys[algo] = None
        else:
            privkeys[algo] = privkey, chain_code_for_this_key

    if len(privkeys) == 0:
        raise RecoveryErrorPublicKeyNoMatch()
    return privkeys

def get_public_key(algo, private_key):
    privkey = private_key
    if type(private_key) != int:
        privkey = int.from_bytes(private_key, byteorder='big')
    if algo == "MPC_ECDSA_SECP256K1" or algo == "MPC_CMP_ECDSA_SECP256K1":
        pubkey = secp256k1.G * privkey
        return pubkey.serialize()
    elif algo == "MPC_EDDSA_ED25519" or algo == "MPC_CMP_EDDSA_ED25519":
        pubkey = ed25519.scalarmult(ed25519.B, privkey)
        return '00' + _ed25519_point_serialize(pubkey)
    else:
        raise RecoveryErrorUnknownAlgorithm(algo)

def restore_private_key(zip_path, private_pem_path, passphrase, key_pass=None):
    return restore_key_and_chaincode(zip_path, private_pem_path, passphrase, key_pass)


def encode_extended_key(algo, key, chain_code, is_pub):
    if type(key) == int:
        key = key.to_bytes(32, byteorder='big')
    elif type(key) == str:
        key = bytes.fromhex(key)

    if is_pub:
        extended_key = pubkey_prefix[algo].to_bytes(4, byteorder='big') # prefix
    else:
        extended_key = privkey_prefix[algo].to_bytes(4, byteorder='big') # prefix
    extended_key += bytes(1) # depth
    extended_key += bytes(4) # fingerprint
    extended_key += bytes(4) # child number
    extended_key += chain_code # chain code

    if not is_pub:
        extended_key += bytes(1)
    extended_key += key
    return encode_base58_checksum(extended_key)
