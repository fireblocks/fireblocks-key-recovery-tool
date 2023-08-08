
from utils.curve import secp256k1
from utils.errors import RecoveryError, RecoveryErrorMetadataNotFound, RecoveryErrorRSAKeyImport, RecoveryErrorIncorrectRSAKey
from utils.metadata import parse_metadata_file

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from dataclasses import dataclass
from typing import Dict, Optional
from zipfile import ZipFile

import hashlib
import hmac
import os
import uuid


DERIVATION_CHILD_NUM = (1 << 31).to_bytes(4, byteorder="big")


class UnsupportedAlgorithmError(RecoveryError):
    def __init__(self, algorithm: str):
        super().__init__(f"Unsupported signing algorithm {algorithm}")


class MissingWalletMasterKeyId(RecoveryError):
    def __init__(self):
        super().__init__("metadata.json does not contain any non custodial wallet master keys")


class AmbiguousWalletMasterKeyId(RecoveryError):
    def __init__(self):
        super().__init__("metadata.json contains more than one non custodial wallet master keys")


class InvalidMasterKey(RecoveryError):
    def __init__(self, key_id: str):
        super().__init__(f"Master key {key_id} is malformed")


class InvalidWalletId(RecoveryError):
    def __init__(self, wallet_id: str):
        super().__init__(f"Wallet ID '{wallet_id}' is invalid")


@dataclass
class WalletMaster:
    wallet_seed: bytes
    asset_seed: bytes
    master_key_for_cosigner: Dict[str, bytes]


def _get_cloud_player_id(cosigner_id: str):
    cosigner_prefix = list(uuid.UUID(cosigner_id).int.to_bytes(16, byteorder="big")[0:4])
    return int.from_bytes(cosigner_prefix, byteorder="little")


def _get_algorithm_field_mod(algorithm: str) -> int:
    if algorithm in ("MPC_ECDSA_SECP256K1", "MPC_CMP_ECDSA_SECP256K1"):
        return secp256k1.q
    else:
        raise UnsupportedAlgorithmError(algorithm)


def is_valid_wallet_id(wallet_id: str) -> bool:
    try:
        return str(uuid.UUID(wallet_id)) == wallet_id
    except ValueError:
        return False


def recover_wallet_master(zip_path: os.PathLike, private_pem_path: os.PathLike, key_passphrase: Optional[str] = None) -> WalletMaster:
    with open(private_pem_path, 'r') as fp:
        key_pem = fp.read()

    try:
        key = RSA.importKey(key_pem, passphrase=key_passphrase)
    except ValueError:
        raise RecoveryErrorRSAKeyImport()

    cipher = PKCS1_OAEP.new(key)

    with ZipFile(zip_path, 'r') as zfp:
        if "metadata.json" not in zfp.namelist():
            raise RecoveryErrorMetadataNotFound(str(zip_path))

        with zfp.open("metadata.json") as file:
            master_keys = parse_metadata_file(file).master_keys

        wallet_master_key_ids = [ key_id for key_id, md in master_keys.items() if md.key_type == "NON_CUSTODIAL_WALLET_MASTER" ]
        if not wallet_master_key_ids:
            raise MissingWalletMasterKeyId()
        elif len(wallet_master_key_ids) > 1:
            raise AmbiguousWalletMasterKeyId()

        key_id = wallet_master_key_ids[0]
        wallet_seed = master_keys[key_id].wallet_seed
        asset_seed = master_keys[key_id].asset_seed

        cosigner_keys = {}
        for cosigner in master_keys[key_id].cosigners:
            if cosigner.cosigner_type != "cloud":
                continue

            player_id = _get_cloud_player_id(cosigner.cosigner_id)
            master_key_file_name = f"{player_id}_{key_id}"
            data = zfp.open(master_key_file_name).read()

            try:
                master_key = cipher.decrypt(data)
            except ValueError:
                raise RecoveryErrorIncorrectRSAKey()

            if len(master_key) != 32:
                raise InvalidMasterKey(key_id)

            cosigner_keys[cosigner.cosigner_id] = master_key

        return WalletMaster(
            wallet_seed=wallet_seed,
            asset_seed=asset_seed,
            master_key_for_cosigner=cosigner_keys
        )


def derive_non_custodial_wallet_cloud_shares(wallet_master: WalletMaster, wallet_id: str, algorithm: str) -> Dict[str, bytes]:
    if not is_valid_wallet_id(wallet_id):
        raise InvalidWalletId(wallet_id)

    mod = _get_algorithm_field_mod(algorithm)
    chaincode = hashlib.sha256(wallet_id.encode() + wallet_master.wallet_seed).digest()

    result = {}
    for cosigner_id, master_key in wallet_master.master_key_for_cosigner.items():
        assert len(master_key) == 32

        h = hmac.HMAC(chaincode, digestmod=hashlib.sha512)
        h.update(b'\0')
        h.update(master_key)
        h.update(DERIVATION_CHILD_NUM)

        offset = int.from_bytes(h.digest()[:32], byteorder="big")
        base = int.from_bytes(master_key, byteorder="big")

        derived_x = (base + offset) % secp256k1.q
        derived = derived_x.to_bytes(32, byteorder="big")

        expansion = int.from_bytes(hashlib.sha512(derived).digest(), byteorder="big")
        wallet_share = expansion % mod

        result[cosigner_id] = wallet_share.to_bytes(32, byteorder="big")

    return result


def derive_non_custodial_wallet_asset_chaincode(wallet_master: WalletMaster, wallet_id: str) -> bytes:
    if not is_valid_wallet_id(wallet_id):
        raise InvalidWalletId(wallet_id)

    return hashlib.sha256(wallet_id.encode() + wallet_master.asset_seed).digest()
