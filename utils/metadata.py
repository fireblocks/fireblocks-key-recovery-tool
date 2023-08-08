from utils.errors import RecoveryErrorUnknownChainCode

from dataclasses import dataclass
from typing import IO, Dict, List, Literal

import json


@dataclass
class CoSignerMetadata:
    cosigner_id: str
    cosigner_type: Literal["cloud", "mobile"]


@dataclass
class SigningKeyMetadata:
    public_key: str
    algorithm: str
    chain_code: bytes


@dataclass
class MasterKeyMetadata:
    key_type: str
    wallet_seed: bytes
    asset_seed: bytes
    cosigners: List[CoSignerMetadata]


@dataclass
class RecoveryPackageMetadata:
    signing_keys: Dict[str, SigningKeyMetadata]
    master_keys: Dict[str, MasterKeyMetadata]


def parse_metadata_file(fp: IO[bytes]) -> RecoveryPackageMetadata:
    obj = json.load(fp)
    default_chain_code = bytes.fromhex(obj["chainCode"])

    keys_in_backup = obj.get("keys")
    if keys_in_backup is None:
        # backward compatibility: backup includes just one ECDSA key
        keys_in_backup = {obj["keyId"]: {"publicKey": obj["publicKey"], "algo": "MPC_ECDSA_SECP256K1"}}

    signing_keys = {}
    for key_id, key_metadata in keys_in_backup.items():
        metadata_public_key = key_metadata["publicKey"]
        algo = key_metadata["algo"]

        # Some keys may have their own chaincode specified
        # If a chaincode definition exists for a specific key, use that.
        # if not, use the "default" chaincode defined at the top of metadata.json
        if "chainCode" in key_metadata:
            chain_code_for_this_key = bytes.fromhex(key_metadata["chainCode"])
        else:
            chain_code_for_this_key = default_chain_code

        if len(chain_code_for_this_key) != 32:
            raise RecoveryErrorUnknownChainCode()

        signing_keys[key_id] = SigningKeyMetadata(
            public_key=metadata_public_key,
            algorithm=algo,
            chain_code=chain_code_for_this_key
        )

    master_keys_in_backup = obj.get("masterKeys", {})

    master_keys = {}
    for key_id, key_metadata in master_keys_in_backup.items():
        key_type = key_metadata["type"]
        wallet_seed = bytes.fromhex(key_metadata["walletSeed"])
        asset_seed = bytes.fromhex(key_metadata["assetSeed"])

        cosigners = []
        for cosigner_obj in key_metadata["cosigners"]:
            cosigners.append(CoSignerMetadata(
                cosigner_id=cosigner_obj["id"],
                cosigner_type=cosigner_obj["type"]
            ))

        master_keys[key_id] = MasterKeyMetadata(
            key_type=key_type,
            wallet_seed=wallet_seed,
            asset_seed=asset_seed,
            cosigners=cosigners
        )

    return RecoveryPackageMetadata(
        signing_keys=signing_keys,
        master_keys=master_keys
    )
