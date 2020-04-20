import pytest
import sys

sys.path.append("..")
from utils import recover


def test_recovery():
    privkeys, chaincode = recover.restore_key_and_chaincode("backup.zip", "priv.pem", "Thefireblocks1!")
    assert(privkeys['MPC_ECDSA_SECP256K1'] == 0x473d1820ca4bf7cf6b018a8520b1ec0849cb99bce4fff45c5598723f67b3bd52)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", privkeys['MPC_ECDSA_SECP256K1'])
    assert(pub == "021d84f3b6d7c6888f81c7cc381b658d85319f27e1ea9c93dff128667fb4b82ba0")
    assert(recover.encode_extended_key(privkeys['MPC_ECDSA_SECP256K1'], chaincode, False) == "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9aunJDs4SsrmoxycAo6xxBTHawSz5sYxEy8TpCkv66Sci373DJ")
    assert(recover.encode_extended_key(pub, chaincode, True) == "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6QJJZSgiCXT6sq7wa2jCk5t4Vv1r1E4q1venKghAAdyzieufGyX")
