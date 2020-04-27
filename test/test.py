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
    print("recovery OK")

def test_full_recovery():
    privkeys, chaincode = recover.restore_key_and_chaincode("backup_new.zip", "priv2.pem", "Thefireblocks1!")
    assert(privkeys['MPC_ECDSA_SECP256K1'] == 0x66b1baf063db6e7152480334ebab0ab098e85f682b784754e46c18c962a1aa9d)
    assert(privkeys['MPC_EDDSA_ED25519'] == 0xd74820d02cc2aa09e2d0bcb36aeb92625b3d92c8d202063eab5513fd4453a44)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", privkeys['MPC_ECDSA_SECP256K1'])
    assert(pub == "02e0bf609d7ced9c49e9f4c1d1df0142bb95eb622fa617a9f7280fa23b7f013dc6")
    assert(recover.encode_extended_key(privkeys['MPC_ECDSA_SECP256K1'], chaincode, False) == "xprv9s21ZrQH143K2zPNSbKDKusTNW4XVwvTCCEFvcLkeNyauqJJd9UjZg3AtfZbmXa22TFph2NdACUPoWR4sCqMCKQM1j7jRvLuBCF3YoapsX6")
    assert(recover.encode_extended_key(pub, chaincode, True) == "xpub661MyMwAqRbcFUTqYcrDh3pBvXu1uQeJZR9rizkNCiWZnddTAgnz7UMejwX7u4xLmh2JMTtL7DdZmBWGUKa7v836UarassQ3DVFATMzRycV")
    pub = recover.get_public_key("MPC_EDDSA_ED25519", privkeys['MPC_EDDSA_ED25519'])
    assert(pub == "0050cfee85dabebed78f43e94a1b7afd13c20461ad66efa083779bdeffd22269d9")
    assert(recover.encode_extended_key(privkeys['MPC_EDDSA_ED25519'], chaincode, False) == "xprv9s21ZrQH143K2zPNSbKDKusTNW4XVwvTCCEFvcLkeNyauqJJd9UjZg3AtetJGrkiTuAgGEbBDsEjdeFpmeFS1kWNA2QoRAZAaCqSJWQA4pm")
    assert(recover.encode_extended_key(pub, chaincode, True) == "xpub661MyMwAqRbcFUTqYcrDh3pBvXu1uQeJZR9rizkNCiWZnddTAgnz7UMejrYEun7RaeNiSAr7puAq7hmhnb5DhyFkWL58iKs4o7TGys4iYXq")
    print("recovery OK")

def test_recovery_old_format():
    privkeys, chaincode = recover.restore_key_and_chaincode("backup_old_format.zip", "priv.pem", "Thefireblocks1!")
    assert(privkeys['MPC_ECDSA_SECP256K1'] == 0x473d1820ca4bf7cf6b018a8520b1ec0849cb99bce4fff45c5598723f67b3bd52)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", privkeys['MPC_ECDSA_SECP256K1'])
    assert(pub == "021d84f3b6d7c6888f81c7cc381b658d85319f27e1ea9c93dff128667fb4b82ba0")
    assert(recover.encode_extended_key(privkeys['MPC_ECDSA_SECP256K1'], chaincode, False) == "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9aunJDs4SsrmoxycAo6xxBTHawSz5sYxEy8TpCkv66Sci373DJ")
    assert(recover.encode_extended_key(pub, chaincode, True) == "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6QJJZSgiCXT6sq7wa2jCk5t4Vv1r1E4q1venKghAAdyzieufGyX")
    print("recovery (old format) OK")

if __name__ == '__main__':
    test_recovery()
    test_full_recovery()
    test_recovery_old_format()

