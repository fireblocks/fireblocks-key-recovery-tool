import pytest
import sys

sys.path.append("..")
from utils import recover


def test_recovery():
    privkeys, chaincode = recover.restore_key_and_chaincode("backup.zip", "priv.pem", "Thefireblocks1!")
    assert(privkeys['MPC_ECDSA_SECP256K1'] == 0x473d1820ca4bf7cf6b018a8520b1ec0849cb99bce4fff45c5598723f67b3bd52)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", privkeys['MPC_ECDSA_SECP256K1'])
    assert(pub == "021d84f3b6d7c6888f81c7cc381b658d85319f27e1ea9c93dff128667fb4b82ba0")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', privkeys['MPC_ECDSA_SECP256K1'], chaincode, False) == "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9aunJDs4SsrmoxycAo6xxBTHawSz5sYxEy8TpCkv66Sci373DJ")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, chaincode, True) == "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6QJJZSgiCXT6sq7wa2jCk5t4Vv1r1E4q1venKghAAdyzieufGyX")
    print("recovery OK")

def test_full_recovery():
    privkeys, chaincode = recover.restore_key_and_chaincode("backup_new.zip", "priv2.pem", "Thefireblocks1!")
    assert(privkeys['MPC_ECDSA_SECP256K1'] == 0x66b1baf063db6e7152480334ebab0ab098e85f682b784754e46c18c962a1aa9d)
    assert(privkeys['MPC_EDDSA_ED25519'] == 0xd74820d02cc2aa09e2d0bcb36aeb92625b3d92c8d202063eab5513fd4453a44)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", privkeys['MPC_ECDSA_SECP256K1'])
    assert(pub == "02e0bf609d7ced9c49e9f4c1d1df0142bb95eb622fa617a9f7280fa23b7f013dc6")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', privkeys['MPC_ECDSA_SECP256K1'], chaincode, False) == "xprv9s21ZrQH143K2zPNSbKDKusTNW4XVwvTCCEFvcLkeNyauqJJd9UjZg3AtfZbmXa22TFph2NdACUPoWR4sCqMCKQM1j7jRvLuBCF3YoapsX6")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, chaincode, True) == "xpub661MyMwAqRbcFUTqYcrDh3pBvXu1uQeJZR9rizkNCiWZnddTAgnz7UMejwX7u4xLmh2JMTtL7DdZmBWGUKa7v836UarassQ3DVFATMzRycV")
    pub = recover.get_public_key("MPC_EDDSA_ED25519", privkeys['MPC_EDDSA_ED25519'])
    assert(pub == "0050cfee85dabebed78f43e94a1b7afd13c20461ad66efa083779bdeffd22269d9")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', privkeys['MPC_EDDSA_ED25519'], chaincode, False) == "fprv4LsXPWzhTTp9ax8NGVwbnRFuT3avVQ4ydHNWcu8hCGZd18TRKxgAzbrpY9bLJRe4Y2AyX9TfQdDPbmqEYoDCTju9QFZbUgdsxsmUgfvuEDK")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', pub, chaincode, True) == "fpub8sZZXw2wbqVpURAAA9cCBpv2256rejFtCayHuRAzcYN1qciBxMVmB6UgiDAQTUZh5EP9JZciPQPjKAHyqPYHELqEHWkvo1sxreEJgLyfCJj")
    print("recovery OK")

def test_recovery_old_format():
    privkeys, chaincode = recover.restore_key_and_chaincode("backup_old_format.zip", "priv.pem", "Thefireblocks1!")
    assert(privkeys['MPC_ECDSA_SECP256K1'] == 0x473d1820ca4bf7cf6b018a8520b1ec0849cb99bce4fff45c5598723f67b3bd52)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", privkeys['MPC_ECDSA_SECP256K1'])
    assert(pub == "021d84f3b6d7c6888f81c7cc381b658d85319f27e1ea9c93dff128667fb4b82ba0")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', privkeys['MPC_ECDSA_SECP256K1'], chaincode, False) == "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9aunJDs4SsrmoxycAo6xxBTHawSz5sYxEy8TpCkv66Sci373DJ")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, chaincode, True) == "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6QJJZSgiCXT6sq7wa2jCk5t4Vv1r1E4q1venKghAAdyzieufGyX")
    print("recovery (old format) OK")

def test_cmp_recovery():
    privkeys, chaincode = recover.restore_key_and_chaincode("backup_cmp.zip", "priv.pem", "Fireblocks1!")
    assert(privkeys['MPC_CMP_ECDSA_SECP256K1'] == 0xf57c18e98a24ca0b36fbbd103233aff128b740426da189ce208545d44bbad050)
    assert(privkeys['MPC_CMP_EDDSA_ED25519'] == 0xa536dc2f2d744ae78eb26fdfb4b9e234a649525e0a1142bf900cd9c26987007)
    pub = recover.get_public_key("MPC_CMP_ECDSA_SECP256K1", privkeys['MPC_CMP_ECDSA_SECP256K1'])
    assert(pub == "03321ad97aea16624280b83e1c1b36bb9cb293cac84925fe5fcf956386cd063fec")
    assert(recover.encode_extended_key('MPC_CMP_ECDSA_SECP256K1', privkeys['MPC_CMP_ECDSA_SECP256K1'], chaincode, False) == "xprv9s21ZrQH143K3PhnQQqPZm38HtkJ3bjcVmwc1SfGG8ddw3jXtrhSBNFNcVVx7VUL8vPpmMg1dqxhecVq8WJ1VHn9yoeRM88qfYEnEEi6XaQ")
    assert(recover.encode_extended_key('MPC_CMP_ECDSA_SECP256K1', pub, chaincode, True) == "xpub661MyMwAqRbcFsnFWSNPvtyrqvanT4TTrzsCoq4spUAcor4gSQ1gjAZrTkzR1o8XZ5uPq6WELaga3Zh1eJyfXLvfkWTfV7AjdFU5VuWMpPp")
    pub = recover.get_public_key("MPC_CMP_EDDSA_ED25519", privkeys['MPC_CMP_EDDSA_ED25519'])
    assert(pub == "00701c977bd4d2038328dd8154c147f9d40225fc8e9fd98c010cc968ea8fabb362")
    assert(recover.encode_extended_key('MPC_CMP_EDDSA_ED25519', privkeys['MPC_CMP_EDDSA_ED25519'], chaincode, False) == "fprv4LsXPWzhTTp9bMSnEKTn2GRaNSGh33t8vs5rhjTCp2Dg2LtebftscJ52FxRRKeHGLfK6X5Lg3LcsGxQyHZ8ovvPsP2s9PLbZC2VFHc64vFH")
    assert(recover.encode_extended_key('MPC_CMP_EDDSA_ED25519', pub, chaincode, True) == "fpub8sZZXw2wbqVpUpUa7y8NRg5gwTndCP53WAgdzFVWEJ24rq9RE4iTnngtS2FeusezUsAJb2sZiMvSDqYGeGVSs65wJqYcGzQRuZGM9NHHqog")
    print("cmp recovery OK")

if __name__ == '__main__':
    test_recovery()
    test_full_recovery()
    test_recovery_old_format()
    test_cmp_recovery()

