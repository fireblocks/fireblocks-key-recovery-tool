import pathlib

from utils import recover

TEST_DIR = pathlib.Path.resolve(pathlib.Path(__file__)).parent

def result_list_to_dict(results):
    result = {}
    for algo, privkey, chaincode, keyset_id in results:
        result[algo] = (privkey, chaincode, keyset_id)
    return result

def test_recovery_basic():
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "backup.zip", TEST_DIR / "priv.pem", "Thefireblocks1!"))
    ecdsa_priv_key, ecdsa_chaincode, keyset_id = result['MPC_ECDSA_SECP256K1']
    assert(ecdsa_priv_key == 0x473d1820ca4bf7cf6b018a8520b1ec0849cb99bce4fff45c5598723f67b3bd52)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key)
    assert(pub == "021d84f3b6d7c6888f81c7cc381b658d85319f27e1ea9c93dff128667fb4b82ba0")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9aunJDs4SsrmoxycAo6xxBTHawSz5sYxEy8TpCkv66Sci373DJ")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6QJJZSgiCXT6sq7wa2jCk5t4Vv1r1E4q1venKghAAdyzieufGyX")
    assert(keyset_id == 1)


def test_full_recovery():
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "backup_new.zip", TEST_DIR / "priv2.pem", "Thefireblocks1!"))
    ecdsa_priv_key, ecdsa_chaincode, keyset_id = result['MPC_ECDSA_SECP256K1']
    eddsa_priv_key, eddsa_chaincode, keyset_id_eddsa = result['MPC_EDDSA_ED25519']

    assert(ecdsa_priv_key == 0x66b1baf063db6e7152480334ebab0ab098e85f682b784754e46c18c962a1aa9d)
    assert(eddsa_priv_key == 0xd74820d02cc2aa09e2d0bcb36aeb92625b3d92c8d202063eab5513fd4453a44)

    assert(ecdsa_chaincode == bytes.fromhex('5d90bd21d2273a25d0aea082716bdc4529e007823260ad3479182f6672c25cc4'))
    assert(eddsa_chaincode == bytes.fromhex('5d90bd21d2273a25d0aea082716bdc4529e007823260ad3479182f6672c25cc4'))

    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key)
    assert(pub == "02e0bf609d7ced9c49e9f4c1d1df0142bb95eb622fa617a9f7280fa23b7f013dc6")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K2zPNSbKDKusTNW4XVwvTCCEFvcLkeNyauqJJd9UjZg3AtfZbmXa22TFph2NdACUPoWR4sCqMCKQM1j7jRvLuBCF3YoapsX6")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcFUTqYcrDh3pBvXu1uQeJZR9rizkNCiWZnddTAgnz7UMejwX7u4xLmh2JMTtL7DdZmBWGUKa7v836UarassQ3DVFATMzRycV")
    pub = recover.get_public_key("MPC_EDDSA_ED25519", eddsa_priv_key)
    assert(pub == "0050cfee85dabebed78f43e94a1b7afd13c20461ad66efa083779bdeffd22269d9")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', eddsa_priv_key, eddsa_chaincode, False) == "fprv4LsXPWzhTTp9ax8NGVwbnRFuT3avVQ4ydHNWcu8hCGZd18TRKxgAzbrpY9bLJRe4Y2AyX9TfQdDPbmqEYoDCTju9QFZbUgdsxsmUgfvuEDK")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', pub, eddsa_chaincode, True) == "fpub8sZZXw2wbqVpURAAA9cCBpv2256rejFtCayHuRAzcYN1qciBxMVmB6UgiDAQTUZh5EP9JZciPQPjKAHyqPYHELqEHWkvo1sxreEJgLyfCJj")
    assert(keyset_id == 1)
    assert(keyset_id_eddsa == 1)


def test_recovery_old_format():
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "backup_old_format.zip", TEST_DIR / "priv.pem", "Thefireblocks1!"))
    ecdsa_priv_key, ecdsa_chaincode, _ = result['MPC_ECDSA_SECP256K1']

    assert(ecdsa_priv_key == 0x473d1820ca4bf7cf6b018a8520b1ec0849cb99bce4fff45c5598723f67b3bd52)
    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key)
    assert(pub == "021d84f3b6d7c6888f81c7cc381b658d85319f27e1ea9c93dff128667fb4b82ba0")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF9aunJDs4SsrmoxycAo6xxBTHawSz5sYxEy8TpCkv66Sci373DJ")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6QJJZSgiCXT6sq7wa2jCk5t4Vv1r1E4q1venKghAAdyzieufGyX")


def test_cmp_recovery():
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "backup_cmp.zip", TEST_DIR / "priv.pem", "Fireblocks1!"))
    ecdsa_priv_key, ecdsa_chaincode, _ = result['MPC_CMP_ECDSA_SECP256K1']
    eddsa_priv_key, eddsa_chaincode, _ = result['MPC_CMP_EDDSA_ED25519']

    assert(ecdsa_priv_key == 0xf57c18e98a24ca0b36fbbd103233aff128b740426da189ce208545d44bbad050)
    assert(eddsa_priv_key == 0xa536dc2f2d744ae78eb26fdfb4b9e234a649525e0a1142bf900cd9c26987007)
    
    pub = recover.get_public_key("MPC_CMP_ECDSA_SECP256K1", ecdsa_priv_key)
    assert(pub == "03321ad97aea16624280b83e1c1b36bb9cb293cac84925fe5fcf956386cd063fec")
    assert(recover.encode_extended_key('MPC_CMP_ECDSA_SECP256K1', ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K3PhnQQqPZm38HtkJ3bjcVmwc1SfGG8ddw3jXtrhSBNFNcVVx7VUL8vPpmMg1dqxhecVq8WJ1VHn9yoeRM88qfYEnEEi6XaQ")
    assert(recover.encode_extended_key('MPC_CMP_ECDSA_SECP256K1', pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcFsnFWSNPvtyrqvanT4TTrzsCoq4spUAcor4gSQ1gjAZrTkzR1o8XZ5uPq6WELaga3Zh1eJyfXLvfkWTfV7AjdFU5VuWMpPp")
    pub = recover.get_public_key("MPC_CMP_EDDSA_ED25519", eddsa_priv_key)
    assert(pub == "00701c977bd4d2038328dd8154c147f9d40225fc8e9fd98c010cc968ea8fabb362")
    assert(recover.encode_extended_key('MPC_CMP_EDDSA_ED25519', eddsa_priv_key, eddsa_chaincode, False) == "fprv4LsXPWzhTTp9bMSnEKTn2GRaNSGh33t8vs5rhjTCp2Dg2LtebftscJ52FxRRKeHGLfK6X5Lg3LcsGxQyHZ8ovvPsP2s9PLbZC2VFHc64vFH")
    assert(recover.encode_extended_key('MPC_CMP_EDDSA_ED25519', pub, eddsa_chaincode, True) == "fpub8sZZXw2wbqVpUpUa7y8NRg5gwTndCP53WAgdzFVWEJ24rq9RE4iTnngtS2FeusezUsAJb2sZiMvSDqYGeGVSs65wJqYcGzQRuZGM9NHHqog")


def test_one_custom_chaincode_recovery():
    '''
    The zip in this test was built from 'backup_new.zip',
    the file used in test_full_recovery()
    The only change is in an alternative chain code assigned specifically to MPC_ECDSA_SECP256K1,
    while MPC_EDDSA_ED25519 is not assigned a specific chaincode.
    
    Hence all the extracted keys are they same, and differce lies mostly in the extended form of the key,
    which encodes the chaincode. 
    '''
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "backup_with_one_custom_chaincode.zip", TEST_DIR / "priv2.pem", "Thefireblocks1!"))
    ecdsa_priv_key, ecdsa_chaincode, _ = result['MPC_ECDSA_SECP256K1']
    eddsa_priv_key, eddsa_chaincode, _ = result['MPC_EDDSA_ED25519']

    assert(ecdsa_chaincode != eddsa_chaincode)
    assert(ecdsa_priv_key == 0x66b1baf063db6e7152480334ebab0ab098e85f682b784754e46c18c962a1aa9d)
    assert(eddsa_priv_key == 0xd74820d02cc2aa09e2d0bcb36aeb92625b3d92c8d202063eab5513fd4453a44)

    assert(ecdsa_chaincode == bytes.fromhex('865b4d6e745c64afc98a7fe32103d6ea775910d4d58e00fe17d2fdd4f8f8f1d0'))
    assert(eddsa_chaincode == bytes.fromhex('5d90bd21d2273a25d0aea082716bdc4529e007823260ad3479182f6672c25cc4'))

    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key)
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K3PwZ9jrXG7MZXgj92u6eeCz6M8w8a5RGYJoNmWQRA2eso47rJHr9qawKR9tQVTRki8XUPwVSuBPSnVxT6mQb99XUbruDGk7")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcFt22FmPXdFJJ5iZdSMpW1Ruh9XLk8QxFR78XK3ifhpyMeL5NRqEUapho5bQ7SUavfocg14EDcz2CFMhJYiTjBSXbWQcdkrR")

    pub = recover.get_public_key("MPC_EDDSA_ED25519", eddsa_priv_key)
    assert(pub == "0050cfee85dabebed78f43e94a1b7afd13c20461ad66efa083779bdeffd22269d9")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', eddsa_priv_key, eddsa_chaincode, False) == "fprv4LsXPWzhTTp9ax8NGVwbnRFuT3avVQ4ydHNWcu8hCGZd18TRKxgAzbrpY9bLJRe4Y2AyX9TfQdDPbmqEYoDCTju9QFZbUgdsxsmUgfvuEDK")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', pub, eddsa_chaincode, True) == "fpub8sZZXw2wbqVpURAAA9cCBpv2256rejFtCayHuRAzcYN1qciBxMVmB6UgiDAQTUZh5EP9JZciPQPjKAHyqPYHELqEHWkvo1sxreEJgLyfCJj")


def test_two_custom_chaincode_recovery():
    '''
    The zip in this test was built from 'backup_new.zip',
    the file used in test_full_recovery()
    The only changes are two different chain code assigned specifically to MPC_ECDSA_SECP256K1 and MPC_EDDSA_ED25519.

    The chaincode assigned to MPC_ECDSA_SECP256K1 is the same as the one in 'backup_with_one_custom_chaincode.zip',
    the file used in test_one_custom_chaincode_recovery()

    Hence all the extracted keys are they same:
    only the extended forms of the keys are different, as they encode the respective chaincodes.
 
    '''
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "backup_with_two_custom_chaincode.zip", TEST_DIR / "priv2.pem", "Thefireblocks1!"))
    ecdsa_priv_key, ecdsa_chaincode, _ = result['MPC_ECDSA_SECP256K1']
    eddsa_priv_key, eddsa_chaincode, _ = result['MPC_EDDSA_ED25519']

    assert(ecdsa_chaincode != eddsa_chaincode)
    assert(ecdsa_priv_key == 0x66b1baf063db6e7152480334ebab0ab098e85f682b784754e46c18c962a1aa9d)
    assert(eddsa_priv_key == 0xd74820d02cc2aa09e2d0bcb36aeb92625b3d92c8d202063eab5513fd4453a44)

    assert(ecdsa_chaincode == bytes.fromhex('865b4d6e745c64afc98a7fe32103d6ea775910d4d58e00fe17d2fdd4f8f8f1d0'))
    assert(eddsa_chaincode == bytes.fromhex('89b11d04462618fa6d3981f891f2ae8968d8762f268fdec0a4c440ecafb072dd'))

    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key)
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K3PwZ9jrXG7MZXgj92u6eeCz6M8w8a5RGYJoNmWQRA2eso47rJHr9qawKR9tQVTRki8XUPwVSuBPSnVxT6mQb99XUbruDGk7")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcFt22FmPXdFJJ5iZdSMpW1Ruh9XLk8QxFR78XK3ifhpyMeL5NRqEUapho5bQ7SUavfocg14EDcz2CFMhJYiTjBSXbWQcdkrR")

    pub = recover.get_public_key("MPC_EDDSA_ED25519", eddsa_priv_key)
    assert(pub == "0050cfee85dabebed78f43e94a1b7afd13c20461ad66efa083779bdeffd22269d9")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', eddsa_priv_key, eddsa_chaincode, False) == "fprv4LsXPWzhTTp9bPcFjmqM7U4drbDYRi1YzzFgrfnWAH3hsnLWeJioBzvyvwYJ5p5SuXjwhVd41wrB3tR1Ep41U2DpkJM3J9JGkuCKiBAyyGz")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', pub, eddsa_chaincode, True) == "fpub8sZZXw2wbqVpUre3dRVwWsikRcjUb3CTaHrU9BpoaYr6iGbHGhYPNVYr717NEs15Sjx7Uun6zj2WmGskXQP6Ed9udZYNcUYMeff9hsYTcyr")


def test_recovery_with_mobile_share_as_json():
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "json_share.zip", TEST_DIR / "priv.pem", "Fireblocks1!"))
    ecdsa_priv_key, ecdsa_chaincode, _ = result['MPC_CMP_ECDSA_SECP256K1']
    eddsa_priv_key, eddsa_chaincode, _ = result['MPC_EDDSA_ED25519']

    assert(ecdsa_priv_key == 0x83af98f2f2bdea33eb34177b311d89569725a401c1fc4d6046d266b1ca0dc382)
    assert(eddsa_priv_key == 0xd5c4d44f0f07aaa0bf18e039f28ec2131935ed696636f48ec46bab58e66296b)

    assert(ecdsa_chaincode == bytes.fromhex('b72ad958e75f981589e172fd40cad7536c4b04e5d2866f5a5ec53ce6ed12865a'))
    assert(eddsa_chaincode == bytes.fromhex('b72ad958e75f981589e172fd40cad7536c4b04e5d2866f5a5ec53ce6ed12865a'))

    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key)
    assert(pub == "026bd67069ae5324d49e929a43deb35942531ab9e5b5dd04eaa40a8382f5a1bcdb")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K3t8KzyhL6Vme2HdTM5NitiiLLurTdwUUeKuquVi5QFxz4BwXHdp7Pj1efmkgzPSJp92nTPTMsE7sqABVrAnfgcU9yWYxaNL")
    assert(recover.encode_extended_key('MPC_ECDSA_SECP256K1', pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcGNCo71ELTdiNaKTwkY6aFwdw9JG5CH1TX8EzT32Kx4HTuSnnZHg2d2GEsHt8ZHSEGC68mSxcfkA1xaqKzAgSPAHz11yytGK")
    pub = recover.get_public_key("MPC_EDDSA_ED25519", eddsa_priv_key)
    assert(pub == "001d0a110282f7e440ca24abfd1fcc785c1325cf9e87a0e87a3d3db17f83dc6f49")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', eddsa_priv_key, eddsa_chaincode, False) == "fprv4LsXPWzhTTp9bqsKptKiZ1A66q9rLXXFKorb3CeQBq4Wjd4xcJuWqBndhfkSrMeRaojHBsEv7HoHuGGn5uqWQ43MZFTfuYB6gQgGTdGggTm")
    assert(recover.encode_extended_key('MPC_EDDSA_ED25519', pub, eddsa_chaincode, True) == "fpub8sZZXw2wbqVpVJu7iXzJxQpCfrfnVri9u7TNKighc6rua7KjEhj71gQVsivkxG6tV5xNmXLrU3EpaRP8cJZhk9otAfzsZwJsjEqGCjmWEg8")


def test_recovery_with_master_keys():
    result = result_list_to_dict(recover.restore_key_and_chaincode(TEST_DIR / "backup_with_master_key.zip", TEST_DIR / "priv_ncw.pem", "2#0Iw0Qov@&QP09p", key_pass="SECRET"))
    ecdsa_priv_key, ecdsa_chaincode, _ = result["MPC_CMP_ECDSA_SECP256K1"]
    eddsa_priv_key, eddsa_chaincode, _ = result["MPC_EDDSA_ED25519"]

    pub = recover.get_public_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key)
    assert pub == "033f5e4fb621e4cc777e5b9cdc0ef06c7b55042e9ce6c3bf013daab9fba29b37b8"
    assert recover.encode_extended_key("MPC_ECDSA_SECP256K1", ecdsa_priv_key, ecdsa_chaincode, False) == "xprv9s21ZrQH143K2Hrbqf9FU48JZrgBSVyQiTiF4NVSeoRQ6gfNhKLC7qSewjGD67sDevao46VE3rdYEBuaN216a9SdgzC425MpMqoVLEB16TF"
    assert recover.encode_extended_key("MPC_ECDSA_SECP256K1", pub, ecdsa_chaincode, True) == "xpub661MyMwAqRbcEmw4wggFqC537tWfqxhG5gdqrku4D8xNyUzXEreSfdm8o1BR6F6fKPDysmcLjrR1Q99AANhVHyk8VDkQNngdE3SYHekMGgJ"

    pub = recover.get_public_key("MPC_EDDSA_ED25519", eddsa_priv_key)
    assert pub == "00d9952a61b48099a1dec145c16de516551fef6ece2792041c9ccfd1bf8b71ce4b"
    assert recover.encode_extended_key("MPC_EDDSA_ED25519", eddsa_priv_key, eddsa_chaincode, False) == "fprv4LsXPWzhTTp9aFbbfZmdvZWkeQCaRx7w9YrVkfHPCh1SBypVQ8XdYmGJbCXK5SepZuo9UGTjegUmgaPFunv8vn1TaEggMnaFPXbAmDqSkjZ"
    assert recover.encode_extended_key("MPC_EDDSA_ED25519", pub, eddsa_chaincode, True) == "fpub8sZZXw2wbqVpTidPZDSEKyAsDRiWbHJqirTH3BKgcxoq2U5G2XMDjFtAmH9GJekgiEW9o6hYVn8TJvmk64FRYcJiWaZFmpLirqhEThcHu2s"
