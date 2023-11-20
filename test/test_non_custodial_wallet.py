import pathlib
import pytest

from utils import non_custodial_wallet, errors

TEST_DIR = pathlib.Path.resolve(pathlib.Path(__file__)).parent


@pytest.fixture
def basic_wallet_master() -> non_custodial_wallet.WalletMaster:
    return non_custodial_wallet.WalletMaster(
        wallet_seed=bytes.fromhex("3c590f865cdf272d9e0490f5918b1a5e4904b07e7c0beccf40ad33d82ba26102"),
        asset_seed=bytes.fromhex("fb8b1b0c95c1247459616a23aa11c3a5aea26c4b0f2c53471e4e4b7f574929d1"),
        master_key_for_cosigner={
            "21926ecc-4a8a-4614-bbac-7c591aa7efdd": bytes.fromhex("0de5a6cf9a4b2f6ba69a7f8348b9fb54df48d5af176c2564d9349425a7efe31c")
        }
    )


def test_recover_wallet_master_basic(basic_wallet_master):
    result = non_custodial_wallet.recover_wallet_master(TEST_DIR / "backup_with_master_key.zip", TEST_DIR / "priv_ncw.pem", key_passphrase="SECRET")

    assert result == basic_wallet_master


def test_recover_wallet_master_incorrect_key():
    with pytest.raises(errors.RecoveryErrorIncorrectRSAKey):
        non_custodial_wallet.recover_wallet_master(TEST_DIR / "backup_with_master_key.zip", TEST_DIR / "priv.pem")


def test_recover_wallet_master_incorrect_passphrase():
    with pytest.raises(errors.RecoveryErrorRSAKeyImport):
        non_custodial_wallet.recover_wallet_master(TEST_DIR / "backup_with_master_key.zip", TEST_DIR / "priv_ncw.pem", key_passphrase="NOT SECRET")

    with pytest.raises(errors.RecoveryErrorRSAKeyImport):
        non_custodial_wallet.recover_wallet_master(TEST_DIR / "backup_with_master_key.zip", TEST_DIR / "priv_ncw.pem")


def test_recover_wallet_master_no_master_keys():
    with pytest.raises(non_custodial_wallet.MissingWalletMasterKeyId):
        non_custodial_wallet.recover_wallet_master(TEST_DIR / "backup_cmp.zip", TEST_DIR / "priv.pem")


def test_derive_cloud_shares_basic_ecdsa(basic_wallet_master):
    result = non_custodial_wallet.derive_non_custodial_wallet_cloud_shares(basic_wallet_master, "2d33e419-4c84-44b1-9d9a-3598f96642b0", "MPC_ECDSA_SECP256K1")
    assert result.keys() == { "21926ecc-4a8a-4614-bbac-7c591aa7efdd" }
    assert result["21926ecc-4a8a-4614-bbac-7c591aa7efdd"].hex().upper() == "F357EC43A3ABA03AECCD4727DB2AB43AFB472B12FE690C2266DBF8E9294AD25D"

    result = non_custodial_wallet.derive_non_custodial_wallet_cloud_shares(basic_wallet_master, "69c4e0de-946f-45db-954d-4d890a5af0fe", "MPC_ECDSA_SECP256K1")
    assert result.keys() == { "21926ecc-4a8a-4614-bbac-7c591aa7efdd" }
    assert result["21926ecc-4a8a-4614-bbac-7c591aa7efdd"].hex().upper() == "165270C168AE45C8980A44179622C521FFE5A5251191ACE11ECDF52BF63D6FA0"


def test_derive_cloud_shares_bad_wallet_id(basic_wallet_master):
    with pytest.raises(non_custodial_wallet.InvalidWalletId):
        non_custodial_wallet.derive_non_custodial_wallet_cloud_shares(basic_wallet_master, "", "MPC_ECDSA_SECP256K1")

    with pytest.raises(non_custodial_wallet.InvalidWalletId):
        non_custodial_wallet.derive_non_custodial_wallet_cloud_shares(basic_wallet_master, "cant-possibly-be-a-wallet", "MPC_ECDSA_SECP256K1")


def test_derive_cloud_shares_bad_algorithm(basic_wallet_master):
    with pytest.raises(non_custodial_wallet.UnsupportedAlgorithmError):
        non_custodial_wallet.derive_non_custodial_wallet_cloud_shares(basic_wallet_master, "2d33e419-4c84-44b1-9d9a-3598f96642b0", "")

    with pytest.raises(non_custodial_wallet.UnsupportedAlgorithmError):
        non_custodial_wallet.derive_non_custodial_wallet_cloud_shares(basic_wallet_master, "2d33e419-4c84-44b1-9d9a-3598f96642b0", "NO_SUCH_ALGO")


def test_derive_asset_chaincode_basic(basic_wallet_master):
    result = non_custodial_wallet.derive_non_custodial_wallet_asset_chaincode(basic_wallet_master, "2d33e419-4c84-44b1-9d9a-3598f96642b0")
    assert result.hex() == "43f48c974efdbbac14e5864fe2f0aec8a13e5f8b823df5052fddf0a9fa24367b"


def test_derive_asset_chaincode_bad_wallet_id(basic_wallet_master):
    with pytest.raises(non_custodial_wallet.InvalidWalletId):
        non_custodial_wallet.derive_non_custodial_wallet_asset_chaincode(basic_wallet_master, "")

    with pytest.raises(non_custodial_wallet.InvalidWalletId):
        non_custodial_wallet.derive_non_custodial_wallet_asset_chaincode(basic_wallet_master, "cant-possibly-be-a-wallet")
