from substrateinterface import SubstrateInterface, Keypair, KeypairType

from utils import eddsa_sign

BIP_44_CONSTANT = 44
DOT_ASSET_NUM = 354
CHANGE = 0
ADDR_INDEX = 0

def withdraw(priv, pub, to_address, amount):
    substrate = SubstrateInterface(url='wss://rpc.polkadot.io', ss58_format=0, type_registry_preset='polkadot', use_remote_preset=True)
    call = substrate.compose_call(
        call_module='Balances',
        call_function='transfer',
        call_params={'dest': to_address, 'value': int(amount * 1e8)}
    )
    from_address = public_key_to_address(pub)
    nonce = substrate.get_account_nonce(from_address)
    payload = substrate.generate_signature_payload(call, nonce=nonce).data
    signature = '0x' + eddsa_sign.eddsa_sign(priv, payload).hex()

    keypair = Keypair(ss58_address=from_address, ss58_format=0, crypto_type=KeypairType.ED25519)
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair, nonce=nonce, signature=signature)
    result=substrate.submit_extrinsic(extrinsic=extrinsic)
    print(result)

def getBalance(self, addr):
    account_info = self._accountInfo(addr)
    if account_info is None: return 0
    return account_info['data']['free']

def public_key_to_address(public_key: bytes) -> str:
    return Keypair(public_key=public_key, ss58_format=0).ss58_address

def xpub_to_address(xpub: str, account: int) -> str:
    path = f'{BIP_44_CONSTANT}/{DOT_ASSET_NUM}/{account}/{CHANGE}/{ADDR_INDEX}'
    _, pub = eddsa_sign.eddsa_derive(xpub, path)
    return public_key_to_address(pub)

def withdraw_from_account(xpriv: str, account: int, to_address : str, amount: float) -> str:
    path = f'{BIP_44_CONSTANT}/{DOT_ASSET_NUM}/{account}/{CHANGE}/{ADDR_INDEX}'
    priv, pub = eddsa_sign.eddsa_derive(xpriv, path)
    return withdraw(priv, pub, to_address, amount)