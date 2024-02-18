from terra_sdk.core import AccAddress
from terra_sdk.client.lcd import LCDClient
from terra_sdk.key.raw import RawKey
from terra_sdk.core.bank import MsgSend
from terra_sdk.core.auth import StdFee

terra = LCDClient(url="https://lcd.terra.dev", chain_id="columbus-5")
prv = ""
from_address = AccAddress("")
to_address = AccAddress("")
amount = "10000000uluna"  # send 10 luna
memo = ""

key = RawKey.from_hex(prv)
wallet = terra.wallet(key)
tx = wallet.create_and_sign_tx(
    msgs=[MsgSend(
        wallet.key.acc_address,
        to_address,
        "100000uluna"  # send 0.1 luna
    )],
    memo=memo,
    fee=StdFee(200000, "40000uluna")  # use 0.04 gas
)

result = terra.tx.broadcast(tx)
print(result)
