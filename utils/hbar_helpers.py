from time import sleep, time
import grpc
import utils.hbar_impl.gen.crypto_service_pb2
import utils.hbar_impl.gen.crypto_service_pb2_grpc
from utils.hbar_impl.gen.transaction_pb2 import Transaction
from utils.hbar_impl.gen.transaction_body_pb2 import TransactionBody
from traceback import format_exc

from utils import eddsa_sign


class TerminalSendException(Exception):
    pass


class NonFinalSendException(Exception):
    pass


class HbarSerializer:
    INITIAL_BALANCE_TINYBARS = 0
    EXP_TINYBARS = int(1e8)
    DEFAULT_FEE = int(1e6)
    MAX_FEE = int(1e8)

    def __init__(self, testnet=True):
        self.nodeAccountID = '0.0.3'  # see note in sender
        self.sender = HbarSender(testnet, self)

    @staticmethod
    def makeAccountID(strID):
        from utils.hbar_impl.gen.basic_types_pb2 import AccountID
        integers = list(map(int, strID.split('.')))
        return AccountID(shardNum=integers[0], realmNum=integers[1], accountNum=integers[2])

    def makeTransactionBody(self, fromAccountIdStr, timestampSeconds, fee, memo=''):
        body = TransactionBody()
        body.transactionID.accountID.CopyFrom(self.makeAccountID(fromAccountIdStr))
        body.transactionID.transactionValidStart.seconds = int(timestampSeconds)
        body.transactionID.transactionValidStart.nanos = 0
        body.nodeAccountID.CopyFrom(self.makeAccountID(self.nodeAccountID))
        body.transactionFee = int(fee)
        body.transactionValidDuration.seconds = 180
        body.memo = memo
        return body

    @classmethod
    def fillCreateAccount(cls, publicKeyBytes, cryptoCreateAccount):
        cryptoCreateAccount.key.ed25519 = publicKeyBytes
        cryptoCreateAccount.initialBalance = cls.INITIAL_BALANCE_TINYBARS
        cryptoCreateAccount.sendRecordThreshold = 9223372036854775807
        cryptoCreateAccount.receiveRecordThreshold = 9223372036854775807
        cryptoCreateAccount.autoRenewPeriod.seconds = 7890000

    def makeCreateAccountTxBody(self, sourceAccountId, publicKeyBytes):
        timestampSeconds = int(time())
        body = self.makeTransactionBody(sourceAccountId, timestampSeconds, self.MAX_FEE)
        self.fillCreateAccount(publicKeyBytes, body.cryptoCreateAccount)
        return body.SerializeToString()

    def fillTransfer(self, sourceAccountId, destAccountId, amountInTinyBars, cryptoTransfer):
        from utils.hbar_impl.gen.basic_types_pb2 import AccountAmount

        src = AccountAmount()
        src.accountID.CopyFrom(self.makeAccountID(sourceAccountId))
        src.amount = -1 * amountInTinyBars
        cryptoTransfer.transfers.accountAmounts.append(src)

        dst = AccountAmount()
        dst.accountID.CopyFrom(self.makeAccountID(destAccountId))
        dst.amount = amountInTinyBars
        cryptoTransfer.transfers.accountAmounts.append(dst)

    def makeSpendTxBody(self, sourceAccountId, timestampSeconds, destAccountId, amount, fee, memo):
        body = self.makeTransactionBody(sourceAccountId, timestampSeconds, fee, memo)
        self.fillTransfer(sourceAccountId, destAccountId, amount, body.cryptoTransfer)
        return body.SerializeToString()

    @staticmethod
    def makeSigPair(signature):
        from utils.hbar_impl.gen.basic_types_pb2 import SignaturePair
        sp = SignaturePair()
        sp.pubKeyPrefix = b''
        sp.ed25519 = signature
        return sp

    def attachSignatureIntoTx(self, txBodyBytes, sigBytes):
        tx = Transaction()
        tx.bodyBytes = txBodyBytes
        tx.sigMap.sigPair.append(self.makeSigPair(sigBytes))

        body = TransactionBody()
        body.ParseFromString(txBodyBytes)
        tid = self.stringifyTransactionID(body.transactionID)
        return tid, tx.SerializeToString()

    @staticmethod
    def fillQueryHeader(qh):
        from utils.hbar_impl.gen.query_header_pb2 import ResponseType
        qh.responseType = ResponseType.ANSWER_ONLY

    def makeReceiptQuery(self, tid):
        from utils.hbar_impl.gen.query_pb2 import Query
        q = Query()
        self.fillQueryHeader(q.transactionGetReceipt.header)
        q.transactionGetReceipt.transactionID.CopyFrom(tid)
        return q

    @staticmethod
    def stringifyAccountID(accountID):
        return f'{accountID.shardNum}.{accountID.realmNum}.{accountID.accountNum}'

    @classmethod
    def stringifyTransactionID(cls, transactionID):
        accountID = transactionID.accountID
        timestamp = transactionID.transactionValidStart
        nanos = str(timestamp.nanos).zfill(9)
        return cls.stringifyAccountID(accountID) + f'-{timestamp.seconds}-{nanos}'

    def makeBalanceQuery(self, accountID):
        from utils.hbar_impl.gen.query_pb2 import Query
        q = Query()
        self.fillQueryHeader(q.transactionGetReceipt.header)
        q.cryptogetAccountBalance.accountID.CopyFrom(self.makeAccountID(accountID))
        return q


def checkStatus(status, message):
    if status in [12, 21]:
        raise NonFinalSendException()
    if status not in [0, 22]:
        print(f'Bad status at {message}, received {status}', flush=True)
        raise TerminalSendException()


class HbarSender:
    def __init__(self, testnet, serializer):
        self.nodeAccountID = '0.0.3'  # both addresses below use this node accountID
        self.nodeAddress = '0.testnet.hedera.com:50211' if testnet else '35.237.200.180:50211'
        self.serializer = serializer

    def sendSpendTx(self, tx):
        tid, receipt = self._sendTx(tx, 'cryptoTransfer')
        tid = self.serializer.stringifyTransactionID(tid)
        return tid

    def sendCreateTx(self, tx):
        tid, receipt = self._sendTx(tx, 'createAccount')
        accountID = self.serializer.stringifyAccountID(receipt.accountID)
        tid = self.serializer.stringifyTransactionID(tid)
        return tid, accountID

    def getTransactionId(self, txBytes):
        tx = Transaction()
        tx.ParseFromString(txBytes)
        body = TransactionBody()
        body.ParseFromString(tx.bodyBytes)
        tid = body.transactionID
        tid = self.serializer.stringifyTransactionID(tid)
        return tid

    def _sendTx(self, txBytes, action):
        tx = Transaction()
        tx.ParseFromString(txBytes)
        body = TransactionBody()
        body.ParseFromString(tx.bodyBytes)

        print(f'About to open channel to {self.nodeAddress}', flush=True)
        with grpc.insecure_channel(self.nodeAddress) as channel:
            stub = utils.hbar_impl.gen.crypto_service_pb2_grpc.CryptoServiceStub(channel)
            tid = body.transactionID
            try:
                response = getattr(stub, action)(tx)  # returns TransactionResponse
                checkStatus(response.nodeTransactionPrecheckCode, 'send tx node response')
            except:
                print(f'Received terminal exception on sending: {format_exc()}', flush=True)
                raise TerminalSendException()

            RETRIES = 2
            for i in range(RETRIES):
                sleep(5)
                response = stub.getTransactionReceipts(self.serializer.makeReceiptQuery(tid))  # return Response
                response = response.transactionGetReceipt
                try:
                    checkStatus(response.header.nodeTransactionPrecheckCode, 'header response code')
                    receipt = response.receipt
                    checkStatus(receipt.status, "receipt status")
                    break
                except NonFinalSendException as e:
                    if i == RETRIES - 1:
                        raise
                    print(f'Got {e}, retrying', flush=True)

            return tid, receipt

    def queryBalance(self, accountID):
        query = self.serializer.makeBalanceQuery(accountID)
        with grpc.insecure_channel(self.nodeAddress) as channel:
            stub = utils.hbar_impl.gen.crypto_service_pb2_grpc.CryptoServiceStub(channel)
            response = stub.cryptoGetBalance(query)
            checkStatus(response.cryptogetAccountBalance.header.nodeTransactionPrecheckCode, 'header response code')
            return response.cryptogetAccountBalance.balance


def withdraw_from_account(fpriv, hd_path, from_address, to_address, amount, memo):
    serializer = HbarSerializer(testnet=False)
    fee = serializer.MAX_FEE
    amount *= serializer.EXP_TINYBARS

    timestamp_seconds = int(time())
    tx_body = serializer.makeSpendTxBody(from_address, timestamp_seconds, to_address, int(amount), fee, memo)

    prv, pub = eddsa_sign.eddsa_derive(fpriv, hd_path)
    sig = eddsa_sign.eddsa_sign(prv, tx_body)

    tx_id, tx_bytes = serializer.attachSignatureIntoTx(tx_body, sig)

    serializer.sender.sendSpendTx(tx_bytes)

if __name__ == "__main__":
    BIP_44_CONSTANT = 44
    HBAR_ASSET_NUM = 3030
    CHANGE = 0
    ADDR_INDEX = 0
    account = 0

    fpriv = ""
    hd_path = f'{BIP_44_CONSTANT}/{HBAR_ASSET_NUM}/{account}/{CHANGE}/{ADDR_INDEX}'
    from_address = ""
    to_address = ""
    amount = 10  # Amount in Tiny Bars
    memo = ""

    withdraw_from_account(fpriv, hd_path, from_address, to_address, amount, memo)
