from utils import eddsa_sign
from typing import List, NamedTuple, Set, Callable, Union
import cbor2
import hashlib
import bech32
import requests
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

BIP_44_CONSTANT = 44
ADA_COIN_TYPE = 1815
ADA_TEST_COIN_TYPE = 1
CHANGE_INDEX = 0
CHIMERIC_INDEX = 2
DEFAULT_MIN_ADDRESS_INDEX = 0
DEFAULT_ADDRESS_GAP_POOL = 20
MIN_UTXO_VALUE_ADA_ONLY = 1000000
DEFAULT_NATIVE_TX_FEE = 1000000  # Over-estimate
TX_TTL_SECS = 7200  # 2 Hours


class CardanoToken(NamedTuple):
    name: str
    ticker: str
    amount: int


class CardanoAddress(NamedTuple):
    address: str
    derivation_index: int


class CardanoUTxO(NamedTuple):
    tx_hash: bytes
    index_in_tx: int
    native_amount: int
    tokens: List[CardanoToken]
    belongs_to: CardanoAddress


class CardanoWitness(NamedTuple):
    pub_key: bytes
    sig: bytes


class CardanoBalanceMap:
    def __init__(self):
        self.__dict = dict()

    def increase_balance(self, k: str, v: int) -> None:
        if k in self.__dict:
            self.__dict[k] += v
        else:
            self.__dict[k] = v

    def get_balance_of(self, k: str) -> int:
        if k in self.__dict:
            return self.__dict[k]
        return 0

    def assets(self) -> List[str]:
        keys = []
        for k, v in self.__dict.items():
            keys.append(k)
        return keys

    def size(self) -> int:
        return len(self.__dict)

    def is_empty(self) -> bool:
        return self.size() == 0


class CardanoGQLClient:
    def __init__(self, gql_server_url: str, server_caller: Union[Callable, None]):
        self.__gql_server_url = gql_server_url
        if server_caller is None:
            self.__gql_server_caller = CardanoGQLClient.__default_client_caller
        else:
            self.__gql_server_caller = server_caller


    def get_current_slot(self) -> int:
        query = r'''query { cardano { tip { slotNo } } }'''
        result = self.__gql_server_caller(self.__gql_server_url, query)
        if 'cardano' in result and 'tip' in result['cardano'] and 'slotNo' in result['cardano']['tip']:
            return result['cardano']['tip']['slotNo']
        else:
            raise Exception(f'Bad response from GQL: {result}')

    def submit_tx(self, signed_tx: bytes) -> str:
        query = r'''mutation SendRawTx($rawtx: String!) {submitTransaction(transaction: $rawtx) {hash}}'''
        result = self.__gql_server_caller(self.__gql_server_url, query, {'rawtx': signed_tx.hex()})
        if 'submitTransaction' in result and 'hash' in result['submitTransaction']:
            return result['submitTransaction']['hash']
        else:
            raise Exception(f'Bad response from gql: {result}')

    def get_utxos(self, addresses: List[CardanoAddress], native_only: bool) -> List[CardanoUTxO]:
        query = r'''query utxoSetForAddresses ( $addresses: [String]!) { utxos( where: { address: { _in: $addresses }} ) { address transaction { block { number } } tokens { asset { name ticker } quantity } txHash index value } }'''

        addresses_str_arr = []
        addresses_index_map = dict()
        for address in addresses:
            addresses_str_arr.append(address.address)
            addresses_index_map[address.address] = address.derivation_index

        result = self.__gql_server_caller(self.__gql_server_url, query, {'addresses': addresses_str_arr})

        if 'utxos' not in result:
            raise Exception(f'Bad response from GQL: {result}')

        utxos = []
        for utxo in result['utxos']:
            if 'transaction' in utxo and 'block' in utxo['transaction'] and 'number' in utxo['transaction']['block'] \
                    and 'txHash' in utxo and 'index' in utxo and 'address' in utxo and 'value' in utxo:
                has_tokens = 'tokens' in utxo and (len(utxo['tokens']) > 0)
                if has_tokens and native_only:
                    continue

                utxo_address = utxo['address']
                utxo_tokens = []
                if has_tokens:
                    for token in utxo['tokens']:
                        if 'quantity' in token and 'asset' in token \
                                and 'name' in token['asset'] and 'ticker' in token['asset']:
                            utxo_tokens.append(CardanoToken(
                                token['asset']['name'],
                                token['asset']['ticker'],
                                int(token['quantity'])
                            ))

                utxos.append(CardanoUTxO(
                    bytearray.fromhex(utxo['txHash']),
                    int(utxo['index']),
                    int(utxo['value']),
                    utxo_tokens,
                    CardanoAddress(utxo_address, addresses_index_map[utxo_address])
                ))

        return utxos

    @staticmethod
    def __default_client_caller(gql_server_url: str, query_str: str, params: Union[dict, None] = None):
        gql_client = Client(transport=RequestsHTTPTransport(url=gql_server_url), fetch_schema_from_transport=True)
        return gql_client.execute(gql(query_str), params)

    @staticmethod
    def http_post_request_caller(gql_server_url: str, queryStr: str, params: Union[dict, None] = None):
        return requests.post(
            gql_server_url,
            headers={
                'Content-Type': 'application/json'
            },
            json={
                'query': str(queryStr),
                'params': str(params).replace("\'", "\"") if params else None
            }
        ).json()


class CardanoWallet:
    def __init__(self, fpub: str, account: int, min_address_index: Union[int, None],
                 max_address_index: Union[int, None], gql_client: CardanoGQLClient, mainnet: bool):
        if account < 0:
            raise Exception(f'Invalid account value of {account}')

        self.__fpub = fpub.encode('utf-8')
        self.__account = account
        self.__gql_client = gql_client
        self.__mainnet = mainnet
        self.__addresses = []

        if mainnet:
            self.__coin_type = ADA_COIN_TYPE
        else:
            self.__coin_type = ADA_TEST_COIN_TYPE

        if (min_address_index is None and max_address_index is not None) or \
                (min_address_index is not None and max_address_index is None):
            raise Exception(f'min_address_index and max_address_index should both be None or both have value')

        if min_address_index is None:
            self.__min_address_index = DEFAULT_MIN_ADDRESS_INDEX
        else:
            self.__min_address_index = min_address_index

        if max_address_index is None:
            self.__max_address_index = self.__find_max_address_index(DEFAULT_ADDRESS_GAP_POOL)
        else:
            self.__max_address_index = max_address_index

        if self.__min_address_index < 0 or \
                self.__max_address_index < 0 or \
                self.__max_address_index < self.__min_address_index:
            raise Exception(f'Invalid address indices ({self.__min_address_index}, {self.__max_address_index})')


    def reset_address_index_range(self, address_pool_gap: Union[int, None]) -> [int, int]:
        if address_pool_gap is None:
            address_pool_gap = DEFAULT_ADDRESS_GAP_POOL
        elif address_pool_gap <= 0:
            raise Exception(f'Invalid address_pool_gap value of {address_pool_gap}')
        
        self.__min_address_index = 0
        self.__max_address_index = self.__find_max_address_index(address_pool_gap)
        return self.__min_address_index, self.__max_address_index


    def get_base_address(self, index: int) -> CardanoAddress:
        if index < 0:
            raise Exception(f'Invalid index value of {index}')

        _, stake_pub_key = eddsa_sign.eddsa_derive(
            self.__fpub,
            f'{BIP_44_CONSTANT}/{self.__coin_type}/{self.__account}/{CHIMERIC_INDEX}/{0}'
        )
        
        _, payment_pub_key = eddsa_sign.eddsa_derive(
            self.__fpub,
            f'{BIP_44_CONSTANT}/{self.__coin_type}/{self.__account}/{CHANGE_INDEX}/{index}'
        )

        return CardanoAddress(
            self.__encode_address(
                self.__base_address_bytes_prefix() +
                CardanoWallet.__blake_hash(payment_pub_key) +
                CardanoWallet.__blake_hash(stake_pub_key)
            ),
            index
        )


    def get_enterprise_address(self, index: int) -> CardanoAddress:
        if index < 0:
            raise Exception(f'Invalid index value of {index}')

        _, payment_pub_key = eddsa_sign.eddsa_derive(
            self.__fpub,
            f'{BIP_44_CONSTANT}/{self.__coin_type}/{self.__account}/{CHANGE_INDEX}/{index}'
        )

        return CardanoAddress(
            self.__encode_address(
                self.__payment_address_bytes_prefix() +
                CardanoWallet.__blake_hash(payment_pub_key)
            ),
            index
        )


    def get_account_addresses(self) -> List[CardanoAddress]:
        if len(self.__addresses) > 0:
            return self.__addresses

        addresses = []
        addresses_size = self.__max_address_index + 1

        for i in range(self.__min_address_index, addresses_size):
            addresses.append(self.get_base_address(i))
            addresses.append(self.get_enterprise_address(i))

        self.__addresses = addresses
        return addresses


    def get_balance_for_account(self) -> CardanoBalanceMap:
        return self.__get_balance_for_addresses(
            self.get_account_addresses()
        )


    def do_native_transfer(self, fpriv: str, to_address: str, net_amount: int,
                           fee_amount: Union[int, None]) -> str:
        if net_amount < MIN_UTXO_VALUE_ADA_ONLY:
            raise Exception(f'Amount is lower than dust ({net_amount} < {MIN_UTXO_VALUE_ADA_ONLY})')

        all_utxos = sorted(self.__get_utxos_for_account(), key=lambda u: u.native_amount)
        collected_utxos = []
        collected_native_amount = 0
        if fee_amount is None:
            fee_amount = DEFAULT_NATIVE_TX_FEE

        for utxo in all_utxos:
            if len(utxo.tokens) > 0:
                continue
            collected_utxos.append(utxo)
            collected_native_amount += utxo.native_amount
            if collected_native_amount >= net_amount + fee_amount:
                change_amount = collected_native_amount - net_amount - fee_amount
                if (change_amount == 0) or (change_amount >= MIN_UTXO_VALUE_ADA_ONLY):
                    break

        if collected_native_amount < net_amount + fee_amount:
            raise Exception(f'Insufficient Balance in account ({collected_native_amount} < {net_amount + fee_amount})')

        change_amount = collected_native_amount - net_amount - fee_amount
        if 0 < change_amount < MIN_UTXO_VALUE_ADA_ONLY:
            raise Exception(f'Change output below minimum {change_amount} < {MIN_UTXO_VALUE_ADA_ONLY}')

        change_address = self.get_base_address(0)
        serialized_tx_payload, deserialized_tx_payload = self.__build_tx_payload(
            to_address, net_amount, collected_utxos, change_amount, change_address.address,
            fee_amount, self.__get_ttl()
        )

        signing_payload = CardanoWallet.__get_signing_payload(serialized_tx_payload)
        sigs = self.__sign_tx_payload(fpriv, collected_utxos, signing_payload)
        signed_tx, _ = CardanoWallet.__embed_sigs_in_tx(deserialized_tx_payload, sigs)
        return self.__gql_client.submit_tx(signed_tx)


    def __get_utxos_for_account(self) -> List[CardanoUTxO]:
        return self.__gql_client.get_utxos(
            self.get_account_addresses(), True
        )


    def __find_max_address_index(self, address_pool_gap: int) -> int:
        if address_pool_gap <= 0:
            raise Exception(f'Invalid address_pool_gap value of {address_pool_gap}')

        curr_gap = 0
        curr_address_idx = self.__min_address_index
        while curr_gap < address_pool_gap:
            curr_balance = self.__get_balance_for_addresses([
                self.get_base_address(curr_address_idx),
                self.get_enterprise_address(curr_address_idx)
            ])

            curr_gap = curr_gap + 1 if curr_balance.is_empty() else 0
            curr_address_idx += 1

        max_index = curr_address_idx - address_pool_gap - 1
        if max_index < 0:
            raise Exception(f'Failed to find max index for address_pool_gap of {address_pool_gap} '
                            f'(is the wallet empty?)')

        return max_index


    def __get_balance_for_addresses(self, addresses: List[CardanoAddress]) -> CardanoBalanceMap:
        balances_map = CardanoBalanceMap()
        for utxo in self.__gql_client.get_utxos(addresses, True):
            balances_map.increase_balance('ADA', utxo.native_amount)
            for token in utxo.tokens:
                balances_map.increase_balance(token.name, token.amount)
        return balances_map


    def __get_address_hrp(self) -> str:
        return 'addr' if self.__mainnet else 'addr_test'


    def __encode_address(self, decoded_address: bytes) -> str:
        return bech32.bech32_encode(
            self.__get_address_hrp(),
            bech32.convertbits(decoded_address, 8, 5, True)
        )


    def __decode_address(self, encoded_address: str) -> bytes:
        if f'{self.__get_address_hrp()}1' not in encoded_address:
            raise Exception(f'Address {encoded_address} is invalid (use Shelley-era addresses)')

        _, decoded = bech32.bech32_decode(encoded_address)
        return bytes(bech32.convertbits(decoded, 5, 8, False))


    def __base_address_bytes_prefix(self) -> bytes:
        return bytearray.fromhex('01' if self.__mainnet else '00')
    
    
    def __payment_address_bytes_prefix(self) -> bytes:
        return bytearray.fromhex('61' if self.__mainnet else '60')


    def __get_ttl(self) -> int:
        return self.__gql_client.get_current_slot() + TX_TTL_SECS


    def __build_tx_payload(self, to_address: str, net_amount: int, tx_inputs: List[CardanoUTxO],
                           change_amount: int, change_address: str, fee_amount: int, ttl: int) -> [bytes, dict]:
        inputs_arr = []
        for tx_input in tx_inputs:
            inputs_arr.append([tx_input.tx_hash, tx_input.index_in_tx])

        outputs_arr = [[self.__decode_address(to_address), net_amount]]
        if change_amount > 0:
            outputs_arr.append([self.__decode_address(change_address), change_amount])

        deserialized = {0: inputs_arr, 1: outputs_arr, 2: fee_amount, 3: ttl}
        return cbor2.dumps(deserialized), deserialized


    def __sign_tx_payload(self, fpriv: str, tx_inputs: List[CardanoUTxO], tx_payload: bytes) -> List[CardanoWitness]:
        sigs = []
        for signing_index in CardanoWallet.__get_signing_indices(tx_inputs):
            witness_prv_key, witness_pub_key = eddsa_sign.eddsa_derive(
                fpriv.encode('utf-8'),
                f'{BIP_44_CONSTANT}/{self.__coin_type}/{self.__account}/{CHANGE_INDEX}/{signing_index}'
            )

            witness_sig = eddsa_sign.eddsa_sign(witness_prv_key, tx_payload)
            sigs.append(CardanoWitness(witness_pub_key, witness_sig))

        return sigs


    @staticmethod
    def __get_signing_indices(tx_inputs: List[CardanoUTxO]) -> Set[int]:
        signing_indices = set()
        for tx_input in tx_inputs:
            signing_indices.add(tx_input.belongs_to.derivation_index)
        return signing_indices


    @staticmethod
    def __get_signing_payload(serialized_tx: bytes) -> bytes:
        return CardanoWallet.__blake_hash(serialized_tx, 32)


    @staticmethod
    def __embed_sigs_in_tx(deserialized_tx_payload: dict, sigs: List[CardanoWitness]) -> [bytes, str]:
        witnesses_arr = []
        for sig in sigs:
            witnesses_arr.append([sig.pub_key, sig.sig])
        deserialized = [deserialized_tx_payload, {0: witnesses_arr}, None]
        return cbor2.dumps(deserialized), deserialized


    @staticmethod
    def __blake_hash(payload: bytes, digest_size=28) -> bytes:
        h = hashlib.blake2b(digest_size=digest_size)
        h.update(payload)
        return h.digest()


class CardanoWalletFactory:
    def __init__(self, fpub: str, gql_client: CardanoGQLClient, mainnet: bool = True):
        self.__fpub = fpub
        self.__gql_client = gql_client
        self.__mainnet = mainnet

    def create_by_indices(self, account: int,
                          min_address_index: Union[int, None],
                          max_address_index: Union[int, None]) -> CardanoWallet:
        return CardanoWallet(self.__fpub, account, min_address_index, max_address_index,
                             self.__gql_client, self.__mainnet)

    def create_by_address_pool_gap(self, account: int, address_pool_gap: int) -> CardanoWallet:
        cw = CardanoWallet(self.__fpub, account, 0, 0, self.__gql_client, self.__mainnet)
        cw.reset_address_index_range(address_pool_gap)
        return cw
