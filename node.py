import socket
import pickle
import threading
import sys

import base58

from script import generate_script, hash160
from sha256 import sha256
from transaction import Transaction, TxIn, TxOut, WalletTx
from block import Block
from blockchain import Blockchain


# Message Types
ADDTX = "ADTX"
ADDBLOCK = "ADBL"
ADDCHAIN = "ADCH"

# Maximum amount of transactions in one block
MAX_TX = 500



class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.connections = []

        # User information
        self.__wallet = {} # Transactions in this Node's wallet: TXID --> WalletTx mapping
        self.__private_key = bytearray()
        self.__public_key = bytearray()
        self.__signature = bytearray()

        # Transactions stored in this Node (memory pool)
        self.transactions = {} # TXID --> Transaction mapping

        # Blockchain stored in this Node
        self.blockchain = Blockchain()

        # Threading locks
        self.wallet_lock = threading.Lock()
        self.tx_lock = threading.Lock()
        self.chian_lock = threading.Lock()

        self.debug = True


# ---- Peer Functions ----

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print(f'Listening on {self.host}:{self.port}...')

        # Main loop
        while True:
            connection, address = self.socket.accept()
            print(f'Received connection from {address[0]}:{address[1]}')
            self.connections.append(connection)

            # Start a new thread to handle the client connection
            client_thread = threading.Thread(target=self.handle_conn, args=(connection,))
            client_thread.start()

    def handle_connection(self, connection):
        while True:
            try:
                # Receive they type of the object being sent
                type_data = connection.recv(4)
                obj_type = type_data.decode()

                data = connection.recv(4096)
                if data:
                    # Deserialize the received object
                    received_object = pickle.loads(data)
                    print(f'Received {obj_type}: {received_object}')
                else:
                    self.connections.remove(connection)
                    print("Client disconnected")
                    break
            except Exception as e:
                print(f'Error: {str(e)}')
                break

    def handle_conn(self, connection):
        while True:
            try:
                # Receive the type of the object being sent
                data_type = connection.recv(4)

                if data_type == ADDTX:
                    self.recv_transaction(connection)
                elif data_type == ADDBLOCK:
                    self.recv_block(connection)
            except Exception as e:
                print(f'Error: {str(e)}')
    
    def send_object(self, peer_address: tuple, obj, obj_type):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(peer_address)

            # Send type
            type_data = obj_type.encode()
            s.sendall(type_data)

            # Serialize and send the object
            data = pickle.dumps(obj)
            s.sendall(data)
            print(f'Sent {obj_type} to {peer_address[0]}:{peer_address[1]}')
        except Exception as e:
            print(f'An error has occured when sending the object: {str(e)}')
        finally:
            s.close()


# ---- Send / Receive Object Functions ----

    # ---- Send / Receive Transactions ----

    def send_transaction(self, tx: Transaction, peer_address: tuple = ('localhost', 8001)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(peer_address)

            # Send message type
            message_type = ADDTX
            s.sendall(message_type)

            # Serialize and send the transaction
            buffer = pickle.dumps(tx)
            s.sendall(buffer)

            if self.debug:
                print(f'Sent transaction {tx.get_hash()} to {peer_address[0]}:{peer_address[1]}')
        
        except Exception as e:
            print(f'Error while sending transaction: {str(e)}')
        finally:
            s.close()

    def recv_transaction(self, connection):
        while True: # Remove this, I beleive
            try:
                # Attempt to receive the transaction
                buffer = connection.recv(4096)
                if buffer:
                    # Deserialize transaction
                    tx = pickle.loads(buffer)

                    # Add new transaction to our memory pool
                    self.add_to_memory_pool(tx)
                    print(f'Transaction: {tx.get_hash()} added to memory pool')
                else:
                    self.connections.remove(connection)
                    print('Client disconnected')
                    break
            except Exception as e:
                print(f'Error while receiving transaction: {str(e)}')

    # --- Send / Receive Blocks ----
    
    def send_block(self, block: Block, peer_address: tuple = ('localhost', 8001)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(peer_address)

            # Send message type
            message_type = ADDBLOCK
            s.sendall(message_type)

            # Serialize and send the block
            buffer = pickle.dumps(block)
            s.sendall(buffer)

            if self.debug:
                print(f'Sent block {block.get_hash()} to {peer_address[0]}:{peer_address[1]}')
        
        except Exception as e:
            print(f'Error while sending block: {str(e)}')
        finally:
            s.close()

    def recv_block(self, connection):
        while True:
            try: 
                # Attempt to receive the block
                buffer = connection.recv(4096)
                if buffer:
                    # Deserialize block
                    block = pickle.loads(buffer)

                    # Try to add to the blockchain stored on this node
                    if not self.blockchain.add_block(block):
                        print(f'recv_block(): Add block {block.get_hash()} to blockchain failed')
                        break
                    
                    print(f'Block: {block.get_hash()} added to blockchain')

                    # Check if any transactions are paying to me
                    # Also check if we have any of these transactions in our memory pool
                    for tx in block.vtx:
                        self.add_to_wallet_if_mine(tx)

                        if self.transactions.get(tx.get_hash()):
                            del self.transactions[tx.get_hash()]
                else:
                    self.connections.remove(connection)
                    print('Client disconnected')
                    break
            except Exception as e:
                print(f'Error while receiving block: {str(e)}')

    # ---- Send / Receive Blockchain
    
    def send_blockchain(self, peer_address: tuple = ('localhost', 8001)):
        # Attempt to automatically send the blockchain stored on this node to new peers
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(peer_address)

            # Serialize and send the blockchain
            buffer = pickle.dumps(self.blockchain)
            s.sendall(buffer)

            if self.debug:
                print(f'Sent blockchain to {peer_address[0]}:{peer_address[1]}')
        
        except Exception as e:
            print(f'Error while sending blockchain: {str(e)}')
        finally:
            s.close()

    def recv_blockchain(self, connection):
        while True:
            try:
                # Attempt to receive the blockchain
                buffer = connection.recv(4096)
                if buffer:
                    # Deserialize the blockchain
                    new_chain = pickle.loads(buffer)

                    # update blockchain
                    self.blockchain = new_chain
                    print("Blockchain updated")
                else:
                    self.connections.remove(connection)
                    print('Client disconnected')
                    break
            except Exception as e:
                print(f'Error while receiving blockchain: {str(e)}')


# ---- Retrieval Functions and Key Setter ----

    def set_keys(self, pubkey: bytearray, privkey: bytearray, sig: bytearray) -> bool:
        self.__public_key = pubkey
        self.__private_key = privkey
        self.__signature = sig

        # Should have this check if each key is the correct amount of bytes long
        if (len(self.__public_key) == 0 or len(self.__private_key) == 0 or len(self.__signature) == 0):
            return False
        
        return True
    
    def get_transactions(self):
        for value in self.transactions.values():
            print(value)

    def get_blocks(self):
        for i in range(len(self.blockchain.chain)):
            print(self.blockchain.chain[i])
        
    def get_balance(self) -> int:
        total = 0
        for it in [*self.__wallet.values()]:
            if (not it.is_final() or it.spent):
                continue
            total += it.get_credit(self.__public_key, self.__signature)
        
        return total
    
    def get_public_key(self) -> bytearray:
        return self.__public_key
    
    def get_address(self) -> None:
        # Temporary function
        #
        # Generates the address, could have this a different function somewhere else
        # and store the address in the Node object, and this function just return the address
        # Only call after keys have been set
        hashed_public_key = hash160(self.__public_key)

        address = bytearray()
        prefix = 0x00
        address.append(prefix)
        address.extend(hashed_public_key)

        # Need to create a copy before attempting to create the checksum
        data = address.copy()

        # Checksum = first four bytes of sha256(sha256(hashed public key))
        hash256 = sha256(sha256(data))
        checksum = hash256[0:4]

        address.extend(checksum)
        encoded_addr = base58.b58encode_check(address)
        print(encoded_addr)
    

# ---- Wallet Functions ----

    def add_to_wallet(self, wtx_in: WalletTx) -> bool:
        hash = wtx_in.get_hash()

        # Insert
        self.__wallet[hash] = wtx_in
        return True
    
    def add_to_wallet_if_mine(self, tx: Transaction) -> bool:
        if tx.is_mine(self.__public_key, self.__private_key):
            wtx = WalletTx(tx)
            return self.add_to_wallet(wtx)
        
        return True
    
    def select_coins(self, target_value: int, set_coins_ret: list) -> bool:
        # Unfinished
        set_coins_ret.clear()

        # List of values lower than the target
        lowest_larger = sys.maxsize
        pcoin_lowest_larger = None
        v_value = [] # List of tuples
        total_lower = 0

        for pcoin in self.__wallet.values():
            if (not pcoin.is_final() or pcoin.spent):
                continue

            n = pcoin.get_credit(self.__public_key, self.__signature)
            if n <= 0:
                continue

            if n < target_value:
                v_value.append((n, pcoin))
                total_lower += n

            elif n == target_value:
                set_coins_ret.append(pcoin)
                return True
            
            elif n < lowest_larger:
                lowest_larger = n
                pcoin_lowest_larger = pcoin

        if total_lower < target_value:
            # Scenario in which we might get change back
    
            if not pcoin_lowest_larger:
                return False

            set_coins_ret.append(pcoin_lowest_larger)
            return True
        


    


# ---- Transaction Functions ----

    def add_to_memory_pool(self, tx: Transaction):
        hash = tx.get_hash()
        self.transactions[hash] = tx
    
    def add_tx(self, tx: Transaction) -> None:
        # Make sure we don't already have it
        hash = tx.get_hash()
        if self.transactions.get(hash):
            print(f'add_tx(): {hash} already exists in the memory pool')
            return
        
        self.add_to_memory_pool(tx)

        # Send Transaction

    def commit_transaction(self, new_tx: WalletTx) -> None:
        # Add tx to wallet
        self.add_to_wallet(new_tx)

        # Mark old coins as spent
        set_coins = []
        
        for txin in new_tx.vin:
            set_coins.append(self.__wallet[txin.prevout.hash]) # fix this 
        
        for pcoin in set_coins:
            pcoin.spent = True

        return True
    
    def create_transaction(self, address: str, amount: int, new_tx: WalletTx) -> bool:
        # address is a string and is given by the user
        # amount is an integer also given by the user
        # both address and amount will be converted to bytes while being added to the transaction

        while True:
            new_tx.vin = []
            new_tx.vout = []
            if amount < 0:
                return False
            
            # amount_out = amount

            set_coins = []
            if not self.select_coins(amount, set_coins):
                print("Select coins failed")
                return False

            amount_in = 0
            for pcoin in set_coins:
                amount_in += pcoin.get_credit(self.__public_key, self.__signature)

            # Fill vout[0] to the payee
            # First, base58 decode the address
            b58_decode = base58.b58decode_check(address)

            # Extract the hashed public key from the decoded base58 bytes
            hashed_pk = b58_decode[1:21]

            # Now generate locking script and append to vout
            new_tx.vout.append(TxOut(amount, generate_script(hashed_pk)))

            # Fill vout[1] back to self if there is any change
            if amount_in > amount:
                script_public_key = generate_script(hash160(self.__public_key))
                new_tx.vout.append(TxOut(amount_in - amount, script_public_key))
            
            # Fill vin
            for pcoin in set_coins:
                for out in range(len(pcoin.vout)):
                    if pcoin.vout[out].is_mine(self.__public_key, self.__signature):
                        # Create vin
                        script_sig = self.__signature + self.__public_key
                        new_tx.vin.append(TxIn(pcoin.get_hash(), out, script_sig))
            break

        return True
    
    def send_money(self, address: str, amount: int) -> None:
        # Address is a string representation of a base58 hash
        wtx = WalletTx()

        # Create and verify the transaction
        if amount < 0:
            print("Send money(): amount vannot be negative")
        
        if amount > self.get_balance():
            print("Send_money(): Amount exceeds your balance")
            return
        
        if not self.create_transaction(address, amount, wtx):
            print("Send_money(): Failed to create transaction")
            return
        
        if not self.commit_transaction(wtx):
            print("Send_money(): Error finalizing transaction")
            return
        
        if not wtx.accept_transaction():
            print("Send money(): Accept_transaction() failed")
            return
        
        # All checks have passed, send the transaction
        self.add_tx(wtx)

    
# ---- Block Functions ----

    def add_block(self, new_block: Block) -> None:
        # Try to add the block to our own blockchain first
        if not self.blockchain.add_block(new_block):
            print("Peer::add_block(): add_block() failed")
            return
        
        # All checks have passed, check if any transactions are paying to me
        for tx in new_block.vtx:
            self.add_to_wallet_if_mine(tx)
        
        # Send block


# ---- Miner ----

    def miner(self):
        print("Miner started")

        # Make sure we have some transactions
        if len(self.transactions) == 0:
            print("No transactions")
            return False
        
        # Create coinbase transaction
        coinbase_tx = WalletTx()

        coinbase_tx.vin.append(TxIn())
        coinbase_tx.vin[0].prevout.set_null()
        coinbase_tx.vin[0].script_sig = bytes('0000', encoding='utf-8')

        coinbase_tx.vout.append(TxOut)
        coinbase_tx.vout[0].value = 50
        coinbase_tx.vout[0].script_pubkey = generate_script(hash160(self.__public_key))

        # Create new block
        new_block = Block()

        # Add coinbase transaction as the first transaction
        new_block.vtx.append(Transaction(coinbase_tx))

        # Collect the current transactions and put them in the block
        dict_block_txes = dict()
        already_added = [len(self.transactions)]
        found_tx = True
        block_size = 0
        
        while found_tx and block_size < MAX_TX:
            found_tx = False
            n = 0
            for tx in self.transactions.values():
                if already_added[n]:
                    continue
                if tx.is_coinbase() or not tx.is_final():
                    continue

                new_block.vtx.append(tx)
                block_size += 1
                already_added[n] = True
                found_tx = True
        
        print("Running miner with {} transactions in block".format(len(new_block.vtx)))

        # Construct block
        new_block.previous_hash = self.blockchain.get_last_block_hash() if len(self.blockchain.chain) else 0
        new_block.merkle_root = new_block.build_merke_tree()
        new_block.index = len(self.blockchain.chain) + 1

        # Mine for the hash
        while True:
            hash = new_block.get_hash()
            if hash[0] == 0x00:
                break
            new_block.nonce += 1
        
        print("Block: {} successfully mined\nAttempting to add block to the blockchain".format(new_block.get_hash()))

        self.add_block(new_block)

        # Clear memory pool
        self.transactions.clear()
        return True


if __name__ == '__main__':
    network = Node('localhost', 8000)
    
    listen_thread = threading.Thread(target=network.start)
    listen_thread.start()

    # Send objects to peers in parallel
    peer_address1 = ('localhost', 8001)
    # Tx to send
    tx_new = Transaction()
    tx_new.vin.append(TxIn())
    tx_new.vin[0].script_sig = bytes('Genesis', encoding='utf-8')
    tx_new.vout.append(TxOut())
    tx_new.vout[0].value = 50
    tx_new.vout[0].script_pubkey = bytes('Genesis', encoding='utf-8')

    ADDTX = "ADDT"
    network.send_object(peer_address1, tx_new, ADDTX)

        
    
