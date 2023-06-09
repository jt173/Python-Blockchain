import socket
import pickle
import threading
import sys
import tkinter as tk

import base58

from script import generate_script, hash160
from sha256 import sha256
from transaction import Transaction, TxIn, TxOut, WalletTx
from block import Block
from blockchain import Blockchain


# TODO:
# implement a refresh gui function instead of updaing everything manually


# Message Types
ADDTX = "ADTX"
ADDBLOCK = "ADBL"
ADDCHAIN = "ADCH"

# Maximum amount of transactions in one block
MAX_TX = 500

NULL_INT = 0

# Helper functions
def wtx_from_tx(tx: Transaction) -> WalletTx:
    wtx = WalletTx()
    wtx.tx_version = tx.tx_version
    wtx.vin = tx.vin
    wtx.vout = tx.vout

    return wtx

def tx_from_wtx(wtx: WalletTx) -> Transaction:
    tx = Transaction()
    tx.tx_version = wtx.tx_version
    tx.vin = wtx.vin
    tx.vout = wtx.vout

    return tx

class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.connections = []
        self.clients = {}

        # User information
        self.__wallet = {} # Transactions in this Node's wallet: TXID --> WalletTx mapping
        self.__private_key = bytearray()
        self.__public_key = bytearray()
        self.__signature = bytearray()
        self.__address = None

        # Transactions stored in this Node (memory pool)
        self.transactions = {} # TXID --> Transaction mapping

        # Blockchain stored in this Node
        self.blockchain = Blockchain()

        self.debug = True


# ---- Peer Functions ----

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.log_message(f'Listening on {self.host}:{self.port}...')

        # Main loop
        while True:
            client_socket, client_address = self.socket.accept()
            self.log_message(f'Received connection from {client_address[0]}:{client_address[1]}')
            self.connections.append(client_socket)

            # Start a new thread to handle the client connection
            client_thread = threading.Thread(target=self.handle_connection, args=(client_socket,))
            client_thread.start()

            # Check if its the first time the peer connects
            #if client_address not in self.clients:
            #    self.send_blockchain()
            #    self.clients[client_address] = True

    def handle_connection(self, connection):
        while True:
            try:
                # Receive the type of the object being sent
                data_type = connection.recv(4)
                data_type = data_type.decode()

                if data_type == ADDTX:
                    self.recv_transaction(connection)
                elif data_type == ADDBLOCK:
                    self.recv_block(connection)
                elif data_type == ADDCHAIN:
                    self.recv_blockchain(connection)
            except Exception as e:
                self.log_message(f'Error: {str(e)}')

    def start_network(self):
        listen_thread = threading.Thread(target=self.start)
        listen_thread.start()

    def log_message(self, message):
        print(message)
        message = message.strip()
        if message:
            self.gui.text_log.insert(tk.END, message + '\n')
            self.gui.text_log.see(tk.END)


# ---- Send / Receive Object Functions ----

    # ---- Send / Receive Transactions ----

    def send_transaction(self, tx: Transaction, peer_address: tuple = ('localhost', 8001)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(peer_address)

            # Send message type
            message_type = ADDTX.encode()
            s.sendall(message_type)

            # Serialize and send the transaction
            buffer = pickle.dumps(tx)
            s.sendall(buffer)

            if self.debug:
                self.log_message(f'Sent transaction {tx.get_hash().hex()} to {peer_address[0]}:{peer_address[1]}')
        
        except Exception as e:
            self.log_message(f'Error while sending transaction: {str(e)}')
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
                    self.log_message(f'Transaction: {tx.get_hash().hex()} added to memory pool')
                else:
                    self.connections.remove(connection)
                    self.log_message('Client disconnected')
                    break
            except Exception as e:
                self.log_message(f'Error while receiving transaction: {str(e)}')

    # --- Send / Receive Blocks ----
    
    def send_block(self, block: Block, peer_address: tuple = ('localhost', 8001)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(peer_address)

            # Send message type
            message_type = ADDBLOCK.encode()
            s.sendall(message_type)

            # Serialize and send the block
            buffer = pickle.dumps(block)
            s.sendall(buffer)

            if self.debug:
                self.log_message(f'Sent block {block.get_hash().hex()} to {peer_address[0]}:{peer_address[1]}')
        
        except Exception as e:
            self.log_message(f'Error while sending block: {str(e)}')
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
                        self.log_message(f'recv_block(): Add block {block.get_hash().hex()} to blockchain failed')
                        break

                    # Check if any transactions are paying to me
                    # Also check if we have any of these transactions in our memory pool
                    for tx in block.vtx:
                        self.add_to_wallet_if_mine(tx)

                        if self.transactions.get(tx.get_hash()):
                            del self.transactions[tx.get_hash()]
                else:
                    self.connections.remove(connection)
                    self.log_message('Client disconnected')
                    break
            except Exception as e:
                self.log_message(f'Error while receiving block: {str(e)}')

    # ---- Send / Receive Blockchain
    
    def send_blockchain(self, peer_address: tuple = ('localhost', 8001)):
        # Attempt to automatically send the blockchain stored on this node to new peers
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(peer_address)

            # Send message type
            message_type = ADDCHAIN.encode()
            s.sendall(message_type)

            # Serialize and send the blockchain
            buffer = pickle.dumps(self.blockchain)
            s.sendall(buffer)

            if self.debug:
                self.log_message(f'Sent blockchain to {peer_address[0]}:{peer_address[1]}')
        
        except Exception as e:
            self.log_message(f'Error while sending blockchain: {str(e)}')
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
                    self.log_message("Blockchain updated")
                else:
                    self.connections.remove(connection)
                    self.log_message('Client disconnected')
                    break
            except Exception as e:
                self.log_message(f'Error while receiving blockchain: {str(e)}')


# ---- Retrieval Functions and Key Setter ----

    def set_keys(self, pubkey: bytearray, privkey: bytearray, sig: bytearray) -> bool:
        # This function sets the keys and generates the user's address from the set
        # public key
        self.__public_key = pubkey
        self.__private_key = privkey
        self.__signature = sig

        # Should have this check if each key is the correct amount of bytes long
        if (len(self.__public_key) == 0 or len(self.__private_key) == 0 or len(self.__signature) == 0):
            return False
        
        # Generate the address
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
        self.__address = encoded_addr
        
        return True
    
    def get_transactions(self):
        for value in self.transactions.values():
            self.log_message(value)

    def get_blocks(self):
        for i in range(len(self.blockchain.chain)):
            self.log_message(self.blockchain.chain[i])
        
    def get_balance(self) -> int:
        total = 0
        for it in [*self.__wallet.values()]:
            if (not it.is_final() or it.spent):
                continue
            total += it.get_credit(self.__public_key, self.__signature)
        
        return total
    
    def get_public_key(self) -> bytearray:
        return self.__public_key
    
    def get_address(self) -> bytes:
        return self.__address

    def show_wallet(self) -> None:
        for value in self.__wallet.values():
            self.log_message(value)



    

# ---- Wallet Functions ----

    def add_to_wallet(self, wtx_in: WalletTx) -> bool:
        hash = wtx_in.get_hash()

        # Insert
        self.__wallet[hash] = wtx_in

        # Notify GUI 
        if wtx_in.is_mine(self.__public_key, self.__signature):
            self.gui.refresh_wallet('recv', hash, wtx_in.get_value_out())
        else:
            self.gui.refresh_wallet('send', hash, wtx_in.get_value_out())

        self.gui.refresh_balance()   
        
        return True
    
    def add_to_wallet_if_mine(self, tx: Transaction) -> bool:
        if tx.is_mine(self.__public_key, self.__signature):
            wtx = wtx_from_tx(tx)
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

        # Notify UI
        self.gui.refresh_txes(hash, tx.get_value_out())
        
    
    def add_tx(self, tx: Transaction) -> None:
        # Make sure we don't already have it
        hash = tx.get_hash()
        if self.transactions.get(hash):
            self.log_message(f'add_tx(): {hash.hex()} already exists in the memory pool')
            return
        
        self.add_to_memory_pool(tx)

        # Send Transaction
        self.send_transaction(tx)

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
                self.log_message("Select coins failed")
                return False

            amount_in = 0
            for pcoin in set_coins:
                amount_in += pcoin.get_credit(self.__public_key, self.__signature)

            # Fill vout[0] to the payee
            # First, base58 decode the address and check for validity
            try:
                b58_decode = base58.b58decode_check(address)
            except ValueError as ve:
                self.log_message(f'ValueError: address {address} is not valid.')
                return False 

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
            self.log_message("Send money(): amount vannot be negative")
        
        if amount > self.get_balance():
            self.log_message("Send_money(): Amount exceeds your balance")
            return
        
        if not self.create_transaction(address, amount, wtx):
            self.log_message("Send_money(): Failed to create transaction")
            return
        
        if not self.commit_transaction(wtx):
            self.log_message("Send_money(): Error finalizing transaction")
            return
        
        if not wtx.accept_transaction():
            self.log_message("Send money(): Accept_transaction() failed")
            return
        
        # All checks have passed, send the transaction
        self.add_tx(wtx)

        self.gui.refresh_balance()

    
# ---- Block Functions ----

    def add_block(self, new_block: Block) -> None:
        # Try to add the block to our own blockchain first
        if not self.blockchain.add_block(new_block):
            self.log_message('add_block(): add_block() failed')
            return
        
        # Update gui
        self.gui.refresh_blocks(new_block.get_hash(), new_block.get_index())
        
        # All checks have passed, check if any transactions are paying to me
        for tx in new_block.vtx:
            self.add_to_wallet_if_mine(tx)
        
        # Send block
        self.send_block(new_block)


# ---- Miner ----

    def miner(self):
        self.log_message("Miner started")

        # Make sure we have some transactions
        if len(self.transactions) == 0:
            self.log_message("No transactions")
            return False
        
        # Create coinbase transaction
        coinbase_tx = WalletTx()

        coinbase_tx.vin.append(TxIn())
        coinbase_tx.vin[0].script_sig = bytes('0000', encoding='utf-8')

        coinbase_tx.vout.append(TxOut())
        coinbase_tx.vout[0].value = 50
        coinbase_tx.vout[0].script_pubkey = generate_script(hash160(self.__public_key))

        # Create new block
        new_block = Block()

        # Add coinbase transaction as the first transaction
        new_block.vtx.append(tx_from_wtx(coinbase_tx))

        # Collect the current transactions and put them in the block
        for tx in self.transactions.values():
            new_block.vtx.append(tx)
        
        self.log_message(f'Running miner with {len(new_block.vtx)} transactions in block')

        # Construct block
        new_block.previous_hash = self.blockchain.get_last_block_hash() if len(self.blockchain.chain) else NULL_INT.to_bytes(32, 'little')
        new_block.merkle_root = new_block.build_merke_tree()
        new_block.index = len(self.blockchain.chain) + 1

        # Mine for the hash
        self.log_message('Mining...')
        while True:
            hash = new_block.get_hash()
            if hash[0] == 0x00:
                break
    
            # Bug
            nonce = int.from_bytes(new_block.nonce, 'little')
            nonce += 1
            new_block.nonce = nonce.to_bytes(4, 'little')
        
        self.log_message(f'Block: {new_block.get_hash().hex()} successfully mined\nAttempting to add block to the blockchain')

        self.add_block(new_block)

        # Clear memory pool
        self.transactions.clear()
        return True
    

# ---- File I/O ----
    def load_blockchain(self) -> None:
        with open('blockchain.dat') as f:
            loaded_chain = pickle.load(f)
            self.blockchain = loaded_chain

    def save_blockchain(self) -> None:
        with open('blockchain.dat', 'wb') as f:
            pickle.dump(self.blockchain, f)

    def load_wallet(self) -> None:
        with open('wallet.dat') as f:
            loaded_wallet = pickle.load(f)
            self.__wallet = loaded_wallet

    def save_wallet(self) -> None:
        with open('wallet.dat', 'wb') as f:
            pickle.dump(self.__wallet, f)
            



