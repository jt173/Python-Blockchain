import sys

from sha256 import sha256
from script import compile_script

MAX_SIZE = 0xffffffff


# OutPoint: Output of a previous Transaction
# - Used to take coinds from a previous transaction
class OutPoint:
    def __init__(self, hash_in: bytes = 0, n_in: int = -1):
        self.hash = bytes(hash_in)
        self.n =n_in.to_bytes(4, 'little', signed=True)
    
    def is_null(self) -> bool:
        return (self.hash == 0 and self.n == -1)
    
    def __str__(self) -> str: 
        return "\nTransaction: {} \nOutput: {}\n".format(self.hash.hex(), self.n.hex())
    
    
# Transaction Input: Contains the previous transaction's output it claims
# and a signature that matches the output's public key
class TxIn:
    def __init__(self, hash_previous_tx: bytes = None, prevtx_out: int = None, script_sig_in: bytes = None, 
                 sequence_in: int = MAX_SIZE):
        # Support for "multiple" constructors
        # Constuctor with given values will generate an Outpoint, 
        # else default constructor will only instantiate self.sequence
        if hash_previous_tx is not None and prevtx_out is not None:
            self.prevout = OutPoint(hash_previous_tx, prevtx_out)
        else:
            self.prevout = OutPoint()

        if script_sig_in:
            self.script_sig = script_sig_in
        else:
            self.script_sig = None

        self.sequence = sequence_in.to_bytes(4, 'little')
    
    def is_final(self) -> bool:
        return (self.sequence == MAX_SIZE.to_bytes(4, 'little'))
    
    def __str__(self) -> str:
        return "Outpoint: {}ScriptSig: {}\nSequence: {}\n".format(self.prevout.__str__(), self.script_sig.hex(), 
                                                                 self.sequence.hex())


# Transaction Output: Contains the public key that the next input must be abel to sign with
# to claim it
class TxOut:
    def __init__(self, value_in: int = -1, script_pk_in: bytes = 0):
        self.value = value_in
        self.script_pubkey = bytes(script_pk_in)

    def is_null(self) -> bool:
        return (self.value == -1)
    
    def get_hash(self) -> bytes:
        # Hash: value + size of script pk + script pk
        return self.value + len(self.script_pubkey) + self.script_pubkey
    
    def is_mine(self, public_key: bytes, signature:bytes) -> bool:
        return compile_script(public_key, signature, self.script_pubkey)
    
    def get_credit(self, public_key: bytes, signature:bytes) -> int:
        if self.is_mine(public_key, signature):
            return self.value
        return 0
    
    def __str__(self) -> str:
        return "TxOut: \nValue: {}\nScript Public key: {}\n".format(self.value, self.script_pubkey.hex())
    

# Transaction: Data broadcasted on the network and contained in blocks
class Transaction:
    def __init__(self):
        self.set_null()
    
    def set_null(self):
        self.tx_version = -1
        self.vin = []
        self.vout = []

    def is_null(self) -> bool:
        return (not self.vin and not self.vout)
    
    def is_final(self) -> bool:
        for txin in self.vin:
            if not txin.is_final():
                return False
        return True
    
    # True here means the transaction has no previous output: must be coinbase
    def is_coinbase(self) -> bool:
        return (len(self.vin) == 1 and self.vin[0].prevout.is_null())
    
    # Simple checks for valid transaction
    def check_transaction(self) -> bool:
        if (not self.vin and not self.vout):
            print("check_transaction(): vin or vout empty")
            return False
        
        for txout in self.vout:
            if txout.value < 0:
                print("check_transaction(): txout.value is negative")
                return False
        
        if self.is_coinbase():
            if (len(self.vin[0].script_sig) < 2 or len(self.vin[0].script_sig) > 100):
                print("check_transaction(): coinbase script size error")
                return False
        
        return True
    
    def get_credit(self, public_key: bytes, signature: bytes) -> int:
        credit = 0
        for txout in self.vout:
            credit += txout.get_credit(public_key, signature)
        return credit
    
    def is_mine(self, public_key: bytes, signature: bytes) -> bool:
        for txout in self.vout:
            if txout.is_mine(public_key, signature):
                return True
        return False
    
    def get_value_out(self) -> int:
        value_out = 0
        for txout in self.vout:
            if txout.value < 0:
                raise ValueError("get_value_out(): Negative Value")
            value_out += txout.value
        return value_out
    
    # FIxing this 
    def get_hash(self) -> bytearray:
        # Return the TXID of this transaction
        output = bytearray()
        # Version: 4 bytes
        output.extend(self.tx_version.to_bytes(4, 'little', signed=True))
        # Input Count:
        output.append(len(self.vin))
        # Input(s):
        for i in range(len(self.vin)):
            # TXID: 32 bytes
            output.extend(self.vin[i].prevout.hash)
            # VOUT: 4 bytes
            output.extend(self.vin[i].prevout.n)
            # ScriptSig Size:
            output.append(len(self.vin[i].script_sig))
            # ScriptSig:
            output.extend(self.vin[i].script_sig)
            # Sequence: 4 bytes:
            output.extend(self.vin[i].sequence)
        # Output Count:
        output.append(len(self.vout))
        # Output(s):
        for i in range(len(self.vout)):
            # Value: 8 bytes
            output.extend(self.vout[i].value.to_bytes(8, 'little'))
            # ScriptPubKey Size:
            output.append(len(self.vout[i].script_pubkey))
            # ScriptPubKey
            output.extend(self.vout[i].script_pubkey)
        
        # TXID
        return sha256(sha256(output))

    def accept_transaction(self) -> bool:
        if (not self.check_transaction()):
            print("accept_transaction(): check_transaction() failed")
            return False
        
        hash = self.get_hash()
        print(f'Transaction: {hash.hex()} accepted.')
        return True

    def add_to_memory_pool(self) -> bool:
        pass

    def __str__(self) -> str:
        string = "Transaction: {}\nInputs:\n".format(self.get_hash().hex())
        for i in range(len(self.vin)):
            string += self.vin[i].__str__()
        string += "Outputs: \n"
        for i in range(len(self.vout)):
            string += self.vout[i].__str__()
        return string


# WalletTx: Contains additional data that only the owner cares about
class WalletTx(Transaction):
    def __init__(self):
        Transaction.__init__(self)

        self.from_me = False
        self.spent = False
    
    def accept_wallet_transaction(self) -> bool:
        if not self.is_coinbase():
            return self.accept_transaction()
        return True

    def __str__(self) -> str:
        return super().__str__()
    


