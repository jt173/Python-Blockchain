import transaction
from sha256 import sha256

MAX_TX = 500

# TODO:
# Add merkle transactions


def hash256(input: bytearray) -> bytearray:
    return sha256(sha256(input))

class Block:
    def __init__(self, int_block_ver=1, null_int=0):
        # Header

        # All data types in little-endian
        self.block_version = int_block_ver.to_bytes(4, 'little') #4 bytes
        self.previous_hash =  null_int.to_bytes(32, 'little') #32 bytes
        self.merkle_root = null_int.to_bytes(32, 'little') #32 bytes

        # Integers for now
        self.time = 0 #4 bytes
        self.bits = 0 #4 bytes
        n = 0
        self.nonce = n.to_bytes(4, 'little') #4 bytes

        # Transactions
        self.vtx = []

        # Merkle Tree
        self.merkle_tree = []

        # This block's index in the blockchain
        self.index = 0
    
    def is_null(self) -> bool:
        return (self.bits == 0)
    
    def get_index(self) -> int:
        return self.index
    
    def get_hash(self) -> bytearray:
        output = bytearray()
        output.extend(self.block_version)
        output.extend(self.previous_hash)
        output.extend(self.merkle_root)
        output.append(self.time)
        output.append(self.bits)
        output.extend(self.nonce)
        return hash256(output)
    # bug here
    def build_merke_tree(self) -> str:
        self.merkle_tree.clear()

        # Initialize merkle tree
        for tx in self.vtx:
            self.merkle_tree.append(tx.get_hash())

        j = 0
        for size in range(len(self.vtx)):
            while size > 1:
                i = 0
                while i < size:
                    i2 = min(i + 1, size - 1)
                    self.merkle_tree.append(hash256(self.merkle_tree[j + i] + self.merkle_tree[j + i2]))
                    i += 2
            j += size
            size = (size + 1) / 2
        
        return self.merkle_tree[-1]
    
    """
    Functions for interacting with merkle transactions

    def get_merkle_branch(self, index: int) -> list:
        if (not self.merkle_tree):
            self.build_merke_tree()

        merkle_branch = []
        j = 0
        for size in range(len(self.vtx)):
            while size > 1:
                i = min(index ^ 1, size - 1)
                merkle_branch.append(self.merkle_tree[j + i])
                index >>= 1
                j += size
            size = (size + 1) / 2
        
        return merkle_branch
    
    def check_merkle_branch(self, hash: bytearray, merkle_branch: list, index: int) -> str:
        if index == -1:
            return 0
        
        for otherside in merkle_branch:
            if (index & 1):
                hash = hash256(otherside + hash)
            else:
                hash = hash256(hash + otherside)
            index >>= 1
        
        return hash
    """
    # basic checks for block validity
    def check_block(self) -> bool:
        # size limits
        if (not self.vtx or len(self.vtx) > MAX_TX):
            print("check_block(): size limit error")
            return False
        
        # First transaction must be coinbase, rest must not
        if (not self.vtx[0].is_coinbase()):
            print("check_block(): first transaction is not coinbase")
            return False
        for i in range(1, len(self.vtx)):
            if self.vtx[i].is_coinbase():
                print("check_block(): more than one coinbase transaction")
                return False
        
        # Check transactions
        for tx in self.vtx:
            if not tx.check_transaction():
                print("check_block(): check_transaction failed")
                return False
            
        # Check merkle root
        if (self.merkle_root != self.build_merke_tree()):
            print("check_block(): merkle root mismatch")
            return False
        
        return True

    def __str__(self) -> str:
        string = "Block: {}".format(self.get_hash().hex())
        string += "\nVersion: {}\nPrevious Hash: {}\nNonce: {}\nTransactions: \n".format(
            self.block_version.hex(), self.previous_hash.hex(), self.nonce.hex()
        )
        for i in range(len(self.vtx)):
            string += self.vtx[i].__str__()
        return string
    

        


    
