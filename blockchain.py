from block import Block
from transaction import Transaction, TxOut, TxIn

class Blockchain:
    def __init__(self):
        self.chain = []
        self.build_genesis_block()

    def get_chain_size(self) -> int:
        return len(self.chain)
    
    def build_genesis_block(self) -> None:
        
        # Genesis Transaction
        tx_new = Transaction()
        tx_new.vin.append(TxIn())
        tx_new.vin[0].script_sig = bytes('Genesis', encoding='utf-8')
        tx_new.vout.append(TxOut())
        tx_new.vout[0].value = 50
        tx_new.vout[0].script_pubkey = bytes('Genesis', encoding='utf-8')

        # Genesis Block
        block = Block()
        block.vtx.append(tx_new)
        block.merkle_root = block.build_merke_tree()

        self.chain.append(block)

    # Search for block by index or hash
    def get_block(self, position: int) -> Block:
        if position <= len(self.chain):
            return self.chain[position]
        else:
            raise ValueError("get_block(): Index out of range")

    def get_block(self, block_hash: str) -> Block:
        for i in range(len(self.chain)):
            if (self.chain[i].get_hash() == block_hash):
                return self.chain[i]
        raise ValueError("get_block(): Hash not found")

    # Basic checks before a block is added to the blockchain
    def add_block(self, cblock: Block) -> bool:
        # Make sure we don't already have it
        hash = cblock.get_hash()
        for i in range(len(self.chain)):
            if self.chain[i].get_hash() == hash:
                print(f"add_block: {hash.hex()} already exists in the blockchain")
                return False
        
        # Check previous block hash
        if cblock.previous_hash != self.get_last_block_hash():
            print("add_block: incorrect previous hash")
            return False
        
        # Check block
        if not cblock.check_block():
            print("add_block(): check_block() failed")
            return False
        
        # Checks have passed
        self.chain.append(cblock)
        print(f"Block: {hash.hex()} added to the blockchain")
        return True

    def get_last_block_hash(self) -> bytearray:
        return self.chain[-1].get_hash()
    

