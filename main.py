import pickle
import os.path

from node import *
from gui import *
from script import generate_keys, generate_script, hash160

def main():

    node = Node('localhost', 8000)

    # Check if theres an existing key file
    # if not, generate new keys and save them
    if os.path.isfile('keys.dat'):
        with open('keys.dat', 'rb') as f:
            keys = pickle.load(f)
            node.set_keys(keys['pubkey'], keys['privkey'], keys['sig'])
            f.close()
    else:
        keys = generate_keys()
        node.set_keys(keys['pubkey'], keys['privkey'], keys['sig'])
        with open('keys.dat', 'wb') as f:
            pickle.dump(keys, f)

    gui = GUI(node)
    node.gui = gui

    # Test transaction

    # Load 
    if os.path.isfile('wallet.dat'):
        node.load_wallet()
    if os.path.isfile('blockchain.dat'):
        node.load_blockchain()

    wtx = WalletTx()
    wtx.vout.append(TxOut(500, generate_script(hash160(node.get_public_key()))))
    wtx.vin.append(TxIn())
    wtx.vin[0].script_sig = bytes('Genesis', encoding='utf-8')
    wtx.vin.append(TxIn())
    wtx.vin[1].script_sig = bytes('Genesis2', encoding='utf-8')
    node.add_to_wallet(wtx)

    node.start_network()
    gui.run()

if __name__ == '__main__':
    main()