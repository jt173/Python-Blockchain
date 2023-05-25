from node import *
from gui import *
from script import generate_keys, generate_script, hash160

node = Node('localhost', 8000)
gui = GUI(node)

keys = generate_keys()
node.set_keys(keys['pubkey'], keys['privkey'], keys['sig'])

wtx = WalletTx()
wtx.vout.append(TxOut(500, generate_script(hash160(node.get_public_key()))))
wtx.vin.append(TxIn())
wtx.vin[0].script_sig = bytes('Genesis', encoding='utf-8')
wtx.vin.append(TxIn())
wtx.vin[1].script_sig = bytes('Genesis2', encoding='utf-8')
node.add_to_wallet(wtx)

node.gui = gui

node.start_network()
gui.run()