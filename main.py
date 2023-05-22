from node import *
from script import generate_keys, generate_script, hash160


def main():
    network = Node('localhost', 8000)
    keys = generate_keys()
    network.set_keys(keys['pubkey'], keys['privkey'], keys['sig'])
    
    listen_thread = threading.Thread(target=network.start)
    listen_thread.start()

    # Test wallet transaction
    wtx = WalletTx()
    wtx.vout.append(TxOut(500, generate_script(hash160(network.get_public_key()))))
    wtx.vin.append(TxIn())
    wtx.vin[0].script_sig = bytes('Genesis', encoding='utf-8')
    wtx.vin.append(TxIn())
    wtx.vin[1].script_sig = bytes('Genesis2', encoding='utf-8')
    network.add_to_wallet(wtx)

    # Command line interface
    while True:
        val = input("\n(1) View Transactions \n(2) Send Transaction\n(3) Get Balance\n(4) Look at Blocks\n(5) Mine Blocks\n(6) Get Public Key\n(7) Get Address\n")

        if int(val) == 1:
            network.get_transactions()
        elif int(val) == 2:
            amount = input("Enter amount: ")
            addr = input("Enter Address: ")
            print(f'Attempting to send {amount} coins to {addr}')
            network.send_money(addr, int(amount))
        elif int(val) == 3:
            print(network.get_balance())
        elif int(val) == 4:
            network.get_blocks()
        elif int(val) == 5:
            network.miner()
        elif int(val) == 6:
            print(network.get_public_key().hex())
        elif int(val) == 7:
            network.get_address()
        
if __name__ == '__main__':
    main()