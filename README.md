# Python Blockchain
Mostly an excercise in learning how cryptocurrency blockchains work. 
To run, use the main.py file. To run multiple nodes, copy the contents of this 
directory into another folder and change the port in the Node constructor in the 
main.py file.

The Node class defaults to sending data to 'local_host:8001'. To change this, update
the peer_address in the node.py file.

## Requirements
pip install secp256k1
pip install base58