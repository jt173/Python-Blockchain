import base58
from sha256 import sha256
from script import generate_keys, hash160



keys = generate_keys()
public_key = keys['pubkey']
hashed_pk = hash160(public_key)
print("Public key hash: {}".format(hashed_pk.hex()))

addr = bytearray()
prefix = 0x00
addr.append(prefix)
addr.extend(hashed_pk)

# Need to create a copy before attempting to create the checksum
# Don't know why
data = addr.copy()

# Checksum = first for bytes of sha256(sha256(hashed public key))
hash256 = sha256(sha256(data))
checksum = hash256[0:4]
print("Checksum: {}".format(checksum.hex()))

addr.extend(checksum)
print(addr.hex())

encoded = base58.b58encode_check(addr)
decoded = base58.b58decode_check(encoded)
print(decoded.hex())
print(type(decoded))
hash = decoded[1:21]
print(hash.hex())