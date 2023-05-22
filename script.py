from sha256 import sha256
from ripemd160 import ripemd160
from secp256k1 import PrivateKey, PublicKey


# ------- Script library -------


# Test hash for all key functions
test_hash = sha256('Hello, World!')

# Hash160 (RIPEMD160(SHA-256(public key)))
def hash160(data: bytes) -> bytearray:
    return bytearray(ripemd160(sha256(data)))

# Extract the 20 byte hashed public key from the script public key
def extract_pubkey(script_pubkey: bytearray) -> bytearray:
    return script_pubkey[3:23]



# Script generation OPCODE functions


# Duplicate the public key and push it to the stack
def OP_DUP(stack: list) -> None:
    dup = stack[-1]
    stack.append(dup)

# Take the duplicated public key, pass it through the hash160 algorithm,
# and push it to the stack
def OP_HASH160(stack: list) -> None:
    stack_pubkey = stack[-1]
    stack.pop()
    stack_hash = hash160(stack_pubkey)

    stack.append(stack_hash)

# Check that the hash160 on the stack is equal to the hash160 in the script.
def OP_EQUALVERIFY(stack: list, pk_hash: bytearray) -> bool:
    stack_hash = stack[-1]

    if stack_hash == pk_hash:
        stack.pop()
        return True
    else:
        return False

# Check that the signature is valid
def OP_CHECKSIG(stack: list) -> None:
    pubkey = stack.pop()
    sig = stack.pop()
    
    # Initialize new PublicKey() from the pubkey on the stack
    public_key = PublicKey(bytes(pubkey), raw=True)
    # Deserialize the signature on the stack
    raw_sig = public_key.ecdsa_deserialize_compact(sig)

    # bool
    verify = public_key.ecdsa_verify(test_hash, raw_sig)

    stack.append(verify)


# Script Functions


# Returns a P2PKH script (scriptpubkey) using the given hashed public key
def generate_script(hashed_key: bytearray) -> bytearray:
    script_pubkey = bytearray()

    # OP_DUP OP_HASH160 <key> OP_EQUALVERIFY OP_CHECKSIG
    OP_DUP = 0x76
    OP_HASH160 = 0xa9
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xac

    bytes_to_push = len(hashed_key)

    # Append opcodes
    script_pubkey.append(OP_DUP)
    script_pubkey.append(OP_HASH160)
    script_pubkey.append(bytes_to_push)

    # Append hashed key
    script_pubkey.extend(hashed_key)
    script_pubkey.append(OP_EQUALVERIFY)
    script_pubkey.append(OP_CHECKSIG)

    return script_pubkey

# Validates the script, returns bool
def compile_script(public_key: bytearray, signature: bytearray, script_pk: bytearray) -> bool:
    # Size check
    # Must be at least 25 bytes long
    if len(script_pk) < 25:
        print("size error")
        return False
    
    # intialize stack
    stack = []
    stack.append(signature)
    stack.append(public_key)

    # Extract hash
    hash = extract_pubkey(script_pk)

    OP_DUP(stack)
    OP_HASH160(stack)
    if not OP_EQUALVERIFY(stack, hash):
        return False
    
    OP_CHECKSIG(stack)

    if (len(stack) == 1 and stack[-1] == 1):
        return True
    else:
        return False



# Generate a new private key, public key, and signature 
# returns: dict containing the keys
def generate_keys() -> dict:
    # Generate private key
    private_key = PrivateKey()
    # Check for validity
    private_key_der = private_key.serialize()
    assert private_key.deserialize(private_key_der) == private_key.private_key

    # Generate signature
    signature = private_key.ecdsa_sign(test_hash)
    # Verify
    verified = private_key.pubkey.ecdsa_verify(test_hash, signature)
    assert verified

    # Serialize signature
    sig_ser = private_key.ecdsa_serialize_compact(signature)
    # Verify again
    sig_dser = private_key.ecdsa_deserialize_compact(sig_ser)
    verified2 = private_key.pubkey.ecdsa_verify(test_hash, sig_dser)
    assert verified2


    # Generate public key
    public_key = private_key.pubkey
    cpublic_key = public_key.serialize(compressed=True)

    # Check for validity
    public_key2 = PublicKey(cpublic_key, raw=True)
    assert public_key2.serialize() == cpublic_key
    assert public_key2.ecdsa_verify(test_hash, signature)

    keys = dict()
    keys['pubkey'] = cpublic_key
    keys['privkey'] = private_key.private_key
    keys['sig'] = sig_ser

    return keys

    

