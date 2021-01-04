#!/usr/bin/env python3

# Example script using Python to query and decode and decrypt a .gyuanx address or HF16+ Session address

import requests
import nacl.hash
import nacl.secret
from base64 import b64encode, b32encode
import sys

name = "Jason.gyuanx"
type = 2 # 2 == gyuanxnet, 0 == session

name_hash = nacl.hash.blake2b(name.lower().encode(), encoder=nacl.encoding.RawEncoder)

# Encode name_hash in base64.  The RPC call will also accept hex, if easier.
name_hash_b64 = b64encode(name_hash)

print("Name: {}, hashed+base64: {}".format(name, name_hash_b64.decode()))

# Make the RPC request to some gyuanxd
r = requests.post('http://localhost:22023/json_rpc',
        json={ "jsonrpc": "2.0", "id": "0",
            "method": "lns_resolve", "params": { "type": 2, "name_hash": name_hash_b64 }
        }).json()

if 'result' in r:
    r = r['result']
else:
    raise RuntimeError("LNS request failed: didn't get any result")

# For gyuanxnet addresses and HF16+ session addresses we'll always have an encrypted value and an
# encryption nonce.  (For HF15 Session addresses the nonce can be missing, in which case the
# encryption involves a much more expensive argon2-based calculation; most external code isn't
# expected to support them and existing registration owners should submit an update after HF16 to
# re-store it with the newer encryption format).
if 'encrypted_value' not in r or 'nonce' not in r:
    print("{} does not exist".format(name))
    sys.exit(1)

# Decryption key: another blake2b hash, this time with the first one as the key
decrypt_key = nacl.hash.blake2b(name.lower().encode(), key=name_hash, encoder=nacl.encoding.RawEncoder);

# XChaCha20+Poly1305 decryption:
val = nacl.secret.nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        bytes.fromhex(r['encrypted_value']),
        b'', # no additional data
        bytes.fromhex(r['nonce']),
        decrypt_key
        )

# val will currently be the raw gyuanxnet ed25519 pubkey (32 bytes).  We can convert it to the more
# common gyuanxnet address (which is the same value but encoded in z-base-32) and convert the bytes to
# a string:
val = b32encode(val).decode()

# Python's regular base32 uses a different alphabet, so translate from base32 to z-base-32:
val = val.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "ybndrfg8ejkmcpqxot1uwisza345h769"))

# Base32 is also padded with '=', which isn't used in z-base-32:
val = val.rstrip('=')

# Finally slap ".gyuanx" on the end:
val += ".gyuanx"

print("Result: {}".format(val))
