#!/usr/bin/env python3

import nacl.bindings as sodium
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
import nacl.encoding
import requests
import zmq
import sys
import re
import time
import random
import shutil


context = zmq.Context()
socket = context.socket(zmq.DEALER)
socket.setsockopt(zmq.CONNECT_TIMEOUT, 5000)
socket.setsockopt(zmq.HANDSHAKE_IVL, 5000)
#socket.setsockopt(zmq.IMMEDIATE, 1)

if len(sys.argv) > 1 and any(sys.argv[1].startswith(x) for x in ("ipc://", "tcp://")):
    remote = sys.argv[1]
    del sys.argv[1]
else:
    remote = "ipc://./gyuanx.sock"

curve_pubkey = b''
my_privkey, my_pubkey = b'', b''
if len(sys.argv) > 1 and len(sys.argv[1]) == 64 and all(x in "0123456789abcdefABCDEF" for x in sys.argv[1]):
    curve_pubkey = bytes.fromhex(sys.argv[1])
    del sys.argv[1]
    socket.setsockopt(zmq.CURVE_SERVERKEY, curve_pubkey)
if len(sys.argv) > 1 and len(sys.argv[1]) == 64 and all(x in "0123456789abcdefABCDEF" for x in sys.argv[1]):
    my_privkey = bytes.fromhex(sys.argv[1])
    del sys.argv[1]
    my_pubkey = zmq.utils.z85.decode(zmq.curve_public(zmq.utils.z85.encode(my_privkey)))
    socket.setsockopt(zmq.CURVE_PUBLICKEY, my_pubkey)
    socket.setsockopt(zmq.CURVE_SECRETKEY, my_privkey)

if (not 2 <= len(sys.argv) <= 3
        or any(x in y for x in ("--help", "-h") for y in sys.argv[1:])
        or not all(x in ('BLOCK', 'TX', 'BLINK') for x in sys.argv[1:])):
    print("Usage: {} [ipc:///path/to/sock|tcp://1.2.3.4:5678] [SERVER_CURVE_PUBKEY [LOCAL_CURVE_PRIVKEY]] [BLOCK] [TX|BLINK]\n"
            "  Connects to the given server and waits for new blocks (if BLOCK specified), new mempool transactions of\n"
            "  any type (if TX specified), and/or new blinks (if BLINK specified).  TX and BLINK are mutually exclusive.".format(sys.argv[0]),
            file=sys.stderr)
    sys.exit(1)

beginning_of_time = time.clock_gettime(time.CLOCK_MONOTONIC)

print("Connecting to {}".format(remote), file=sys.stderr)
socket.connect(remote)

last_sub_time = None
def subscribe():
    if 'BLOCK' in sys.argv[1:]:
        socket.send_multipart([b'sub.block', b'_blocksub'])
    if 'TX' in sys.argv[1:]:
        socket.send_multipart([b'sub.mempool', b'_txallsub', b'all'])
    elif 'BLINK' in sys.argv[1:]:
        socket.send_multipart([b'sub.mempool', b'_txblinksub', b'blink'])
    global last_sub_time
    last_sub_time = time.time()

subscribe()

subbed = set()

while True:
    got_msg = socket.poll(timeout=5000)

    if last_sub_time + 60 < time.time():
        subscribe()

    if not got_msg and not subbed:
        print("Connection timed out")
        sys.exit(1)

    if not got_msg:
        continue

    m = socket.recv_multipart()
    if len(m) == 3 and m[0] == b'REPLY' and m[1] in (b'_blocksub', b'_txallsub', b'_txblinksub') and m[2] in (b'OK', b'ALREADY'):
        if m[2] == b'ALREADY':
            continue
        what = 'new blocks' if m[1] == b'_blocksub' else 'new txes' if m[1] == b'_txallsub' else 'new blinks'
        if what in subbed:
            print("Re-subscribed to {} (perhaps the server restarted?)".format(what))
        else:
            subbed.add(what)
            print("Subscribed to {}".format(what))
    elif len(m) == 3 and m[0] == b'notify.mempool':
        print("New TX: {}".format(m[1].hex()))
    elif len(m) == 3 and m[0] == b'notify.block':
        print("New block: Height {}, hash {}".format(int(m[1]), m[2].hex()))
    else:
        print("Received unexpected {}-part message from gyuanxd:".format(len(m)), file=sys.stderr)
        for x in m:
            print("- {}".format(x))
        sys.exit(1)
