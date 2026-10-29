import sys
import time

import zmq

kind = sys.argv[1]
context = zmq.Context()
socket = context.socket(getattr(zmq, kind))
socket.setsockopt(zmq.RCVTIMEO, 5000)
socket.setsockopt(zmq.SNDTIMEO, 5000)
socket.setsockopt(zmq.LINGER, 1000)
if kind == "SUB":
    socket.setsockopt(zmq.SUBSCRIBE, b"topic")
if len(sys.argv) == 3:
    endpoint = sys.argv[2]
    socket.connect(endpoint)
else:
    socket.bind("tcp://127.0.0.1:*")
    endpoint = socket.getsockopt_string(zmq.LAST_ENDPOINT)
print(endpoint, flush=True)
message = [b"topic", b"", bytes(range(256)) * 2]
try:
    if kind in ("PULL", "SUB", "REP"):
        assert socket.recv_multipart() == message
        if kind == "REP":
            socket.send_multipart(message)
    elif kind == "PUB":
        for _ in range(20):
            socket.send_multipart([b"other", b"ignored"])
            socket.send_multipart(message)
            time.sleep(0.025)
    else:
        socket.send_multipart(message)
        if kind == "REQ":
            assert socket.recv_multipart() == message
finally:
    socket.close()
    context.term()
