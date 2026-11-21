# SPDX-License-Identifier: BSD-2-Clause
"""Stand-in for ssh and scp in tests/test_cilctl.py: records its argv and
stdin to $FAKE_REC as JSON and exits with $FAKE_RC (default 0). With -N,
-L and $FAKE_FWD it is the jump tunnel: it forwards the -L listen port to
127.0.0.1:$FAKE_FWD until it is terminated, its pid in $FAKE_REC.pid."""
import json
import os
import socket
import sys
import threading

argv = sys.argv[1:]
stdin = "" if sys.stdin is None or sys.stdin.isatty() else sys.stdin.read()
with open(os.environ["FAKE_REC"], "w") as f:
    json.dump({"argv": argv, "stdin": stdin}, f)
rc = int(os.environ.get("FAKE_RC", "0"))
if rc or "-N" not in argv or "-L" not in argv or not os.environ.get("FAKE_FWD"):
    sys.exit(rc)

lhost, lport = argv[argv.index("-L") + 1].split(":")[:2]
with open(os.environ["FAKE_REC"] + ".pid", "w") as f:
    f.write(str(os.getpid()))
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((lhost, int(lport)))
srv.listen(8)


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


while True:
    c, _ = srv.accept()
    u = socket.create_connection(("127.0.0.1", int(os.environ["FAKE_FWD"])))
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c), daemon=True).start()
