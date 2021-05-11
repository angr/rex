import argparse
import os
import time
import signal
import psutil

import nclib
from rex.exploit.actions import RexWaitAction, RexOpenChannelAction, RexSendAction, RexCloseChannelAction


def timeout(seconds_before_timeout):
    def decorate(f):
        def handler(signum, frame):
            raise TimeoutError("Timeout!")
        def new_f(*args, **kwargs):
            old = signal.signal(signal.SIGALRM, handler)
            old_time_left = signal.alarm(seconds_before_timeout)
            if 0 < old_time_left < seconds_before_timeout: # never lengthen existing timer
                signal.alarm(old_time_left)
            start_time = time.time()
            try:
                result = f(*args, **kwargs)
            finally:
                if old_time_left > 0: # deduct f's run time from the saved timer
                    old_time_left -= int(time.time() - start_time)
                signal.signal(signal.SIGALRM, old)
                signal.alarm(old_time_left)
            return result
        return new_f
    return decorate

@timeout(2)
def recv_once(r):
    return r.recv()

def recvall(r):
    data = b''
    while True:
        try:
            data += recv_once(r)
        except Exception: #pylint:disable=broad-except
            return data

def force_kill(r):
    r.close()
    proc = psutil.Process(r.pid)
    for child in proc.children():
        os.system("kill -9 %d" % child.pid)
    os.system("kill -9 %d" % r.pid)


def script2rexactions(script_path, ip="127.0.0.1", port=8000, VERBOSE=False):
    assert os.path.isfile(script_path), f"{script_path} does not exist."

    if not script_path[0] == os.path.sep:
        script_path = "./" + script_path

    r = nclib.Process(["nc", "-l", ip, str(port)], verbose=VERBOSE)
    p = nclib.Process([script_path, ip, str(port)],
                      env={
                          "PATH": os.path.dirname(os.path.abspath(__file__)) + ":" + os.getenv("PATH"),
                          "TERM": "linux",
                          "TERMINFO": "/etc/terminfo",
                      },
                      verbose=VERBOSE,
                      )
    # print({ "PATH": os.path.dirname(os.path.abspath(__file__))+":"+os.getenv("PATH")})

    # The assumption is curl is blocking, which is the default behavior
    requests = []
    while p.poll() is None:
        data = recvall(r)
        if data:
            requests.append(data)
        force_kill(r)
        r = nclib.Process(["nc", "-l", ip, str(port)], verbose=VERBOSE)
    p.kill()
    force_kill(r)

    actions = [RexWaitAction(2)]
    for req in requests:
        actions += [
            RexOpenChannelAction(),
            RexSendAction(req),
            RexCloseChannelAction(),
            RexWaitAction(1)
        ]
    actions = actions[:-2] + [actions[-1]]  # we don't close the last connection but we do wait after exploitation
    return actions


def main():
    VERBOSE = False

    parser = argparse.ArgumentParser(description="Translate a bash script full of curl requests to rex actions.")
    parser.add_argument('script', type=str, help="the path to the bash script")
    parser.add_argument("--ip", type=str, help="the IP that the script sends requests to", default="127.0.0.1")
    parser.add_argument('--port', type=int, help="which port the script sends requests to", default=8000)

    args = parser.parse_args()
    ip = args.ip
    port = args.port
    script_path = args.script

    actions = script2rexactions(script_path, ip=ip, port=port, VERBOSE=VERBOSE)
    print(actions)


if __name__ == "__main__":
    main()
