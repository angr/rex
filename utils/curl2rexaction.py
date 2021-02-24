import argparse
import struct
import sys
import os
import time
import signal
import psutil

#from pwn import *
import nclib
#from nclib import Process

VERBOSE = False

parser = argparse.ArgumentParser(description="Translate a bash script full of curl requests to rex actions, assuming the curl commands request 127.0.0.1")
parser.add_argument('script', type=str, help="the path to the bash script")
parser.add_argument('port', type=int, help="which port the curl commands send requests to")

args = parser.parse_args()
port = args.port
script_path = args.script
assert os.path.exists(script_path), "<script> is a bash script"

class TimeoutError(Exception):
    pass

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

r = nclib.Process(["sudo", "nc", "-l", str(port)], verbose=VERBOSE)
p = nclib.Process(script_path, env={"PATH": os.path.dirname(os.path.abspath(__file__))+":"+os.getenv("PATH")}, verbose=VERBOSE)
#print({ "PATH": os.path.dirname(os.path.abspath(__file__))+":"+os.getenv("PATH")})

@timeout(2)
def recv_once(r):
    return r.recv()

def recvall(r):
    data = b''
    while True:
        try:
            data += recv_once(r)
        except Exception as e:
            return data

def force_kill(r):
    r.close()
    proc = psutil.Process(r.pid)
    for child in proc.children():
        os.system("sudo kill -9 %d" % child.pid)
    os.system("sudo kill -9 %d" % r.pid)

# The assumption is curl is blocking, which is the default behavior
requests = []
while p.poll() is None:
    data = recvall(r)
    if data:
        requests.append(data)
    force_kill(r)
    r = nclib.Process(["sudo", "nc", "-l", str(port)])
p.kill()
force_kill(r)

actions = ["RexWaitAction(5)"]
for req in requests:
    open_act = ""
    actions += ["RexOpenChannelAction()", f"RexSendAction({repr(req)})", "RexCloseChannelAction()", "RexWaitAction(1)"]
actions = actions[:-2] + [actions[-1]] # we don't close the last connection but we do wait after exploitation

action_str = "actions = [" + ", ".join(actions) + "]"

print(action_str)

