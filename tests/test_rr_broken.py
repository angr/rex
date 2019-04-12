import os
import archr
import rex

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
lib_path = os.path.join(bin_location, "tests/x86_64")
ld_path = os.path.join(lib_path, "ld-linux-x86-64.so.2")
path = os.path.join(lib_path, "../../../rex/tests/example_1.bin")
t = archr.targets.LocalTarget([ld_path, "--library-path", lib_path, path, "passcode", "flag"], path, target_arch='x86_64').build().start()
symb_fd = archr.arsenal.InputFDBow(t)
tb = archr.arsenal.RRTracerBow(t, timeout=999999, symbolic_fd=symb_fd)


#r = tb.fire(save_core=False)

import ipdb; ipdb.set_trace()
crash = rex.Crash(t, b"A"*120, aslr=False, input_type=rex.enums.CrashInputType.TCP, port=8081, tracer_bow=tb)
exploit = crash.exploit()
exploit.arsenal['call_shellcode'].script()
