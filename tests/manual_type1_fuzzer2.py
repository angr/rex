import os
from rex import pov_fuzzing

with open("NRFIN_00075_crash", "rb") as f:
    crash_in = f.read()

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_fuzzer = pov_fuzzing.Type1CrashFuzzer(os.path.join(bin_location, "tests/cgc/NRFIN_00075"), crash=crash_in)
for i in range(10):
    if not pov_fuzzer.test_binary():
        raise Exception("wtf")

