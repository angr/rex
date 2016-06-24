from rex import pov_fuzzing

with open("/home/salls/Projects/angr/rex/rex/pov_fuzzing/NRFIN_00075_crash", "rb") as f:
    crash_in = f.read()

pov_fuzzer = pov_fuzzing.Type1CrashFuzzer("/home/salls/Projects/angr/binaries-private/cfe_original/NRFIN_00075/NRFIN_00075", crash=crash_in)
for i in range(10):
    if not pov_fuzzer.test_binary():
        raise Exception("wtf")

