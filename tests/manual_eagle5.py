import rex
with open("/home/salls/Projects/angr/rex/rex/exploit/cgc/derander/crash2.txt", "rb") as f:
   crash_input = f.read()
crash = rex.Crash("/home/salls/Projects/angr/binaries-private/cgc_trials/EAGLE_00005", crash=crash_input)
exploit_f = crash.exploit()
derand = rex.exploit.cgc.derander.Derander(exploit_f.best_type1)
