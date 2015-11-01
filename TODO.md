* State-Aware ROP
    1. state aware rop gadget finder, won't set arguments which are already controlled
    1. can identify libcgc functions which are helpful for chain building

* Improvements
    1. call rop func_call with a more controlled returned address in the cases where we can't get to
       an unconstrained successor
    1. detect actual stack smashing more easily to avoid using 'stack changing gadgets' which only do a 'ret'
    1. the fourth argument to CGC's transmit system call can be the address of an writeable page, let's support this

* Testcases
    1. testcases to test dumped exploit scripts

* Basics
    1. Generate Type 2 exploits for binaries
    1. use register trampolines, when calling shellcode see if any registers are pointing to our payload, if so call those registers with gadgets
    1. Need a way of querying if a page is executable
    1. Recover randomness and challenge-response during exploit generation
