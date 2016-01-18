* State-Aware ROP
    1. state aware rop gadget finder, won't set arguments which are already controlled
    1. can identify libcgc functions which are helpful for chain building

* Improvements
    1. When exploring a crash, start from the same basic block as the original crash instead of retracing the entire input again
    1. call rop func_call with a more controlled returned address in the cases where we can't get to
       an unconstrained successor
    1. detect actual stack smashing more easily to avoid using 'stack changing gadgets' which only do a 'ret'
    1. the fourth argument to CGC's transmit system call can be the address of an writeable page, let's support this
    1. test constraint dependencies between bits when setting registers circumstantially, the current method of bit testing
       doesn't support testing whether null bytes or newlines can exist for example

* Testcases
    1. testcases to test dumped exploit scripts

* Basics
    1. use register trampolines, when calling shellcode see if any registers are pointing to our payload, if so call those registers with gadgets
    1. Need a way of querying if a page is executable
    1. Recover randomness and challenge-response during exploit generation
