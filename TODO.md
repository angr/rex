* CGCROP
    1. state aware rop gadget finder, won't set functions which are already controlled
    1. can identify libcgc functions which are helpful for chain building

* Improvements
    1. call rop func_call with a more controlled returned address in the cases where we can't get to
       an unconstrained successor
    1. detect actual stack smashing more easily to avoid using 'stack changing gadgets' which only do a 'ret'

* Testcases
    1. test CGC binaries with known exploitable conditions and make sure they return full_control
