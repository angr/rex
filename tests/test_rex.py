import rex
from rex.vulnerability import Vulnerability
import nose

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))

CGC_HEADER = "7f43 4743 0101 0143 014d 6572 696e 6f00".replace(" ","").decode('hex')

def test_cpp_vptr_smash():
    '''
    Test detection of 'arbitrary-read' vulnerability type. (that's it... for now)
    '''

    crash = "A" * 300
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/vuln_vptr_smash"), crash)

    nose.tools.assert_equal(crash.crash_type, Vulnerability.ARBITRARY_READ)
    nose.tools.assert_false(crash.exploitable())

def test_linux_stacksmash():
    '''
    Test exploiting a simple linux program with a stack buffer overflow. We should be able to exploit the test binary by
    ropping to 'system', calling shellcode in the BSS and calling 'jmpsp' shellcode in the BSS.
    '''

    crash = "A" * 227
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/vuln_stacksmash"), crash)
    exploit = crash.exploit()

    # make sure we're able to exploit it in all possible ways
    nose.tools.assert_equal(len(exploit.arsenal), 3)
    nose.tools.assert_true('rop_to_system' in exploit.arsenal)
    nose.tools.assert_true('call_shellcode' in exploit.arsenal)
    nose.tools.assert_true('call_jmp_sp_shellcode' in exploit.arsenal)

    # TODO test exploit with pwntool's 'process'

def test_cgc_type1_rop_stacksmash():
    '''
    Test creation of type1 exploit on 0b32aa01_01 ('Palindrome') with rop. The vulnerability exposed by the string `crash` is
    stack buffer overflow. This testcase should exercise rex exploiting stack-based buffer overflows with rop.
    '''

    crash = "0500ffff80ffffff80f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1ffff80f1f1f1ebf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f100de7fff80ffffff800fffffff7ef3ffffffff7fffff80fffffeff09fefefefefe0a57656c63fe6d6520746f2850616c696e64726f6d65204669776465720a0affffffff80ffffe8800fffffff7f230a"

    crash = rex.Crash(os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01"), crash.decode('hex'))
    exploit = crash.exploit()

    # make sure we can control ecx, edx, ebx, ebp, esi, and edi with rop
    nose.tools.assert_true(exploit.can_control('ecx'))
    nose.tools.assert_true(exploit.can_control('edx'))
    nose.tools.assert_true(exploit.can_control('ebx'))
    nose.tools.assert_true(exploit.can_control('ebp'))
    nose.tools.assert_true(exploit.can_control('esi'))
    nose.tools.assert_true(exploit.can_control('edi'))
    nose.tools.assert_true(exploit.can_control('eax'))
    nose.tools.assert_true(exploit.can_control('esp'))

    # make sure our ecx chain actually works (ecx is chosen arbitrarily)
    ecx_exploit = exploit.register_setters['ecx']

    c_str = ecx_exploit._chain.payload_str(constraints=(ecx_exploit._value_var==0x50495a41))
    c_bvv = ecx_exploit.crash.state.se.BVV(c_str)

    c_mem = ecx_exploit.crash.state.memory.load(ecx_exploit._chain_addr, len(c_str))
    ecx_exploit.crash.state.add_constraints(c_mem == c_bvv)

    exploited_state = ecx_exploit._windup_state(ecx_exploit.crash.state)

    # make sure there is only one possibility for ecx at this point
    exploited_ecx_vals = exploited_state.se.any_n_str(exploited_state.regs.ecx, 2)
    nose.tools.assert_true(len(exploited_ecx_vals) == 1)

    ecx_val = exploited_ecx_vals[0]
    nose.tools.assert_equal(ecx_val, "PIZA")

    # TODO test circumstantial and shellcode setters

    # make sure our leaker exploits writes out the contents
    leaker_exploit = exploit.best_type2

    # leak the memory at the binary's base address
    c_str = leaker_exploit._chain.payload_str(constraints=(leaker_exploit._addr_var==0x8048000))
    c_bvv = leaker_exploit.crash.state.se.BVV(c_str)

    c_mem = leaker_exploit.crash.state.memory.load(leaker_exploit._chain_addr, len(c_str))
    leaker_exploit.crash.state.add_constraints(c_mem == c_bvv)

    exploited_state = leaker_exploit._windup_state(leaker_exploit.crash.state, to_syscall=True)
    exploited_state.add_constraints(exploited_state.regs.eax == 2)
    exploited_state.add_constraints(exploited_state.regs.ebx == 1)
    exploited_state.add_constraints(exploited_state.regs.ecx == 0x8048000)
    exploited_state.add_constraints(exploited_state.regs.edx == 0x1000)
    exploited_state.add_constraints(exploited_state.regs.esi == 0)

    ss = leaker_exploit._windup_state(exploited_state)

    leaked = ss.posix.dumps(1)
    leak_start = leaked.find("\x7fCGC")
    leaked_header = leaked[leak_start:leak_start+0x10]
    nose.tools.assert_equals(leaked_header, CGC_HEADER)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
