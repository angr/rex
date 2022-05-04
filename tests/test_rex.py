import os
import random
import subprocess
import sys
import tempfile
import time
import struct
import logging

import archr
import rex
import colorguard
from rex.vulnerability import Vulnerability
from angr.state_plugins.trace_additions import FormatInfoStrToInt, FormatInfoDontConstrain
from rex.exploit.cgc.type1.cgc_type1_shellcode_exploit import CGCType1ShellcodeExploit

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
cache_location = str(os.path.join(bin_location, 'tests_data/rop_gadgets_cache'))
tests_dir = str(os.path.dirname(os.path.realpath(__file__)))


def _do_pov_test(pov, enable_randomness=True):
    ''' Test a POV '''
    for _ in range(10):
        if pov.test_binary(enable_randomness=enable_randomness):
            return True
    return False

def _check_arsenal_has_send(arsenal):
    # Test that the script generated for the arsenal has sends (i.e. is not null)
    for exploit in arsenal.values():
        assert ".send(" in exploit.script()


#
# TODO: this test is not slow, but rather just uses more memory than the travis runner can do
# this is caused by z3's heap fragmentation issues, and was under control until we upgraded
# to z3 4.8.5. using REUSE_Z3_SOLVER will solve the issue but we can't set it just for one test.
# this should be removed when we reduce the amount of solver thrashing that happens in claripy
# or when we move to a test runner with more RAM.
#
def test_legit_00001():
    # Test exploitation of legit_00001 given a good crash.

    inp = bytes.fromhex('1002000041414141414141414141414d41414141414141414141414141414141001041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141412a4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141604141414141414141414102ffffff410080ffff4141410d807f412641414141414141414141414141414141414141413b41415f414141412b41414141417f4141414141412441414141416041f8414141414141c1414139410010000200005541415f4141b9b9b9b1b9d4b9b9b9b99cb99ec4b9b9b941411f4141414141414114414141514141414141414141414141454141494141414141414141404141414141414d414124a0414571717171717171717171717171717171616161616161616161616161616161006161515e41414141412041414141412125414141304141492f41414141492f4141414541412c4141410037373737373737373737414141414141413a41c4b9b9b9b901b9413c41414141414141414141414141412133414141414141412f414141414141414164414141414141414141414141417f41414100010000000055414b4100124141414141414141')
    path = os.path.join(bin_location, "tests/defcon24/legit_00001")

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True,
                                       rop_cache_path=os.path.join(cache_location, 'legit_00001'), use_crash_input=True)

        arsenal = crash.exploit(blacklist_techniques={'rop_set_register', 'rop_leak_memory'})

        assert len(arsenal.register_setters) >= 2
        assert len(arsenal.leakers) >= 1

        for reg_setter in arsenal.register_setters:
            assert _do_pov_test(reg_setter)

        for leaker in arsenal.leakers:
            assert _do_pov_test(leaker)

def test_legit_00003():
    # Test exploration and exploitation of legit_00003.

    inp = b"1\n" + b"A" * 200
    path = os.path.join(bin_location, "tests/defcon24/legit_00003")
    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'legit_00003'))

        assert crash.explorable()
        assert crash.one_of(Vulnerability.WRITE_WHAT_WHERE)

        crash.explore()

        arsenal = crash.exploit(blacklist_techniques={'rop_set_register', 'rop_leak_memory'})

        assert len(arsenal.register_setters) >= 2
        assert len(arsenal.leakers) >= 1

        for reg_setter in arsenal.register_setters:
            assert _do_pov_test(reg_setter)

        for leaker in arsenal.leakers:
            assert _do_pov_test(leaker)

def break_controlled_printf():#L90
    # Test ability to turn controlled format string into Type 2 POV.

    crash = "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%X%x%sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    binary = os.path.join(bin_location, "tests/i386/controlled_printf")
    crash = rex.Crash(binary, crash, rop_cache_path=os.path.join(cache_location, 'controlled_printf'))

    assert crash.one_of(Vulnerability.ARBITRARY_READ)

    flag_leaks = list(crash.point_to_flag())

    assert len(flag_leaks) >= 1

    cg = colorguard.ColorGuard(binary, flag_leaks[0])

    assert cg.causes_leak()

    pov = cg.attempt_pov()

    assert _do_pov_test(pov, enable_randomness=False)


def test_shellcode_placement():

    # Test that shellcode is placed in only executable memory regions.

    inp = b"A" * 272
    path = os.path.join(bin_location, "tests/cgc/shellcode_tester")

    with archr.targets.LocalTarget([path], target_os='cgc').build().start() as target:
        crash = rex.Crash(target, inp, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'shellcode_tester'))

        arsenal = crash.exploit(blacklist_techniques={'rop_leak_memory',
            'rop_set_register', 'circumstantially_set_register'})
        exploit = [e for e in arsenal.register_setters if type(e) is CGCType1ShellcodeExploit][0]

        # make sure the shellcode was placed into the executable heap page
        heap_top = crash.state.solver.eval(crash.state.cgc.allocation_base)
        assert struct.unpack("<I", exploit._raw_payload[-4:])[0] & 0xfffff000 == heap_top
        exec_regions = list(filter(lambda a: crash.state.solver.eval(crash.state.memory.permissions(a)) & 0x4,
            crash.symbolic_mem))

        # should just be two executable regions
        assert len(exec_regions)== 2

        # only executable regions should be that one heap page and the stack, despite having more heap control and global control
        assert sorted(exec_regions) == sorted([0xb7ffb000, 0xbaaaaeec])

def test_boolector_solving():
    # Test boolector's ability to generate the correct values at pov runtime.

    inp = b"A" * 64 * 4
    path = os.path.join(bin_location, "tests/cgc/add_payload")
    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'add_payload'))

        arsenal = crash.exploit(blacklist_techniques={'rop_leak_memory'})

        assert len(arsenal.register_setters) >= 3
        assert len(arsenal.leakers) >= 1

        for reg_setter in arsenal.register_setters:
            assert _do_pov_test(reg_setter)

        for leaker in arsenal.leakers:
            assert _do_pov_test(leaker)

def break_cpp_vptr_smash():#L165
    # Test detection of 'arbitrary-read' vulnerability type, exploration of the crash, and exploitation post-exploration

    crash = b"A" * 512
    crash = rex.Crash(os.path.join(bin_location, "tests/i386/vuln_vptr_smash"),
        crash, rop_cache_path=os.path.join(cache_location, 'vuln_vptr_smash'))

    # this should just tell us that we have an arbitrary-read and that the crash type is explorable
    # but not exploitable
    assert crash.one_of(Vulnerability.ARBITRARY_READ)
    assert not crash.exploitable()
    assert crash.explorable()

    crash.explore()
    # after exploring the crash we should see that it is exploitable
    assert crash.exploitable
    assert crash.state.solver.symbolic(crash.state.regs.pc)

    # let's generate some exploits for it
    arsenal = crash.exploit()

    # make sure we have three register setting exploits (one for each technique)
    assert len(arsenal.register_setters) >= 2

    # make sure we can also generate some leakers, should be rop and shellcode at this point
    assert len(arsenal.leakers) >= 2

    # make sure the test succeeds on every register setter
    for reg_setter in arsenal.register_setters:
        assert _do_pov_test(reg_setter)

    # make sure the test succeeds on every leaker
    for leaker in arsenal.leakers:
        assert _do_pov_test(leaker)

    _check_arsenal_has_send(arsenal)

def test_linux_stacksmash_64():
    # Test exploiting a simple linux 64-bit program with a stack buffer overflow. We should be able to exploit the test binary by
    # ropping to 'system', calling shellcode in the BSS, and calling 'jmpsp' shellcode in the BSS.

    inp = b"A" * 250
    lib_path = os.path.join(bin_location, "tests/x86_64")
    ld_path = os.path.join(lib_path, "ld-linux-x86-64.so.2")
    path = os.path.join(lib_path, "vuln_stacksmash")
    with archr.targets.LocalTarget([ld_path, '--library-path', lib_path, path], path, target_arch='x86_64').build().start() as target:
        crash = rex.Crash(target, crash=inp, fast_mode=True,
            rop_cache_path=os.path.join(cache_location, 'vuln_stacksmash_64'), aslr=False)

        exploit = crash.exploit(blacklist_techniques={'ret2libc'})

        # make sure we're able to exploit it to call shellcode
        assert 'call_shellcode' in exploit.arsenal

        _check_arsenal_has_send(exploit.arsenal)


def test_linux_stacksmash_32():
    # Test exploiting a simple linux program with a stack buffer overflow. We should be able to exploit the test binary by
    # ropping to 'system', calling shellcode in the BSS and calling 'jmpsp' shellcode in the BSS.

    inp = b"A" * 227
    lib_path = os.path.join(bin_location, "tests/i386")
    ld_path = os.path.join(lib_path, "ld-linux.so.2")
    path = os.path.join(lib_path, "vuln_stacksmash")
    with archr.targets.LocalTarget([ld_path, '--library-path', lib_path, path], path, target_arch='i386').build().start() as target:
        crash = rex.Crash(target, inp, fast_mode=True,
            rop_cache_path=os.path.join(cache_location, 'vuln_stacksmash'))

        exploit = crash.exploit(blacklist_techniques={'rop_leak_memory', 'rop_set_register', 'ret2libc'})

        # make sure we're able to exploit it in all possible ways
        assert len(exploit.arsenal) == 3
        assert 'rop_to_system' in exploit.arsenal
        assert 'call_shellcode' in exploit.arsenal
        assert 'call_jmp_sp_shellcode' in exploit.arsenal

        _check_arsenal_has_send(exploit.arsenal)


def test_linux_network_stacksmash_64():
    # Test exploiting a simple network server with a stack-based buffer overflow.
    inp = b'\x00' * 500
    lib_path = os.path.join(bin_location, "tests/x86_64")
    # ld_path = os.path.join(lib_path, "ld-linux-x86-64.so.2")
    path = os.path.join(lib_path, "network_overflow")
    port = random.randint(8000, 9000)
    with archr.targets.LocalTarget([path, str(port)], path,
                                   target_arch='x86_64',
                                   ipv4_address="127.0.0.1",
                                   tcp_ports=(port,)).build().start() as target:
        crash = rex.Crash(target, crash=inp, rop_cache_path=os.path.join(cache_location, 'network_overflow_64'),
            aslr=False,
            input_type=rex.enums.CrashInputType.TCP, port=port)

        exploit = crash.exploit(cmd=b"echo hello", blacklist_techniques={'ret2libc'})

        assert 'call_shellcode' in exploit.arsenal

        _check_arsenal_has_send(exploit.arsenal)

        # let's actually run the exploit

    new_port = random.randint(9001, 10000)
    with archr.targets.LocalTarget([path, str(new_port)],
                                   path,
                                   target_arch='x86_64',
                                   ipv4_address="127.0.0.1",
                                   tcp_ports=(new_port,)).build().start() as new_target:
        try:
            new_target.run_command("")

            # wait for the target to load
            time.sleep(.5)

            temp_script = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
            exploit_location = temp_script.name
            temp_script.close()

            exploit.arsenal['call_shellcode'].script(filename=exploit_location)

            exploit_result = subprocess.check_output(["python", exploit_location,
                                                      "127.0.0.1", str(new_port),
                                                      ], timeout=3)
            assert b"hello" in exploit_result
        finally:
            os.unlink(exploit_location)


def test_cgc_type1_rop_stacksmash():
    # Test creation of type1 exploit on 0b32aa01_01 ('Palindrome') with rop. The vulnerability exposed by the string `crash` is
    # stack buffer overflow. This testcase should exercise rex exploiting stack-based buffer overflows with rop.

    inp = bytes.fromhex("0500ffff80ffffff80f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1ffff80f1f1f1ebf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f100de7fff80ffffff800fffffff7ef3ffffffff7fffff80fffffeff09fefefefefe0a57656c63fe6d6520746f2850616c696e64726f6d65204669776465720a0affffffff80ffffe8800fffffff7f230a")
    path = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'sc1_0b32aa01_01'))
        arsenal = crash.exploit()

        # make sure we can control ecx, edx, ebx, ebp, esi, and edi with rop
        assert len(arsenal.register_setters) >= 3
        assert len(arsenal.leakers) >= 2

        # make sure the test succeeds on every register setter
        for reg_setter in arsenal.register_setters:
            assert _do_pov_test(reg_setter)

        # make sure the test succeeds on every leaker
        for leaker in arsenal.leakers:
            assert _do_pov_test(leaker)


def test_exploit_yielding():
    # Test the yielding of exploits

    inp = bytes.fromhex("0500ffff80ffffff80f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1ffff80f1f1f1ebf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f100de7fff80ffffff800fffffff7ef3ffffffff7fffff80fffffeff09fefefefefe0a57656c63fe6d6520746f2850616c696e64726f6d65204669776465720a0affffffff80ffffe8800fffffff7f230a")
    path = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True, rop_cache_path=os.path.join(cache_location, 'sc1_0b32aa01_01'))

        leakers = 0
        register_setters = 0
        for exploit in crash.yield_exploits():
            leakers += 1 if exploit.cgc_type == 2 else 0
            register_setters += 1 if exploit.cgc_type == 1 else 0
            assert _do_pov_test(exploit)

        # make sure we can generate a few different exploits
        assert register_setters >= 3
        assert leakers >= 2

def _do_arbitrary_transmit_test_for(binary):
    inp = b"A"*0x24
    path = os.path.join(bin_location, binary)

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True,
            rop_cache_path=os.path.join(cache_location, os.path.basename(binary)))
        zp = crash.state.get_plugin("zen_plugin")
        assert len(zp.controlled_transmits) == 1

        flag_leaks = list(crash.point_to_flag())

        assert len(flag_leaks) >= 1

        for ptfi in flag_leaks:
            cg = colorguard.ColorGuard(path, ptfi)
            assert cg.causes_leak()
            pov = cg.attempt_exploit()
            assert pov.test_binary()

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
    crash = rex.Crash(binary, crash, format_infos=format_infos,
        rop_cache_path=os.path.join(cache_location, 'KPRCA_00057_crash'))

    assert crash.one_of(Vulnerability.ARBITRARY_TRANSMIT)

    flag_leaks = list(crash.point_to_flag())

    assert len(flag_leaks) >= 1

    cg = colorguard.ColorGuard(binary, flag_leaks[0])
    cg.causes_leak()
    pov = cg.attempt_pov()

    assert _do_pov_test(pov)

def test_arbitrary_transmit_no_crash():
    # Test our ability to exploit an arbitrary transmit which does not cause a crash

    _do_arbitrary_transmit_test_for("tests/i386/arbitrary_transmit_no_crash")

def test_reconstraining():
    # Test our ability to reconstrain

    inp = b'3\x89111'+b'0'+b'A'*190+b'1'
    path = os.path.join(bin_location, "tests/cgc/PIZZA_00003")

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True,
            rop_cache_path=os.path.join(cache_location, 'PIZZA_00003'))

        ptfi = list(crash.point_to_flag())
        assert len(ptfi) >= 2

        # test point to flag #1
        cg = colorguard.ColorGuard(path, ptfi[0])
        x = cg.attempt_exploit()
        assert x is not None
        assert _do_pov_test(x)

        # test point to flag #2
        cg = colorguard.ColorGuard(path, ptfi[1])
        x = cg.attempt_exploit()
        assert x is not None
        assert _do_pov_test(x)


# FIXME: This test fails non-deterministically, see angr/rex#93
test_reconstraining.speed = "slow"


def test_cromu71():
    inp = b'3&\x1b\x17/\x12\x1b\x1e]]]]]]]]]]]]]]]]]]]]\n\x1e\x7f\xffC^\n'
    path = os.path.join(bin_location, "tests/cgc/simplified_CROMU_00071")

    # create format info for atoi
    format_infos = []
    format_infos.append(FormatInfoStrToInt(0x804C500, "based_atoi_signed_10", str_arg_num=0, base=10,
                                           base_arg=None, allows_negative=True))

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, inp, fast_mode=True,
            rop_cache_path=os.path.join(cache_location, 'simplified_CROMU_00071'))

        # let's generate some exploits for it
        arsenal = crash.exploit(blacklist_techniques={'rop_set_register', 'rop_leak_memory'})

        # make sure it works
        assert _do_pov_test(arsenal.best_type1)

def test_halfway_tracing():
    inp = b'A'*100
    bin_path = os.path.join(bin_location, "tests", "x86_64", "stack_smash")
    with archr.targets.LocalTarget([bin_path], target_arch='x86_64').build().start() as target:
        tracer_opts = {"trace_addr": 0x4005bd}
        crash = rex.Crash(target, inp, fast_mode=True, use_rop=True, trace_mode="halfway", tracer_opts=tracer_opts,
                          rop_cache_path=os.path.join(cache_location, 'halfway_stack_smash'))
        exp = crash.exploit()

        assert 'rop_to_system' in exp.arsenal
        assert 'rop_register_control' in exp.arsenal

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
    logging.getLogger('archr').setLevel('DEBUG')
    #logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
