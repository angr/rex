import rex
import angr
import archr
import flaky
from angr.state_plugins.trace_additions import FormatInfoIntToStr, FormatInfoStrToInt

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
cache_location = str(os.path.join(bin_location, 'tests_data/rop_gadgets_cache'))

import logging

def _do_pov_test(pov, enable_randomness=True):
    """ Test a POV """
    for _ in range(10):
        if pov.test_binary(enable_randomness=enable_randomness, timeout=25):
            return True
    return False


def break_chall_resp_atoi():
    crash_input = b'-435982256\n-439864843\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'

    bin_path = bin_location + "/tests/i386/chall_resp_atoi"
    cfg_fast = angr.Project(bin_path, auto_load_libs=False).analyses.CFGFast()
    atoi_addr = cfg_fast.functions["atoi"].addr
    itoa_addr = cfg_fast.functions["itoa"].addr
    f1 = FormatInfoIntToStr(addr=itoa_addr, func_name="itoa", int_arg_num=1, str_dst_num=0, base=10, base_arg=None)
    f2 = FormatInfoStrToInt(addr=atoi_addr, func_name="atoi", str_arg_num=0, base=10, base_arg=None,
                            allows_negative=True)
    crash = rex.Crash(bin_path, crash=crash_input, format_infos=[f1, f2], rop_cache_path=os.path.join(cache_location, "chall_resp_atoi"))
    exploit_f = crash.exploit()
    for e in exploit_f.register_setters:
        assert _do_pov_test(e)
    for e in exploit_f.leakers:
        assert _do_pov_test(e)


def test_chall_response():
    inp = b"\x63\xbd\x66\xfd" + \
          b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
          b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
          b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    path = bin_location + "/tests/cgc/overflow_after_challenge_response2"

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, crash=inp, rop_cache_path=os.path.join(cache_location, "overflow_after_challenge_response2"))
        exploit_f = crash.exploit()
        crash.project.loader.close()

        for e in exploit_f.register_setters:
            assert _do_pov_test(e)
        for e in exploit_f.leakers:
            assert _do_pov_test(e)

@flaky.flaky(3, 1)
def test_chall_resp_rand():
    inp = b" (((" \
          b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
          b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
          b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    path = bin_location + "/tests/cgc/overflow_after_chall_resp_rand"

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, crash=inp, rop_cache_path=os.path.join(cache_location, "overflow_after_chall_resp_rand"))
        exploit_f = crash.exploit()
        crash.project.loader.close()

        for e in exploit_f.register_setters:
            assert _do_pov_test(e)
        for e in exploit_f.leakers:
            assert _do_pov_test(e)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("rex").setLevel("DEBUG")
    logging.getLogger("povsim").setLevel("DEBUG")
    logging.getLogger('archr').setLevel("DEBUG")
    #logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
