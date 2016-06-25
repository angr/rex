from rex import pov_fuzzing
import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

import logging
logging.getLogger("rex").setLevel("DEBUG")

crash = "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%X%x%sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
binary = os.path.join(bin_location, "tests/i386/controlled_printf")

pov_fuzzer = pov_fuzzing.Type2CrashFuzzer(binary, crash)

assert any(pov_fuzzer.test_binary() for _ in range(10))

#FIXME dump to colorguard too

#cg = colorguard.ColorGuard(binary, flag_leak)

#nose.tools.assert_true(cg.causes_leak())

#pov = cg.attempt_pov()

#nose.tools.assert_true(_do_pov_test(pov, enable_randomness=False))
