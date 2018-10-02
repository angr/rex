import os
import rex
import nose

import logging
l = logging.getLogger("rex").setLevel("DEBUG")
logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
logging.getLogger("angr.simos").setLevel("DEBUG")
logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

def _do_pov_test(pov, enable_randomness=True):
    ''' Test a POV '''
    for _ in range(10):
        if pov.test_binary(enable_randomness=enable_randomness):
            return True
    return False

def test_cromu_00071():
    '''
    Test exploitation of CROMU_00071
    '''

    crash = rex.Crash(os.path.join(bin_location, "tests/cgc/CROMU_00071"), bytes.fromhex("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c"))

    arsenal = crash.exploit()

    nose.tools.assert_equals(len(arsenal.register_setters), 2)

    for exploit in arsenal.register_setters:
        nose.tools.assert_true(_do_pov_test(exploit))

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
