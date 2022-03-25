import os

import archr
import rex

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
cache_location = str(os.path.join(bin_location, 'tests_data/rop_gadgets_cache'))


def test_write_what_where_shadowstack():

    # Test that our write what where exploit can leak, and works in the presence of a shadowstack
    inp = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    path = os.path.join(bin_location, "tests/cgc/write_what_where_shadow_stack")

    with archr.targets.LocalTarget([path], target_os='cgc') as target:
        crash = rex.Crash(target, crash=inp, rop_cache_path=os.path.join(cache_location,
            "write_what_where_shadow_stack"))
        arsenal = crash.exploit()
        crash.project.loader.close()

        exploit = arsenal.best_type2
        assert exploit.test_binary()


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    import sys
    import logging
    logging.getLogger('rex').setLevel('DEBUG')
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
