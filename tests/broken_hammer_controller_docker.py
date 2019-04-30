import os
import nose
import archr
import rex
import logging
import subprocess

tests_location = os.path.dirname(os.path.realpath(__file__))

def build_docker():
    subprocess.check_call(['make'], cwd=os.path.join(tests_location, 'hammer_controller'))

def test_hammer_controller_rr_tracer():
    try:
        import trraces
    except ImportError:
        raise nose.SkipTest('need trraces')

    build_docker()

    t = archr.targets.DockerImageTarget('rex_tests:hammer_controller').build().start()
    tb = archr.arsenal.RRTracerBow(t, local_trace_dir='/tmp/rex_hammer_controller_trace', symbolic_fd=0)

    crash = rex.Crash(t, b"\x41"*120 + b'\n', aslr=False, tracer_bow=tb)

    exploit = crash.exploit()
    assert 'rop_chess_control' in exploit.arsenal
    exploit.arsenal['rop_chess_control'].script()
    exploit.arsenal['rop_chess_control'].script("x2.py")


def test_hammer_controller_qemu_tracer():
    build_docker()

    t = archr.targets.DockerImageTarget('rex_tests:hammer_controller').build().start()
    tb = archr.arsenal.QEMUTracerBow(t)

    crash = rex.Crash(t, b"\x41"*120 + b'\n', aslr=False, tracer_bow=tb)

    exploit = crash.exploit()
    assert 'rop_chess_control' in exploit.arsenal
    exploit.arsenal['rop_chess_control'].script()
    exploit.arsenal['rop_chess_control'].script("x2.py")


def run_all():
    logging.getLogger("angr.exploration_techniques.tracer").setLevel(logging.DEBUG)
    logging.getLogger("rex").setLevel(logging.DEBUG)

    for f_name in globals():
        if f_name.startswith('test_'):
            try:
                globals()[f_name]()
            except nose.SkipTest:
                pass


if __name__ == '__main__':
    run_all()
