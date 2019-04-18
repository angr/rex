import os
import archr
import rex


def build_docker():
    os.system('make -C ./hammer_controller')


def test_hammer_controller_rr_tracer():
    try:
        import trraces
    except:
        return

    build_docker()

    t = archr.targets.DockerImageTarget('rex_tests:hammer_controller').build().start()
    tb = archr.arsenal.RRTracerBow(t, local_trace_dir='/tmp/rex_hammer_controller_trace', symbolic_fd=0)

    import logging
    logging.getLogger("angr.exploration_techniques.tracer").setLevel(logging.DEBUG)

    crash = rex.Crash(t, b"\x41"*120 + b'\n', aslr=False, tracer_bow=tb)

    exploit = crash.exploit()
    exploit.arsenal['rop_chess_control'].script()
    exploit.arsenal['rop_chess_control'].script("x2.py")


def test_hammer_controller_qemu_tracer():
    build_docker()

    t = archr.targets.DockerImageTarget('rex_tests:hammer_controller').build().start()
    tb = archr.arsenal.QEMUTracerBow(t)

    import logging
    logging.getLogger("angr.exploration_techniques.tracer").setLevel(logging.DEBUG)

    crash = rex.Crash(t, b"\x41"*120 + b'\n', aslr=False, tracer_bow=tb)

    exploit = crash.exploit()
    exploit.arsenal['rop_chess_control'].script()
    exploit.arsenal['rop_chess_control'].script("x2.py")


def run_all_tests():
    for f_name in globals():
        if f_name.startswith('test_'):
            globals()[f_name]()


if __name__ == '__main__':
    run_all_tests()
