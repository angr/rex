import logging
from abc import abstractmethod

import archr
from angr import sim_options as so


l = logging.getLogger("rex.CrashTracer")

class NonCrashingInput(Exception):
    pass

class CrashTracerError(Exception):
    pass

class TraceMode:
    DUMB            =   "dumb"
    HALFWAY         =   "halfway"
    FULL_SYMBOLIC   =   "full_symbolic"

remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                  so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES, so.SIMPLIFY_MEMORY_WRITES,
                  so.ALL_FILES_EXIST, so.UNICORN, so.CPUID_SYMBOLIC}
add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
               so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS, so.KEEP_IP_SYMBOLIC}

class CrashTracer:
    def __init__(self, crash, tracer_bow=None, angr_project_bow=None, is_cgc=False):
        """
        :param tracer_bow:          The bow instance to use for tracing operations
        :param angr_project_bow:    The project bow to use, can be used for custom hooks and syscalls
        """
        self.crash = crash
        self.tracer_bow = tracer_bow
        self.angr_project_bow = angr_project_bow
        self.project = None

        # cgc related
        self._is_cgc = is_cgc
        self.cgc_flag_page_magic = None

    @abstractmethod
    def concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None, taint=None):
        """
        generate a concrete trace and maybe core dump
        """
        raise NotImplementedError()

    @abstractmethod
    def create_project(self, target, **kwargs):
        """
        create an angr project
        """
        raise NotImplementedError()

    @abstractmethod
    def create_state(self, target, **kwargs):
        """
        create an initial angr state for later symbolic tracing
        """
        raise NotImplementedError()

    @abstractmethod
    def bootstrap_state(self, state, **kwargs):
        """
        modify the initial angr state for later symbolic tracing
        """
        raise NotImplementedError()

    def _init_angr_project_bow(self, target):
        # pass tracer_bow to datascoutanalyzer to make addresses in angr consistent with those
        # in the analyzer
        if not self.angr_project_bow:
            dsb = archr.arsenal.DataScoutBow(target, analyzer=self.tracer_bow)
            self.angr_project_bow = archr.arsenal.angrProjectBow(target, dsb)

    @staticmethod
    def _channel_to_input_type(channel):
        s = channel.split(":")[0]
        return CrashInputType.STDIN if s == 'stdio' else s

    @staticmethod
    def identify_bad_bytes(crash):
        """
        identify the bad bytes by inspecting constraints in an unconstrained state
        the extracted bad bytes are used to help angrop filter gadgets
        """
        state = crash.state

        bad_bytes = []
        sim_bytes = []

        # in case its a partial IP overwrite
        for i in range(state.project.arch.bytes):
            byte = state.ip.get_byte(i)
            if len(state.solver.eval_upto(byte, 2)) == 2:
                sim_bytes.append(byte)

        # a byte is a bad byte if none of the bytes in
        # the pc can be that byte
        for c in range(0x100):
            if any(state.solver.satisfiable(extra_constraints=[c==x]) for x in sim_bytes):
                continue
            bad_bytes.append(c)
        return bad_bytes

from ..enums import CrashInputType

from .full_tracer import SimTracer
from .halfway_tracer import HalfwayTracer
from .dumb_tracer import DumbTracer
