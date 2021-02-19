import os
import logging

from abc import abstractmethod
from typing import Union, Tuple

import archr
from tracer import TinyCore
from angr import sim_options as so
from archr.analyzers.angr_state import SimArchrMount

l = logging.getLogger("rex.CrashTracer")

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
    def __init__(self, tracer_bow=None, angr_project_bow=None):
        """
        :param tracer_bow:          (deprecated)The bow instance to use for tracing operations
        :param angr_project_bow:    The project bow to use, can be used for custom hooks and syscalls
        """
        self.tracer_bow = tracer_bow
        self.angr_project_bow = angr_project_bow
        self.project = None

    @abstractmethod
    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0):
        """
        generate a concrete trace and maybe core dump
        """
        raise NotImplementedError()

    @abstractmethod
    def _create_project(self, target, **kwargs):
        """
        create an angr project
        """
        raise NotImplementedError()

    @abstractmethod
    def _create_state(self, target, **kwargs):
        """
        create an initial angr state for later symbolic tracing
        """
        raise NotImplementedError()

    @abstractmethod
    def _bootstrap_state(self, state, **kwargs):
        """
        create an initial angr state for later symbolic tracing
        """
        raise NotImplementedError()

    def _init_angr_project_bow(self, target):
        # pass tracer_bow to datascoutanalyzer to make addresses in angr consistent with those
        # in the analyzer
        if not self.angr_project_bow:
            dsb = archr.arsenal.DataScoutBow(target, analyzer=self.tracer_bow)
            self.angr_project_bow = archr.arsenal.angrProjectBow(target, dsb)

class SimTracer(CrashTracer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0):
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True,
                                 pre_fire_hook=pre_fire_hook)

        # if a coredump is available, save a copy of all registers in the coredump for future references
        assert r.core_path and os.path.isfile(r.core_path)
        tiny_core = TinyCore(r.core_path)
        return r, tiny_core.registers

    def _create_project(self, target, **kwargs):
        self._init_angr_project_bow(target)
        self.project = self.angr_project_bow.fire()
        return self.project

    def _create_state(self, target, **kwargs):
        state_bow = archr.arsenal.angrStateBow(target, self.angr_project_bow)
        initial_state = state_bow.fire(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options,
        )
        return initial_state

    def _bootstrap_state(self, state, **kwargs):
        return state

class HalfwayTracer(CrashTracer):
    def __init__(self, trace_addr : Union[int, Tuple[int, int]]=None, **kwargs):
        super().__init__(**kwargs)
        self.trace_addr = trace_addr if type(trace_addr) in {type(None), tuple} else (trace_addr, 1)
        self.trace_bb_addr = None
        self.trace_result = None
        self.elfcore_obj = None # this is for the main_object swap hack

    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0):
        # to enable halfway-tracing, we need to generate a coredump at the wanted address first
        # and use the core dump to create an angr project
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, record_trace=True,
                                 trace_bb_addr=self.trace_addr, crash_addr=self.trace_addr, delay=delay,
                                 pre_fire_hook=pre_fire_hook)

        # if a coredump is available, save a copy of all registers in the coredump for future references
        assert r.core_path and os.path.isfile(r.core_path)
        tiny_core = TinyCore(r.core_path)
        self.trace_result = r
        return r, tiny_core.registers

    def _create_project(self, target, **kwargs):
        l.debug("Loading the core dump @ %s into angr...", self.trace_result.core_path)
        self._init_angr_project_bow(target)
        project = self.angr_project_bow.fire(core_path=self.trace_result.core_path)

        self.elfcore_obj = project.loader.main_object
        project.loader.main_object = project.loader.main_object._main_object
        self.project = project
        return project

    def _create_state(self, target, **kwargs):
        self.project.loader.main_object = self.elfcore_obj
        initial_state = self.project.factory.blank_state(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options)
        self.project.loader.main_object = self.project.loader.main_object._main_object
        self.trace_bb_addr = initial_state.solver.eval(initial_state.regs.pc)
        initial_state.fs.mount('/', SimArchrMount(target))
        return initial_state

    def _bootstrap_state(self, state, **kwargs):
        # if we use halfway tracing, we need to reconstruct the sockets
        # as a hack, we trigger the allocation of all sockets
        # FIXME: this should be done properly, maybe let user to provide a hook
        for i in range(3, 10):
            state.posix.open_socket(str(i))
        return state

class DumbTracer(CrashTracer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)