import os
import logging
from typing import Union, Tuple

from tracer import TinyCore
from archr.analyzers.angr_state import SimArchrMount

from . import CrashTracer, add_options, remove_options

l = logging.getLogger(__name__)

class HalfwayTracer(CrashTracer):
    """
    automatically identify where user input is read and then generate coredump from here
    TODO: it's not automated yet, user needs to specify the trace_addr manually
    """
    def __init__(self, crash, trace_addr : Union[int, Tuple[int, int]]=None, **kwargs):
        super().__init__(crash, **kwargs)
        self.trace_addr = trace_addr if type(trace_addr) in {type(None), tuple} else (trace_addr, 1)
        self.trace_bb_addr = None
        self.trace_result = None

    def concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None, taint=None):
        # to enable halfway-tracing, we need to generate a coredump at the wanted address first
        # and use the core dump to create an angr project
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, record_trace=True,
                                 trace_bb_addr=self.trace_addr, crash_addr=self.trace_addr, delay=delay,
                                 pre_fire_hook=pre_fire_hook, actions=actions, record_magic=self._is_cgc, taint=taint)
        # if a coredump is available, save a copy of all registers in the coredump for future references
        assert r.core_path and os.path.isfile(r.core_path)
        tiny_core = TinyCore(r.core_path)
        self.trace_result = r
        return r, tiny_core.registers

    def create_project(self, target, **kwargs):
        l.debug("Loading the halfway core dump @ %s into angr...", self.trace_result.halfway_core_path)
        self._init_angr_project_bow(target)
        project = self.angr_project_bow.fire(core_path=self.trace_result.halfway_core_path)

        project.loader._main_object = project.loader.elfcore_object._main_object
        self.project = project
        return project

    def create_state(self, target, **kwargs):
        self.project.loader._main_object = self.project.loader.elfcore_object
        initial_state = self.project.factory.blank_state(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options)
        self.project.loader._main_object = self.project.loader.elfcore_object._main_object
        self.trace_bb_addr = initial_state.solver.eval(initial_state.regs.pc)
        initial_state.fs.mount('/', SimArchrMount(target))
        return initial_state

    def bootstrap_state(self, state, **kwargs):
        # if we use halfway tracing, we need to reconstruct the sockets
        # as a hack, we trigger the allocation of all sockets
        # FIXME: this should be done properly, maybe let user to provide a hook
        for i in range(3, 10):
            state.posix.open_socket(str(i))
        return state
