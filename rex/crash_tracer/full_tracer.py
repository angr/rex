import os
import logging

import archr
from tracer import TinyCore

from . import CrashTracer, add_options, remove_options

l = logging.getLogger(__name__)

class SimTracer(CrashTracer):
    def __init__(self, crash, **kwargs):
        super().__init__(crash, **kwargs)

    def concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None, taint=None):
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, record_magic=self._is_cgc,
                                 pre_fire_hook=pre_fire_hook, delay=delay, actions=actions, taint=taint)
        # if a coredump is available, save a copy of all registers in the coredump for future references
        assert r.core_path and os.path.isfile(r.core_path)
        tiny_core = TinyCore(r.core_path)
        return r, tiny_core.registers

    def create_project(self, target, **kwargs):
        self._init_angr_project_bow(target)
        self.project = self.angr_project_bow.fire()
        return self.project

    def create_state(self, target, **kwargs):
        state_bow = archr.arsenal.angrStateBow(target, self.angr_project_bow)
        initial_state = state_bow.fire(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options,
        )
        return initial_state

    def bootstrap_state(self, state, **kwargs):
        return state
