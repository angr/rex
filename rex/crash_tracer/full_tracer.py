import os
import logging

from abc import abstractmethod
from typing import Union, Tuple

import archr
from tracer import TinyCore
from angr import sim_options as so
from archr.analyzers.angr_state import SimArchrMount
from angr.storage.file import SimFileDescriptorDuplex

from . import CrashTracer, CrashTracerError, add_options, remove_options
from ..enums import CrashInputType

l = logging.getLogger("rex.HalfwayTracer")

class SimTracer(CrashTracer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

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