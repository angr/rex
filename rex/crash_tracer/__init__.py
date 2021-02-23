import os
import logging

from abc import abstractmethod
from typing import Union, Tuple

import archr
from tracer import TinyCore
from angr import sim_options as so
from archr.analyzers.angr_state import SimArchrMount
from angr.storage.file import SimFileDescriptorDuplex

from ..enums import CrashInputType

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
    def __init__(self, tracer_bow=None, angr_project_bow=None, is_cgc=False):
        """
        :param tracer_bow:          (deprecated)The bow instance to use for tracing operations
        :param angr_project_bow:    The project bow to use, can be used for custom hooks and syscalls
        """
        self.tracer_bow = tracer_bow
        self.angr_project_bow = angr_project_bow
        self.project = None

        # cgc related
        self._is_cgc = is_cgc
        self.cgc_flag_page_magic = None

    @abstractmethod
    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None):
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
        return channel.split(":")[0]

class SimTracer(CrashTracer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None):
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, record_magic=self._is_cgc,
                                 pre_fire_hook=pre_fire_hook, delay=delay, actions=actions)
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

    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None):
        # to enable halfway-tracing, we need to generate a coredump at the wanted address first
        # and use the core dump to create an angr project
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, record_trace=True,
                                 trace_bb_addr=self.trace_addr, crash_addr=self.trace_addr, delay=delay,
                                 pre_fire_hook=pre_fire_hook, actions=actions, record_magic=self._is_cgc)
        # if a coredump is available, save a copy of all registers in the coredump for future references
        assert r.core_path and os.path.isfile(r.core_path)
        tiny_core = TinyCore(r.core_path)
        self.trace_result = r
        return r, tiny_core.registers

    def _create_project(self, target, **kwargs):
        l.debug("Loading the core dump @ %s into angr...", self.trace_result.core_path)
        self._init_angr_project_bow(target)
        project = self.angr_project_bow.fire(core_path=self.trace_result.core_path)

        project.loader.main_object = project.loader.elfcore_object._main_object
        self.project = project
        return project

    def _create_state(self, target, **kwargs):
        self.project.loader.main_object = self.project.loader.elfcore_object
        initial_state = self.project.factory.blank_state(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options)
        self.project.loader.main_object = self.project.loader.elfcore_object._main_object
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
    """
    automatically identify accept library call and then generate coredump from here
    FIXME: assumption: the target can be fired multiple times with the same behavior
    FIXME: assumption: the trace is not insanely long. But in reality, it can be.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.trace_result = None
        self.crash_addr = None
        self.testcase = None
        self.channel = None

    def _identify_crash_addr(self, testcase, channel, pre_fire_hook, delay=0, actions=None):
        """
        run the target once to identify crash_addr
        """
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=False, delay=delay,
                                 pre_fire_hook=pre_fire_hook, record_trace=True, actions=actions,
                                 record_magic=self._is_cgc)
        if not r.crashed:
            raise CrashTracerError("The target is not crashed inside QEMU!")
        return r.trace[-1]

    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None):
        """
        identify the crash location and then generate a coredump before crashing
        """
        self.crash_addr = self._identify_crash_addr(testcase, channel, pre_fire_hook,
                                                    delay=delay, actions=actions)
        l.info("DumbTracer identified the crash_addr @ %#x", self.crash_addr)

        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, delay=delay,
                                 trace_bb_addr=(self.crash_addr, 1), crash_addr=(self.crash_addr, 1),
                                 pre_fire_hook=pre_fire_hook, record_trace=True, actions=actions)
        self.trace_result = r
        self.testcase = testcase
        self.channel = channel

        # if a coredump is available, save a copy of all registers in the coredump for future references
        assert r.core_path and os.path.isfile(r.core_path)
        tiny_core = TinyCore(r.core_path)
        return r, tiny_core.registers

    def _create_project(self, target, **kwargs):
        l.debug("Loading the core dump @ %s into angr...", self.trace_result.core_path)
        self._init_angr_project_bow(target)
        project = self.angr_project_bow.fire(core_path=self.trace_result.core_path)

        project.loader.main_object = project.loader.elfcore_object._main_object
        self.project = project
        return project

    def _create_state(self, target, **kwargs):
        initial_state = self.project.factory.blank_state(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options)
        self.project.loader.main_object = self.project.loader.elfcore_object._main_object
        initial_state.fs.mount('/', SimArchrMount(target))
        return initial_state

    def _bootstrap_state(self, state, **kwargs):
        """
        perform analysis to input-state correspondence and then add the constraints in the state
        """
        word_size = self.project.arch.bytes
        marker_size = word_size * 3 # the minimal amount of gadgets to be useful

        # we operate on concrete memory so far, so it is safe to load and eval concrete memory
        data = state.solver.eval(state.memory.load(state.regs.sp, 0x100), cast_to=bytes)

        # identify marker from the original input on stack
        for i in range(0, len(data), marker_size):
            marker = data[i:i+marker_size]
            if marker in self.testcase:
                break
        else:
            raise CrashTracerError("Fail to identify marker from the original input")
        controlled_addr = state.regs.sp + i
        marker_idx = self.testcase.index(marker)
        assert self.testcase.count(marker) == 1, "The input should have high entropy, cyclic is recommended"

        # search for the max length of the controlled data
        data = state.solver.eval(state.memory.load(controlled_addr, 0x200), cast_to=bytes)
        assert data[:marker_size] == self.testcase[marker_idx:marker_idx+marker_size]
        for max_len in range(marker_size, len(data), word_size):
            if data[:max_len] != self.testcase[marker_idx:marker_idx+max_len]:
                max_len -= word_size
                break

        # only support network input at the moment
        input_type = self._channel_to_input_type(self.channel)
        assert input_type != CrashInputType.STDIN, "input from stdin is not supported by dumb tracer right now"

        # open a fake socket, look for it and fake reading from it
        state.posix.open_socket(3)
        for fd in state.posix.fd:
            if fd in [0, 1, 2]:
                continue
            simfd = state.posix.fd[fd]
            if not isinstance(simfd, SimFileDescriptorDuplex):
                continue
            if simfd.read_storage.ident.startswith("aeg_stdin"):
                break
        else:
            raise CrashTracerError("Fail to find the input socket")
        simfd.read_data(len(self.testcase))

        # replace concrete input with symbolic input for the socket
        sim_chunk = simfd.read_storage.load(marker_idx, max_len)
        state.memory.store(controlled_addr, sim_chunk)

        # do not allow null byte and blank
        # FIXME: should perform some value analysis just in case null byte is allowed
        for i in range(max_len):
            state.solver.add(sim_chunk.get_byte(i) != 0)
            state.solver.add(sim_chunk.get_byte(i) != 0x20)
        return state
