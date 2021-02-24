import os
import logging

from tracer import TinyCore
from archr.analyzers.angr_state import SimArchrMount
from angr.storage.file import SimFileDescriptorDuplex

from . import CrashTracer, CrashTracerError, add_options, remove_options
from ..enums import CrashInputType

l = logging.getLogger("rex.DumbTracer")

class DumbTracer(CrashTracer):
    """
    generate a coredump 1 block before crashing, identify the crash input
    and then replace the crash input with symbolic data
    FIXME: assumption: the target can be fired multiple times with the same behavior
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
        # let's just be safe, recording a full trace takes a lot of time
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=False, delay=delay+15,
                                 pre_fire_hook=pre_fire_hook, record_trace=True, actions=actions,
                                 record_magic=self._is_cgc)
        if not r.crashed:
            raise CrashTracerError("The target is not crashed inside QEMU!")
        crash_addr = r.trace[-1]
        return crash_addr, r.trace.count(crash_addr)

    def _concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None, taint=None):
        """
        identify the crash location and then generate a coredump before crashing
        """
        self.crash_addr, times = self._identify_crash_addr(testcase, channel, pre_fire_hook,
                                                    delay=delay, actions=actions)
        l.info("DumbTracer identified the crash_addr @ %#x:%d", self.crash_addr, times)

        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, delay=delay,
                                 trace_bb_addr=(self.crash_addr, times), crash_addr=(self.crash_addr, times),
                                 pre_fire_hook=pre_fire_hook, record_trace=True, actions=actions, taint=taint)
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
        self.project.loader.main_object = self.project.loader.elfcore_object
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
        controlled_addr_val = state.solver.eval(controlled_addr)
        obj = state.project.loader.find_object_containing(controlled_addr_val)
        max_buffer_size = min(obj.max_addr - controlled_addr_val, len(self.testcase))
        data = state.solver.eval(state.memory.load(controlled_addr, max_buffer_size), cast_to=bytes)
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
            if simfd.read_storage.ident.startswith("aeg_input"):
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
            state.solver.add(sim_chunk.get_byte(i) != 0x25)
            state.solver.add(sim_chunk.get_byte(i) != 0x2b)
        return state