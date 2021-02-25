import os
import copy
import logging

import nclib
import archr
import claripy
from tracer import TinyCore
from archr.analyzers.angr_state import SimArchrMount
from angr.storage.file import SimFileDescriptorDuplex

from . import CrashTracer, CrashTracerError, add_options, remove_options
from ..enums import CrashInputType
from ..exploit.actions import RexSendAction

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
        self.crash_addr_times = None
        self.testcase = None
        self.channel = None

        self._max_len = None
        self._marker_idx = None
        self._input_addr = None
        self._initial_state = None
        self._buffer_size = None

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

    def concrete_trace(self, testcase, channel, pre_fire_hook, delay=0, actions=None, taint=None):
        """
        identify the crash location and then generate a coredump before crashing
        """
        self.crash_addr, times = self._identify_crash_addr(testcase, channel, pre_fire_hook,
                                                    delay=delay, actions=actions)
        self.crash_addr_times = times
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

    def create_project(self, target, **kwargs):
        l.debug("Loading the core dump @ %s into angr...", self.trace_result.core_path)
        self._init_angr_project_bow(target)
        project = self.angr_project_bow.fire(core_path=self.trace_result.core_path)

        project.loader.main_object = project.loader.elfcore_object._main_object
        self.project = project
        return project

    def create_state(self, target, **kwargs):
        self.project.loader.main_object = self.project.loader.elfcore_object
        initial_state = self.project.factory.blank_state(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options)
        self.project.loader.main_object = self.project.loader.elfcore_object._main_object
        initial_state.fs.mount('/', SimArchrMount(target))
        self._initial_state = initial_state.copy()
        return initial_state

    def bootstrap_state(self, state, **kwargs):
        """
        perform analysis to input-state correspondence and then add the constraints in the state
        """
        word_size = self.project.arch.bytes
        marker_size = word_size * 3 # the minimal amount of gadgets to be useful

        # we operate on concrete memory so far, so it is safe to load and eval concrete memory
        data_len = state.regs.sp - state.regs.bp + 0x100
        data = state.solver.eval(state.memory.load(state.regs.sp, data_len), cast_to=bytes)

        # identify marker from the original input on stack
        for i in range(0, len(data), marker_size):
            marker = data[i:i+marker_size]
            if marker in self.testcase:
                break
        else:
            raise CrashTracerError("Fail to identify marker from the original input")
        input_addr = state.regs.sp + i
        marker_idx = self.testcase.index(marker)
        assert self.testcase.count(marker) == 1, "The input should have high entropy, cyclic is recommended"

        # search for the max length of the controlled data
        input_addr_val = state.solver.eval(input_addr)
        obj = state.project.loader.find_object_containing(input_addr_val)
        max_buffer_size = min(obj.max_addr - input_addr_val, len(self.testcase))
        data = state.solver.eval(state.memory.load(input_addr, max_buffer_size), cast_to=bytes)
        assert data[:marker_size] == self.testcase[marker_idx:marker_idx+marker_size]
        for max_len in range(marker_size, len(data), word_size):
            if data[:max_len] != self.testcase[marker_idx:marker_idx+max_len]:
                max_len -= word_size
                break
        self._input_addr = input_addr_val
        self._max_len = max_len
        self._marker_idx = marker_idx

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
        state.memory.store(input_addr, sim_chunk)

        ## do not allow null byte and blank
        ## FIXME: should perform some value analysis just in case null byte is allowed
        #for i in range(max_len):
        #    state.solver.add(sim_chunk.get_byte(i) != 0)
        #    state.solver.add(sim_chunk.get_byte(i) != 0x20)
        #    state.solver.add(sim_chunk.get_byte(i) != 0x25)
        #    state.solver.add(sim_chunk.get_byte(i) != 0x2b)
        return state

    def _get_buffer_size(self, crash):
        """
        identify the size of bytes we control before overwriting return address
        """
        byte_list = [claripy.BVS('taint_byte', 8) for _ in range(self._max_len)]
        byte_name_list = [list(x.variables)[0] for x in byte_list]
        taint = claripy.Concat(*byte_list)
        state = self._initial_state.copy()
        state.memory.store(self._input_addr, taint)
        succ = state.step().all_successors[0]

        if self.project.arch.memory_endness == 'Iend_LE':
            guard_idx = self.project.arch.bytes - 1
        else:
            guard_idx = 0

        guard_byte = succ.ip.get_byte(guard_idx)
        buffer_size = byte_name_list.index(list(guard_byte.variables)[0])
        return buffer_size

    def _same_behavior(self, trace_result, project, taint_str):
        # whether the process continues execution after the crash point
        if len(trace_result.trace) > 1:
            return False

        # whether there is any sliding because of input transformation
        mem = project.loader.memory.load(self._input_addr+self._buffer_size, len(taint_str))
        if mem != taint_str:
            return False

        return True

    def _is_bad_byte(self, crash, bad_byte):
        l.info("perform bad byte test on byte: %#x...", bad_byte)

        word_size = self.project.arch.bytes

        # prepare new input
        inp = bytes([bad_byte])

        # prepare new actions
        new_actions = []
        for act in crash.actions:
            new_act = copy.copy(act)
            new_act.interaction = None
            new_actions.append(new_act)

        # replace input in RexSendAction
        inp_idx = 0
        for act in new_actions:
            if type(act) != RexSendAction:
                continue
            if inp_idx + len(act.data) <= self._marker_idx:
                inp_idx += len(act.data)
                continue
            marker_offset = self._marker_idx - inp_idx
            # we assume the overflow happens inside one send
            assert marker_offset + self._buffer_size + self.project.arch.bytes <= len(act.data)

            # replace the byte several bytes before the input that affects pc
            # this location is usually not processed
            header = act.data[:marker_offset+self._buffer_size-word_size]
            footer = act.data[marker_offset+self._buffer_size-word_size+len(inp):]
            new_data = header + inp + footer
            act.data = new_data

            # replace where ip should be with a taint, if there is no bad byte,
            # it should be found at a known address
            taint_str = b'\xef\xbe\xad\xde\xbe\xba\xfe\xca'
            header = act.data[:marker_offset+self._buffer_size]
            footer = act.data[marker_offset+self._buffer_size+self.project.arch.bytes:]
            new_data = header + taint_str + footer
            act.data = new_data

        # now interact with the target using new input. If there are any bad byte
        # in the input, the target won't crash at the same location or don't crash at all
        channel, _ = crash._prepare_channel()
        try:
            r = self.tracer_bow.fire(testcase=None, channel=channel, delay=crash.delay, save_core=True,
                                     trace_bb_addr=(self.crash_addr, self.crash_addr_times),
                                     pre_fire_hook=crash.pre_fire_hook, record_trace=True, actions=new_actions)
        except archr.errors.ArchrError:
            # if the binary never reaches the crash address, the byte is a bad byte
            return True
        except nclib.errors.NetcatError:
            return None

        dsb = archr.arsenal.DataScoutBow(crash.target, analyzer=self.tracer_bow)
        angr_project_bow = archr.arsenal.angrProjectBow(crash.target, dsb)
        project = angr_project_bow.fire(core_path=r.core_path)
        project.loader.main_object = project.loader.elfcore_object._main_object

        # if the new actions have the same behavior as before, that means there are
        # no bad bytes in it
        if self._same_behavior(r, project, taint_str):
            return False
        return True

    def identify_bad_bytes(self, crash):
        """
        dumb tracer does not have information about the constraints on the input
        so it has to use concrete execution to identify the bad bytes through heuristics
        TODO: we can write it in a binary search fashion to properly identify all bad bytes
        """
        self._buffer_size = self._get_buffer_size(crash)

        bad_bytes = []
        for c in [0x00, 0x20, 0x25, 0x2b]:
            ret = self._is_bad_byte(crash, c)
            if ret:
                l.debug("%#x is a bad byte!", c)
                bad_bytes.append(c)
        return bad_bytes