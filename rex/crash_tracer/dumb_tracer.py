import os
import copy
import logging
from typing import TYPE_CHECKING

import nclib
import archr
import claripy
from tracer import TinyCore
from archr.analyzers.angr_state import SimArchrMount
from angr.storage.file import SimFileDescriptorDuplex

from . import CrashTracer, CrashTracerError, add_options, remove_options
from ..enums import CrashInputType
from ..exploit.actions import RexSendAction

if TYPE_CHECKING:
    from angr import Project


l = logging.getLogger("rex.DumbTracer")

class DumbTracer(CrashTracer):
    """
    generate a coredump 1 block before crashing, identify the crash input
    and then replace the crash input with symbolic data
    FIXME: assumption: the target can be fired multiple times with the same behavior
    """
    def __init__(self, crash, **kwargs):
        super().__init__(crash, **kwargs)
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
        self._bad_bytes = None
        self._save_ip_addr = None

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
        crash_block_addr = r.trace[-1]
        return crash_block_addr, r.trace.count(crash_block_addr)

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
        l.debug("Loading the core dump @ %s into angr...", self.trace_result.halfway_core_path)
        self._init_angr_project_bow(target)
        project = self.angr_project_bow.fire(core_path=self.trace_result.halfway_core_path)

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

    def _get_saved_ip_addr(self, state):
        """
        input state is at the basic block moving input to ip
        """

        # step once
        simgr = self.project.factory.simgr(state.copy())
        simgr.step()
        assert len(simgr.active) == 1
        crashing_state = simgr.active[0]

        # identify the addresses that this block reads
        read_addr_bvs = []
        for act in crashing_state.history.actions:
            if act.type == 'mem' and act.action == 'read':
                read_addr_bvs.append(act.addr.ast)

        # insert symbolic values to the addresses and identify saved_ip_addr
        # just in case the value loaded to ip is not unique in those reads
        init_state = state.copy()
        sim_words = [claripy.BVS('taint_word', self.project.arch.bits) for _ in read_addr_bvs]
        for idx in range(len(read_addr_bvs)):
            init_state.memory.store(read_addr_bvs[idx], sim_words[idx])

        # step from the tainted state once
        simgr = self.project.factory.simgr(init_state, save_unconstrained=True)
        simgr.step()
        assert len(simgr.unconstrained) == 1
        crashing_state = simgr.unconstrained[0]

        # identify the saved ip addr
        sim_ip = crashing_state.ip
        idx = None
        for idx, x in enumerate(sim_words):
            if list(x.variables)[0] == list(sim_ip.variables)[0]:
                break
        if not idx:
            raise RuntimeError("WTF? the block at @ %#x does not load IP?" % self.crash_addr)
        return crashing_state.solver.eval(read_addr_bvs[idx])

    def bootstrap_state(self, state, **kwargs):
        """
        perform analysis to find input-state correspondence and then add the constraints in the state
        """

        self._save_ip_addr = self._get_saved_ip_addr(state)

        crashing_state = state

        word_size = self.project.arch.bytes
        marker_size = word_size * 3 # the minimal amount of gadgets to be useful

        # we operate on concrete memory so far, so it is safe to load and eval concrete memory
        data = crashing_state.solver.eval(crashing_state.memory.load(self._save_ip_addr, 0x100), cast_to=bytes)

        # identify marker from the original input on stack
        for i in range(0, len(data), marker_size):
            marker = data[i:i+marker_size]
            if marker in self.testcase:
                break
        else:
            raise CrashTracerError("Fail to identify marker from the original input")
        input_addr = self._save_ip_addr + i
        marker_idx = self.testcase.index(marker)
        assert self.testcase.count(marker) == 1, "The input should have high entropy, cyclic is recommended"

        # search for the max length of the controlled data
        input_addr = crashing_state.solver.eval(input_addr)
        obj = crashing_state.project.loader.find_object_containing(input_addr)
        max_buffer_size = min(obj.max_addr - input_addr, len(self.testcase))
        data = crashing_state.solver.eval(crashing_state.memory.load(input_addr, max_buffer_size), cast_to=bytes)
        assert data[:marker_size] == self.testcase[marker_idx:marker_idx+marker_size]
        for max_len in range(marker_size, len(data), word_size):
            if data[:max_len] != self.testcase[marker_idx:marker_idx+max_len]:
                max_len -= word_size
                break

        self._input_addr = input_addr
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

        # to simulate a tracing, the bad bytes constraints should be applied to state here
        self._bad_bytes = self.identify_bad_bytes(self.crash)
        for i in range(max_len):
            for c in self._bad_bytes:
                state.solver.add(sim_chunk.get_byte(i) != c)

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
        assert succ.ip.symbolic, "input identification is wrong! the ip is not overwritten!"

        if self.project.arch.memory_endness == 'Iend_LE':
            guard_idx = self.project.arch.bytes - 1
        else:
            guard_idx = 0

        guard_byte = succ.ip.get_byte(guard_idx)
        buffer_size = byte_name_list.index(list(guard_byte.variables)[0])
        return buffer_size

    def _same_behavior(self, trace_result, project, taint_str, byte_under_test):
        # whether the process continues execution after the crash point
        if len(trace_result.trace) > 1:
            return False

        # whether there is any sliding because of input transformation
        end_addr = self._input_addr + self._max_len
        mem = project.loader.memory.load(end_addr - len(taint_str), len(taint_str))
        if mem != taint_str:
            return False

        should_be_byte = project.loader.memory.load(end_addr-len(taint_str)-1, 1)[0]
        if should_be_byte != byte_under_test:
            return False
        return True

    @staticmethod
    def _replace_bytes(data, idx, new):
        assert len(new) + idx <= len(data)
        return data[:idx] + new + data[idx+len(new):]

    def _is_bad_byte(self, crash, bad_byte):
        l.info("perform bad byte test on byte: %#x...", bad_byte)

        # prepare new input
        inp = bytes([bad_byte]*(self._max_len - (self._save_ip_addr - self._input_addr)))
        taint_str = b'\xef\xbe\xad\xde\xbe\xba\xfe\xca'

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

            # replace several bytes before the end of the controlled region
            end_offset = marker_offset + self._max_len
            saved_ip_offset = marker_offset + self._buffer_size
            act.data = self._replace_bytes(act.data, saved_ip_offset, inp)

            # replace where ip should be with a taint, if there is no bad byte,
            # it should be found at a known address
            act.data = self._replace_bytes(act.data, end_offset-8, taint_str)

        # now interact with the target using new input. If there are any bad byte
        # in the input, the target won't crash at the same location or don't crash at all
        channel, _ = crash._prepare_channel()
        try:
            r = self.tracer_bow.fire(testcase=None, channel=channel, delay=crash.delay, save_core=True,
                                     crash_addr=(self.crash_addr, self.crash_addr_times),
                                     trace_bb_addr=(self.crash_addr, self.crash_addr_times),
                                     pre_fire_hook=crash.pre_fire_hook, record_trace=True, actions=new_actions)
        except archr.errors.ArchrError:
            # if the binary never reaches the crash address, the byte is a bad byte
            return True
        except nclib.errors.NetcatError:
            return None

        dsb = archr.arsenal.DataScoutBow(crash.target, analyzer=self.tracer_bow)
        angr_project_bow = archr.arsenal.angrProjectBow(crash.target, dsb)
        project = angr_project_bow.fire(core_path=r.halfway_core_path)
        project.loader.main_object = project.loader.elfcore_object._main_object

        # if the new actions have the same behavior as before, that means there are
        # no bad bytes in it
        if self._same_behavior(r, project, taint_str, bad_byte):
            return False
        return True

    def identify_bad_bytes(self, crash):
        """
        dumb tracer does not have information about the constraints on the input
        so it has to use concrete execution to identify the bad bytes through heuristics
        TODO: we can write it in a binary search fashion to properly identify all bad bytes
        """
        if self._bad_bytes is not None:
            return self._bad_bytes

        self._buffer_size = self._get_buffer_size(crash)

        bad_bytes = []
        for c in [0x00, 0x20, 0x25, 0x2b, 0x2d]:
            ret = self._is_bad_byte(crash, c)
            if ret:
                l.debug("%#x is a bad byte!", c)
                bad_bytes.append(c)
        return bad_bytes
