import os
import copy
import re
import logging
from typing import List, Tuple, TYPE_CHECKING

import nclib
import archr
import claripy
from tracer import TinyCore
from archr.analyzers.angr_state import SimArchrMount
from archr.analyzers.qemu_tracer import QEMUTracerError
from angr.storage.file import SimFileDescriptorDuplex
from cle.backends import ELFCore
from claripy.annotation import SimplificationAvoidanceAnnotation

from . import CrashTracer, CrashTracerError, add_options, remove_options
from ..enums import CrashInputType
from ..exploit.actions import RexSendAction

if TYPE_CHECKING:
    from angr import Project

l = logging.getLogger(__name__)

DANGEROUS_BYTES = [0x00, 0x0a, 0x20, 0x24, 0x25, 0x26, 0x27, 0x2b, 0x2d, 0x3b, 0x3f, 0x5c, 0x7c, 0xff]

class ASTTaint(SimplificationAvoidanceAnnotation):
    """
    A dummy taint for input-to-state analysis
    """
    def __init__(self):
        pass

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
        self.channel = None

        self._max_len = None
        self._marker_idx = None
        self._input_addr = None
        self._initial_state = None
        self._buffer_size = None
        self._bad_bytes = None
        self._save_ip_addr = None

        self._patch_strs = []

    @property
    def testcase(self):
        return self.crash.crash_input

    def _investigate_crash(self, r, testcase, channel, pre_fire_hook, delay=0):
        l.info("investigating crash @ %#x", r.crash_address)

        # create a project
        self._init_angr_project_bow(self.tracer_bow.target)
        project = self.angr_project_bow.fire(core_path=r.core_path)
        project.loader.main_object = project.loader.elfcore_object
        state = project.factory.blank_state(
            mode='tracing',
            add_options=add_options
            )

        # taint the registers and then step one single instruction which is the crashing instruction
        # then we can use the taint to infer which register caused the crash
        # This assumes that the register value directly comes from the input

        # step 1: taint the registers
        taint = ASTTaint()
        for x in state.project.arch.registers:
            setattr(state.regs, x, getattr(state.regs, x).annotate(taint))

        # step 2: step one single instruction
        block = state.block()
        insn = block.capstone.insns[0]
        insn_end = block.addr + insn.insn.size
        simgr = project.factory.simgr(state)
        simgr.step(extra_stop_points=[insn_end])
        assert len(simgr.active) == 1
        crashing_state = simgr.active[0]

        # step 3: extracting info about the crashing memory access
        for act in crashing_state.history.actions:
            if act.type == 'mem':
                break
        else:
            raise CrashTracerError("There is no memory access in the last instruction" +
                                   "why does it crash?")
        for ast in act.addr.ast.leaf_asts():
            if ast.annotations:
                break
        else:
            raise CrashTracerError("Investigation error! The crash is not caused by any register!")
        bad_ptr = ast
        bad_data = state.solver.eval(bad_ptr, cast_to=bytes)

        # find an address in rw region with no dangerous bytes
        addr_str = None
        sim_addr = claripy.BVS("addr", project.arch.bytes*8)
        for obj in project.loader.all_elf_objects:
            if type(obj) == ELFCore:
                continue
            for seg in obj.segments:
                if not seg.is_readable or not seg.is_writable:
                    continue
                st = state.copy()
                # make it in the middle of a segment
                st.add_constraints(sim_addr >= seg.min_addr+0x100)
                st.add_constraints(sim_addr < seg.max_addr-0x100)
                # no bad bytes
                for c in DANGEROUS_BYTES:
                    for i in range(project.arch.bytes):
                        st.add_constraints(sim_addr.get_byte(i) != c)
                if st.satisfiable():
                    addr_str = st.solver.eval(sim_addr, cast_to=bytes)
                if addr_str:
                    break
            if addr_str:
                break
        else:
            raise CrashTracerError("Fail to find a pointer to rw region")

        # fix pointer strings
        if project.arch.memory_endness == 'Iend_LE':
            addr_str = addr_str[::-1]
            bad_data = bad_data[::-1]

        # replace the bad data with a valid known pointer to rw region and pin this
        # patch to corresponding RexSendAction
        self._patch_strs.append(addr_str)
        for act in self.crash.actions:
            if type(act) != RexSendAction:
                continue
            patches = [(i, addr_str) for i in range(len(act.data)) if act.data[i:i+len(addr_str)] == bad_data]
            act.patches += patches
            act.data = act.data.replace(bad_data, addr_str)
        tup = self.crash._input_preparation(None, self.crash.actions, self.crash.input_type)
        self.crash.crash_input, self.crash.actions, self.crash.sim_input = tup

        # Hack: we only need this project once, so let's destroy the initialized project bow and the project
        self.angr_project_bow.project = None
        self.angr_project_bow = None

        return self._identify_crash_addr(testcase, channel, pre_fire_hook,
                                         delay=delay, actions=self.crash.actions, investigate=False)

    def _identify_crash_addr(self, testcase, channel, pre_fire_hook, delay=0, actions=None, investigate=True):
        """
        run the target once to identify crash_addr
        """
        # let's just be safe, recording a full trace takes a lot of time
        r = self.tracer_bow.fire(testcase=testcase, channel=channel, save_core=True, delay=delay+15,
                                 pre_fire_hook=pre_fire_hook, record_trace=True, actions=actions,
                                 record_magic=self._is_cgc)
        if not r.crashed:
            raise CrashTracerError("The target is not crashed inside QEMU!")

        # investigate the crash if the target crashes at an uncontrolled address
        # likely because of memory access
        self._init_angr_project_bow(self.tracer_bow.target)
        project = self.angr_project_bow.fire(core_path=r.core_path)
        project.loader.main_object = project.loader.elfcore_object
        if project.loader.find_object_containing(r.crash_address):
            if investigate:
                return self._investigate_crash(r, testcase, channel, pre_fire_hook, delay=delay)
            raise CrashTracerError("Not an IP control vulnerability!")

        # destroy the temporary project bow and the project
        self.angr_project_bow.project = None
        self.angr_project_bow = None

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
        for idx, addr_bv in enumerate(read_addr_bvs):
            init_state.memory.store(addr_bv, sim_words[idx])

        # step from the tainted state once
        simgr = self.project.factory.simgr(init_state, save_unconstrained=True)
        simgr.step()
        assert len(simgr.unconstrained) == 1, "Do not control IP, panicking!"
        crashing_state = simgr.unconstrained[0]

        # identify the saved ip addr
        sim_ip = crashing_state.ip
        idx = None
        for idx, x in enumerate(sim_words):
            if list(x.variables)[0] == list(sim_ip.variables)[0]:
                break
        if idx is None:
            raise RuntimeError("WTF? the block at @ %#x does not load IP?" % self.crash_addr)
        addr= crashing_state.solver.eval(read_addr_bvs[idx])
        l.debug("identify saved ip addr @ %#x", addr)
        return addr

    def bootstrap_state(self, state, **kwargs):
        """
        perform analysis to find input-state correspondence and then add the constraints in the state
        """

        self._save_ip_addr = self._get_saved_ip_addr(state)

        crashing_state = state
        word_size = self.project.arch.bytes

        # we operate on concrete memory so far, so it is safe to load and eval concrete memory
        sim_data = crashing_state.memory.load(self._save_ip_addr, len(self.testcase))
        data = crashing_state.solver.eval(sim_data, cast_to=bytes)
        assert data[:word_size] in self.testcase, "PC is not overwritten!"

        # identify marker from the original input on stack
        for marker_size in range(word_size, len(data)):
            marker = data[:marker_size]
            if marker not in self.testcase:
                raise CrashTracerError("Fail to identify marker from the original input")
            if self.testcase.count(marker) == 1:
                break
        else:
            raise CrashTracerError("The input should have high entropy, cyclic is recommended")

        marker_idx = self.testcase.index(marker)

        #
        # we search forward and backward from `search_start` to find the maximum number of bytes that we control
        #
        search_start = self._save_ip_addr
        search_start = crashing_state.solver.eval(search_start)
        obj = crashing_state.project.loader.find_object_containing(search_start)

        # search forward to determine the maximum length of controlled data
        max_buffer_size = min(obj.max_addr - search_start, len(self.testcase) - marker_idx)
        data = crashing_state.solver.eval(crashing_state.memory.load(search_start, max_buffer_size), cast_to=bytes)
        assert data[:marker_size] == self.testcase[marker_idx:marker_idx+marker_size]
        for i in range(marker_size, len(data), word_size):
            if data[:i] != self.testcase[marker_idx:marker_idx+i]:
                max_len_forward = i - word_size
                break
        else:
            max_len_forward = len(data)

        # search backward to determine the maximum length of controlled data
        # no one needs more than 1KB of buffer size - Gill Bates
        max_backward_buffer_size = min(search_start - obj.min_addr, marker_idx, 1024)

        data = crashing_state.solver.eval(
            crashing_state.memory.load(search_start - max_backward_buffer_size, max_backward_buffer_size),
            cast_to=bytes,
        )
        for i in range(word_size, len(data)+word_size, word_size):
            if data[-i:] != self.testcase[marker_idx - i : marker_idx]:
                max_len_backward = i - word_size
                break
        else:
            max_len_backward = len(data)

        # search complete!
        self._input_addr = search_start - max_len_backward
        self._max_len = max_len_backward + max_len_forward
        self._marker_idx = marker_idx - max_len_backward

        l.debug("Input is at %#x in memory. We control at most %d bytes. The controllable chunk starts at offset "
                "%d in the given test case.",
                self._input_addr,
                self._max_len,
                self._marker_idx,
                )

        # only support network input at the moment
        input_type = self._channel_to_input_type(self.channel)
        # assert input_type != CrashInputType.STDIN, "input from stdin is not supported by dumb tracer right now"

        # open a fake socket, look for it and fake reading from it
        on_stdin = input_type == CrashInputType.STDIN
        if not on_stdin:
            state.posix.open_socket(3)
        for fd in state.posix.fd:
            if fd in [0, 1, 2] and not on_stdin:
                continue
            simfd = state.posix.fd[fd]
            if not isinstance(simfd, SimFileDescriptorDuplex):
                continue
            if simfd.read_storage.ident.startswith("aeg_input"):
                break
        else:
            raise CrashTracerError("Fail to find the input socket")
        simfd.read_data(len(self.testcase))

        # compute where to patch
        concrete_str = state.solver.eval(state.memory.load(self._input_addr, self._max_len), cast_to=bytes)
        patches = []
        for patch_str in self._patch_strs:
            addrs = [self._input_addr+i for i in range(self._max_len) if concrete_str[i:i+len(patch_str)] == patch_str]
            patches += list(zip(addrs, [patch_str]*len(addrs)))

        # replace concrete input with symbolic input for the socket
        sim_chunk = simfd.read_storage.load(self._marker_idx, self._max_len)
        state.memory.store(self._input_addr, sim_chunk)

        # apply patches
        for addr, patch_str in patches:
            state.memory.store(addr, patch_str)

        # to simulate a tracing, the bad bytes constraints should be applied to state here
        self._bad_bytes = self.identify_bad_bytes()
        for i in range(self._max_len):
            for c in self._bad_bytes:
                state.solver.add(sim_chunk.get_byte(i) != c)

        return state

    def _get_buffer_size(self):
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
        # taint string should be something unique and not contain bad bytes
        taint_str = b'DeAdB33F' # b'\xef\xbe\xad\xde\xbe\xba\xfe\xca'

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

            # find all previously identified byte chunks that should not be touched
            patchstr_and_offset: List[Tuple[int,bytes]] = [ ]
            for patch_str in self._patch_strs:
                offsets = [ m.start() for m in re.finditer(re.escape(patch_str), act.data) ]
                patchstr_and_offset += [ (off, patch_str) for off in offsets ]

            # replace several bytes before the end of the controlled region
            end_offset = marker_offset + self._max_len
            saved_ip_offset = marker_offset + self._buffer_size
            act.data = self._replace_bytes(act.data, saved_ip_offset, inp)

            # replace where ip should be with a taint, if there is no bad byte,
            # it should be found at a known address
            act.data = self._replace_bytes(act.data, end_offset-8, taint_str)

            # patch back the byte chunks that should not be touched!
            for off, patch_str in patchstr_and_offset:
                act.data = self._replace_bytes(act.data, off, patch_str)

        # now interact with the target using new input. If there are any bad byte
        # in the input, the target won't crash at the same location or don't crash at all
        channel, _ = crash._prepare_channel()
        try:
            r = self.tracer_bow.fire(testcase=None, channel=channel, delay=crash.delay, save_core=True,
                                     crash_addr=(self.crash_addr, self.crash_addr_times),
                                     trace_bb_addr=(self.crash_addr, self.crash_addr_times),
                                     pre_fire_hook=crash.pre_fire_hook, record_trace=True, actions=new_actions)
        except QEMUTracerError:
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

    def identify_bad_bytes(self):
        """
        dumb tracer does not have information about the constraints on the input
        so it has to use concrete execution to identify the bad bytes through heuristics
        TODO: we can write it in a binary search fashion to properly identify all bad bytes
        """
        if self._bad_bytes is not None:
            return self._bad_bytes

        self._buffer_size = self._get_buffer_size()

        bad_bytes = []
        for c in DANGEROUS_BYTES:
            ret = self._is_bad_byte(self.crash, c)
            if ret:
                l.debug("%#x is a bad byte!", c)
                bad_bytes.append(c)
        return bad_bytes
