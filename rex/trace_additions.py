from simuvex import SimStatePlugin
import simuvex

import string
import logging
l = logging.getLogger("rex.trace_additions")
l.setLevel("DEBUG")


class FormatInfo(object):
    def copy(self):
        raise NotImplementedError

    def compute(self, state):
        raise NotImplementedError

    def get_type(self):
        raise NotImplementedError


class FormatInfoStrToInt(FormatInfo):
    def __init__(self, addr, func_name, str_arg_num, base, base_arg):
        # the address of the function
        self.addr = addr
        # the name of the function
        self.func_name = func_name
        # the argument which is a string
        self.str_arg_num = str_arg_num
        # the base of the string
        self.base = base
        # the argument which represents the base
        self.base_arg = base_arg
        # the input_val (computed at the start of function call)
        self.input_val = None
        self.input_base = None

    def copy(self):
        out = FormatInfoStrToInt(self.addr, self.func_name, self.str_arg_num,
                                 self.base, self.base_arg)
        return out

    def compute(self, state):
        self.input_val = simuvex.s_cc.SimCCCdecl(state.arch).arg(state, self.str_arg_num)
        if self.base_arg is not None:
            self.input_base = state.se.any_int(simuvex.s_cc.SimCCCdecl(state.arch).arg(state, self.base_arg))
        else:
            self.input_base = self.base

    def get_type(self):
        return "StrToInt"

class FormatInfoIntToStr(FormatInfo):
    def __init__(self, addr, func_name, int_arg_num, str_dst_num, base, base_arg):
        # the address of the function
        self.addr = addr
        # the name of the function
        self.func_name = func_name
        # the argument which is a string
        self.int_arg_num = int_arg_num
        # the argument which is the dest buf
        self.str_dst_num = str_dst_num
        # the base of the string
        self.base = base
        # the argument which represents the base
        self.base_arg = base_arg
        # the input_val and str addr (computed at the start of function call)
        self.input_val = None
        self.input_base = None
        self.str_dst_addr = None

    def copy(self):
        out = FormatInfoIntToStr(self.addr, self.func_name, self.int_arg_num,
                                 self.str_dst_num, self.base, self.base_arg)
        return out

    def compute(self, state):
        self.input_val = simuvex.s_cc.SimCCCdecl(state.arch).arg(state, self.int_arg_num)
        if self.base_arg is not None:
            self.input_base = state.se.any_int(simuvex.s_cc.SimCCCdecl(state.arch).arg(state, self.base_arg))
        else:
            self.input_base = self.base
        self.str_dst_addr = simuvex.s_cc.SimCCCdecl(state.arch).arg(state, self.str_dst_num)

    def get_type(self):
        return "IntToStr"


def generic_info_hook(state):
    addr = state.se.any_int(state.regs.ip)
    chall_resp_plugin = state.get_plugin("chall_resp_info")

    # hook the return address
    ret_addr = state.se.any_int(state.memory.load(state.regs.sp, 4, endness="Iend_LE"))
    chall_resp_plugin.ret_addr_to_unhook = ret_addr
    chall_resp_plugin.project.hook(ret_addr, end_info_hook, length=0)

    format_info = chall_resp_plugin.format_infos[addr].copy()
    format_info.compute(state)
    l.debug("starting hook for %s at %#x", format_info.func_name, format_info.addr)
    chall_resp_plugin.pending_info = format_info


"""
def get_actual_int_len(state, bv, base):
    valid_chars = set()
    for i in range(base):
        if i < 10:
            valid_chars.add(chr(ord("0")+i))
        if i >= 10:
            valid_chars.add(chr(ord("A")+i-10))
            valid_chars.add(chr(ord("a")+i-10))

    the_int = state.se.any_str(bv)
    found_start = False
    for i in range(len(the_int)):
        if the_int[i] in valid_chars:
            found_start = True
        if found_start and the_int[i] not in valid_chars:
            return i
    return len(the_int)
"""

def end_info_hook(state):
    chall_resp_plugin = state.get_plugin("chall_resp_info")
    pending_info = chall_resp_plugin.pending_info

    # undo the stops
    chall_resp_plugin.project.unhook(chall_resp_plugin.ret_addr_to_unhook)
    chall_resp_plugin.ret_addr_to_unhook = None
    chall_resp_plugin.pending_info = None

    # replace the result with a symbolic variable
    # also add a constraint that points out what the input is
    if pending_info.get_type() == "StrToInt":
        # result constraint
        result = state.se.any_int(state.regs.eax)
        new_var = state.se.BVS(pending_info.get_type() + "_" + str(pending_info.input_base) + "_result", 32)
        constraint = new_var == result
        chall_resp_plugin.replacement_pairs.append((new_var, state.regs.eax))
        state.regs.eax = new_var

        # mark the input
        input_val = state.mem[pending_info.input_val].string.resolved
        input_bvs = state.se.BVS(pending_info.get_type() + "_" + str(pending_info.input_base) + "_input", input_val.size())
        chall_resp_plugin.str_to_int_pairs.append((input_bvs, new_var))
        chall_resp_plugin.replacement_pairs.append((input_bvs, input_val))
    else:
        # result constraint
        result = state.se.any_str(state.mem[pending_info.str_dst_addr].string.resolved)
        new_var = state.se.BVS(pending_info.get_type() + "_" + str(pending_info.input_base) + "_result",
                               len(result) * 8)
        chall_resp_plugin.replacement_pairs.append((new_var, state.mem[pending_info.str_dst_addr].string.resolved))
        state.memory.store(pending_info.str_dst_addr, new_var)
        constraint = new_var == result

        # mark the input
        input_val = pending_info.input_val
        input_bvs = state.se.BVS(pending_info.get_type() + "_" + str(pending_info.input_base) + "_input", 32)
        chall_resp_plugin.int_to_str_pairs.append((input_bvs, new_var))
        chall_resp_plugin.replacement_pairs.append((input_bvs, input_val))

    l.debug("ending hook for %s at %#x", pending_info.func_name, pending_info.addr)
    l.debug("new constraint %s", constraint)
    chall_resp_plugin.vars_we_added.update(new_var.variables)
    chall_resp_plugin.vars_we_added.update(input_bvs.variables)
    state.add_constraints(input_val == input_bvs)
    state.add_constraints(constraint)
    chall_resp_plugin.tracer.preconstraints.append(constraint)
    chall_resp_plugin.tracer.variable_map[list(new_var.variables)[0]] = constraint


def exit_hook(state):
    # detect challenge response for fun
    guard = state.inspect.exit_guard
    if any(v.startswith("cgc-flag") for v in guard.variables) and \
            any(v.startswith("file_/dev/stdin") for v in guard.variables):
        l.warning("Challenge response detected")

    # track the amount of stdout we had when a constraint was first added to a byte of stdin
    chall_resp_plugin = state.get_plugin("chall_resp_info")
    stdin_min_stdout_constraints = chall_resp_plugin.stdin_min_stdout_constraints
    stdout_pos = state.se.any_int(state.posix.get_file(1).pos)
    for v in guard.variables:
        if v.startswith("file_/dev/stdin"):
            byte_num = ChallRespInfo.get_byte(v)
            if byte_num not in stdin_min_stdout_constraints:
                stdin_min_stdout_constraints[byte_num] = stdout_pos

def syscall_hook(state):
    # here we detect how much stdout we have when a byte is first read in
    syscall_name = state.inspect.syscall_name
    if syscall_name == "receive":
        # track the amount of stdout we had when we first read the byte
        stdin_min_stdout_reads = state.get_plugin("chall_resp_info").stdin_min_stdout_reads
        stdout_pos = state.se.any_int(state.posix.get_file(1).pos)
        stdin_pos = state.se.any_int(state.posix.get_file(0).pos)
        for i in range(0, stdin_pos):
            if i not in stdin_min_stdout_reads:
                stdin_min_stdout_reads[i] = stdout_pos


def constraint_hook(state):
    # here we prevent adding constraints if there's a pending thing
    chall_resp_plugin = state.get_plugin("chall_resp_info")
    if chall_resp_plugin.pending_info is not None:
        state.inspect.added_constraints = []

class ChallRespInfo(SimStatePlugin):
    """
    This state plugin keeps track of the reads and writes to symbolic addresses
    """
    def __init__(self):
        SimStatePlugin.__init__(self)
        # for each constraint we check what the max stdin it has and how much stdout we have
        self.stdin_min_stdout_constraints = {}
        self.stdin_min_stdout_reads = {}
        self.format_infos = dict()
        self.project = None
        self.pending_info = None
        self.tracer = None
        self.str_to_int_pairs = []
        self.int_to_str_pairs = []
        self.ret_addr_to_unhook = None
        self.vars_we_added = set()
        self.replacement_pairs = []


    def __getstate__(self):
        d = dict(self.__dict__)
        del d["project"]
        del d["tracer"]
        del d["state"]

        return d

    def __setstate__(self, d):
        self.__dict__.update(d)
        self.project = None
        self.tracer = None
        self.state = None

    def copy(self):
        s = ChallRespInfo()
        s.stdin_min_stdout_constraints = dict(self.stdin_min_stdout_constraints)
        s.stdin_min_stdout_reads = dict(self.stdin_min_stdout_reads)
        s.format_infos = dict(self.format_infos)
        s.project = self.project
        s.pending_info = self.pending_info
        s.tracer = self.tracer
        s.str_to_int_pairs = list(self.str_to_int_pairs)
        s.int_to_str_pairs = list(self.int_to_str_pairs)
        s.ret_addr_to_unhook = self.ret_addr_to_unhook
        s.vars_we_added = set(self.vars_we_added)
        s.replacement_pairs = list(self.replacement_pairs)
        return s

    @staticmethod
    def get_byte(var_name):
        idx = var_name.split("_")[3]
        return int(idx, 16)

    def lookup_original(self, replacement):
        for r, o in self.replacement_pairs:
            if r is replacement:
                return o
        return None

    def get_stdin_indices(self, variable):
        byte_indices = set()
        for str_val, int_val in self.str_to_int_pairs:
            if variable in int_val.variables:
                original_str = self.lookup_original(str_val)
                if original_str is None:
                    l.warning("original_str is None")
                    continue
                for v in original_str.variables:
                    if v.startswith("file_/dev/stdin"):
                        byte_indices.add(self.get_byte(v))
        return byte_indices

    def get_stdout_indices(self, variable):
        file_1 = self.state.posix.get_file(1)
        stdout_size = self.state.se.any_int(file_1.pos)
        stdout = file_1.content.load(0, stdout_size)
        byte_indices = set()
        for int_val, str_val in self.int_to_str_pairs:
            if variable in int_val.variables:
                num_bytes = str_val.size()/8
                if stdout.op != "Concat":
                    l.warning("stdout is not concat!")
                    continue
                stdout_pos = 0
                for arg in stdout.args:
                    if arg is str_val:
                        byte_indices.update(range(stdout_pos, stdout_pos+num_bytes))
                    stdout_pos += arg.size()/8
        return byte_indices

    @staticmethod
    def prep_tracer(tracer, format_infos=None):
        path = tracer.path_group.one_active
        format_infos = [] if format_infos is None else format_infos
        state = path.state
        state.inspect.b(
            'exit',
            simuvex.BP_BEFORE,
            action=exit_hook
        )
        state.inspect.b(
            'syscall',
            simuvex.BP_AFTER,
            action=syscall_hook
        )
        state.inspect.b(
            'constraints',
            simuvex.BP_BEFORE,
            action=constraint_hook
        )

        if state.has_plugin("chall_resp_info"):
            chall_resp_plugin = state.get_plugin("chall_resp_info")
        else:
            chall_resp_plugin = ChallRespInfo()
        chall_resp_plugin.project = path._project
        chall_resp_plugin.tracer = tracer
        for f in format_infos:
            chall_resp_plugin.format_infos[f.addr] = f

        state.register_plugin("chall_resp_info", chall_resp_plugin)

        for addr in chall_resp_plugin.format_infos:
            path._project.hook(addr, generic_info_hook, length=0)
