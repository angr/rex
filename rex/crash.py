import logging

l = logging.getLogger("rex.Crash")

import os
import angr
import angrop
import tracer
import hashlib
from rex.exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from rex.vulnerability import Vulnerability
from simuvex import s_options as so

class NonCrashingInput(Exception):
    pass

class Crash(object):
    '''
    Triage a crash using angr.
    '''

    def __init__(self, binary, crash=None, pov_file=None, aslr=None, constrained_addrs=None):
        '''
        :param binary: path to the binary which crashed
        :param crash: string of input which crashed the binary
        :param pov_file: CGC PoV describing a crash
        :param aslr: analyze the crash with aslr on or off
        :param constrained_addrs: list of addrs which have been constrained during exploration
        '''

        self.binary = binary
        self.crash  = crash
        self.pov_file = pov_file
        self.constrained_addrs = [ ] if constrained_addrs is None else constrained_addrs

        self.project = angr.Project(binary)

        # we search for ROP gadgets now to avoid the memory exhaustion bug in pypy
        # hash binary contents for rop cache name
        binhash = hashlib.md5(open(self.binary).read()).hexdigest()
        rop_cache_path = os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(self.binary), binhash))
        self.rop = self.project.analyses.ROP()
        if os.path.exists(rop_cache_path):
            l.info("loading rop gadgets from cache '%s'", rop_cache_path)
            self.rop.load_gadgets(rop_cache_path)
        else:
            self.rop.find_gadgets()
            self.rop.save_gadgets(rop_cache_path)

        self.os = self.project.loader.main_bin.os

        # determine the aslr of a given os and arch
        if aslr is None:
            if self.os == "cgc": # cgc has no ASLR, but we don't assume a stackbase
                self.aslr = False
            else: # we assume linux is going to enfore stackbased aslr
                self.aslr = True
        else:
            self.aslr = aslr

        # run the tracer, grabbing the crash state
        remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS}
        add_options = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
        prev, crash_state = tracer.Tracer(binary, input=self.crash, pov_file=self.pov_file, resiliency=False, add_options=add_options, remove_options=remove_options).run(constrained_addrs)
        if crash_state is None:
            l.warning("input did not cause a crash")
            raise NonCrashingInput

        l.debug("done tracing input")
        # a path leading up to the crashing basic block
        self.prev   = prev

        # the state at crash time
        self.state  = crash_state

        # hacky trick to get all bytes
        memory_writes = [ ]
        for var in self.state.memory.mem._name_mapping.keys():
            memory_writes.extend(self.state.memory.addrs_for_name(var))

        self.symbolic_mem = { }

        memory_writes = sorted(memory_writes)

        current_w_start = memory_writes[0]
        current_w_end = current_w_start + 1

        for write in memory_writes[1:]:
            write_start = write
            write_len = 1

            # segment is completely seperate
            if write_start > current_w_end:
                # store the old segment
                self.symbolic_mem[current_w_start] = current_w_end - current_w_start

                # new segment, update start and end
                current_w_start = write_start
                current_w_end = write_start + write_len
            else:
                # update the end of the current segment, the segment `write` exists within current
                current_w_end = max(current_w_end, write_start + write_len)


        # write in the last segment
        self.symbolic_mem[current_w_start] = current_w_end - current_w_start

        # crash type
        self.crash_type = None
        # action (in case of a bad write or read) which caused the crash
        self.violating_action = None

        l.debug("triaging crash")
        self._triage_crash()

### EXPOSED

    def exploitable(self):
        '''
        determine if the crash is exploitable
        :return: True if the crash's type is generally considered exploitable, False otherwise
        '''

        exploitables = [Vulnerability.IP_OVERWRITE, Vulnerability.PARTIAL_IP_OVERWRITE, Vulnerability.BP_OVERWRITE,
                Vulnerability.PARTIAL_BP_OVERWRITE, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

        return self.crash_type in exploitables

    def explorable(self):
        '''
        determine if the crash can be explored with the 'crash explorer'.
        :return: True if the crash's type lends itself to exploring, only 'arbitrary-read' for now
        '''

        return self.crash_type == Vulnerability.ARBITRARY_READ

    def exploit(self, **kwargs):
        '''
        craft an exploit for a crash
        '''

        # crash should have been classified at this point
        if not self.exploitable():
                raise CannotExploit("non-exploitable crash")

        if self.os == 'cgc':
            exploit = CGCExploitFactory(self, **kwargs)
        else:
            exploit = ExploitFactory(self, **kwargs)

        exploit.initialize()
        return exploit

    def explore(self, path_file=None):
        '''
        explore a crash further to find new bugs
        '''

        # crash should be classified at this point
        if not self.explorable():
                raise CannotExplore("non-explorable crash")

        assert self.violating_action is not None

        # crash type was an arbitrary-read, let's point the violating address at a symbolic memory region

        # XXX: which symbolic region do we pick do we choose to point it to?
        max_addr = None
        for addr in self.symbolic_mem.keys():
            region_sz = self.symbolic_mem[addr]
            if max_addr is None or region_sz >= self.symbolic_mem[max_addr]:
                max_addr = addr

        # TODO: if max_addr cannot be set, we need to find another address to set it to
        if max_addr is None:
            l.debug("unable to find a symbolic memory region to set violating address to, setting to non-writable region")
            max_addr = self.project.loader.min_addr()

        self.state.add_constraints(self.violating_action.addr == max_addr)

        l.info("starting a new crash exploration phase based off the crash at address 0x%x", self.violating_action.ins_addr)

        new_input = self.state.posix.dumps(0)
        if path_file is not None:
            l.info("dumping new crash evading input into file '%s'", path_file)
            with open(path_file, 'w') as f:
                f.write(new_input)

        # create a new crash object starting here
        self.__init__(self.binary, new_input, constrained_addrs=self.constrained_addrs + [self.violating_action])

    def copy(self):
        cp = Crash.__new__(Crash)
        cp.binary = self.binary
        cp.crash = self.crash
        cp.project = self.project
        cp.os = self.os
        cp.aslr = self.aslr
        cp.prev = self.prev.copy()
        cp.state = self.state.copy()
        cp.symbolic_mem = self.symbolic_mem.copy()
        cp.crash_type = self.crash_type

        return cp

### UTIL

    @staticmethod
    def _symbolic_control(ast):
        '''
        determine the amount of symbolic bits in an ast, useful to determining how much control we have
        over registers
        '''

        sbits = 0

        # XXX assumes variables will always obey the same naming convention
        # the variable's bit size must be the string after the final '_' character
        for var in ast.variables:
            idx = var.rindex("_")
            sbits += int(var[idx+1:])

        return sbits


    def _triage_crash(self):
        ip = self.state.regs.ip
        bp = self.state.regs.bp

        # we assume a symbolic eip is always exploitable
        if self.state.se.symbolic(ip):
            # how much control of ip do we have?
            if self._symbolic_control(ip) >= self.state.arch.bits:
                l.info("detected ip overwrite vulnerability")
                self.crash_type = Vulnerability.IP_OVERWRITE
            else:
                l.info("detected partial ip overwrite vulnerability")
                self.crash_type = Vulnerability.PARTIAL_IP_OVERWRITE

            return

        if self.state.se.symbolic(bp):
            # how much control of bp do we have
            if self._symbolic_control(bp) >= self.state.arch.bits:
                l.info("detected bp overwrite vulnerability")
                self.crash_type = Vulnerability.BP_OVERWRITE
            else:
                l.info("detected partial bp overwrite vulnerability")
                self.crash_type = Vulnerability.PARTIAL_BP_OVERWRITE

            return

        # if nothing obvious is symbolic let's look at actions

        # grab the all actions in the last basic block
        symbolic_actions = [ ]
        for a in self.prev.state.log.actions:
            if a.type == 'mem':
                if self.state.se.symbolic(a.addr):
                    symbolic_actions.append(a)

        # TODO: pick the crashing action based off the crashing instruction address,
        # crash fixup attempts will break on this
        for sym_action in symbolic_actions:
            if sym_action.action == "write":
                if self.state.se.symbolic(sym_action.data):
                    l.info("detected write-what-where vulnerability")
                    self.crash_type = Vulnerability.WRITE_WHAT_WHERE
                else:
                    l.info("detected write-x-where vulnerability")
                    self.crash_type = Vulnerability.WRITE_X_WHERE

                self.violating_action = sym_action

            if sym_action.action == "read":
                # special vulnerability type, if this is detected we can explore the crash further
                l.info("detected arbitrary-read vulnerability")
                self.crash_type = Vulnerability.ARBITRARY_READ

                self.violating_action = sym_action

        return
