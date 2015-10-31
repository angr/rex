import logging

l = logging.getLogger("rex.Crash")

import angr
import tracer
from rex.exploit import CannotExploit, ExploitFactory, CGCExploitFactory
from rex.vulnerability import Vulnerability

class NonCrashingInput(Exception):
    pass

class Crash(object):
    '''
    Triage a crash using angr.
    '''

    def __init__(self, binary, crash, aslr=None):
        '''
        :param binary: path to the binary which crashed
        :param crash: string of input which crashed the binary
        :param stack_base: option base address of the stack, if none is specified this will either be infered or left as
            None, depending on the platform
        '''

        self.binary = binary
        self.crash  = crash

        self.project = angr.Project(binary)
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
        prev, crash_state = tracer.Tracer(binary, crash, resiliency=False).run()
        if crash_state is None:
            l.warning("input did not cause a crash")
            raise NonCrashingInput

        # a path leading up to the crashing basic block
        self.prev   = prev

        # the state at crash time
        self.state  = crash_state

        memory_writes = [ ]
        for act in prev.actions:
            if act.type == "mem" and act.action == "write":
                what = act.data.ast
                if not (isinstance(what, int) or isinstance(what, long)):
                    if self.state.se.symbolic(what):
                        what_l = len(what) / 8
                        if self.state.se.symbolic(act.addr.ast):
                            l.warning("symbolic write target address is symbolic")
                        target = self.state.se.any_int(act.addr.ast)

                        memory_writes.append((target, what_l))

        self.symbolic_mem = { }

        memory_writes = sorted(memory_writes, key=lambda x: x[0])
        write_i = 0
        while write_i < len(memory_writes) - 1:

            current_w, current_len = memory_writes[write_i]
            current_end_w = current_w + current_len
            self.symbolic_mem[current_w] = current_len

            next_w, next_len = memory_writes[write_i + 1]
            next_end_w = next_w + next_len
            if current_end_w >= next_w: # does the next address start in an existing region?
                if not next_end_w <= current_end_w: # does the next region not end inside the existing region?
                    self.symbolic_mem[current_w] = next_end_w - current_w

                write_i += 1

            write_i += 1

        # crash type
        self.crash_type = None
        self._triage_crash()

### EXPOSED

    def exploitable(self):
        '''
        determine if the crash is exploitable
        :return: True if the crash's type is generally considered exploitable, False otherwise
        '''

        return not self.crash_type is None

    def exploit(self, **kwargs):
        '''
        craft an exploit for a crash
        '''

        # if this crash hasn't been classified, classify it now
        if not self.exploitable():
                raise CannotExploit

        if self.os == 'cgc':
            exploit = CGCExploitFactory(self, **kwargs)
        else:
            exploit = ExploitFactory(self, **kwargs)

        exploit.initialize()
        return exploit

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
        for a in self.state.log.actions:
            if a.type == 'mem':
                if self.state.se.symbolic(a.addr):
                    symbolic_actions.append(a)

        for sym_action in symbolic_actions:
            if sym_action.action == "write":
                if self.state.se.symbolic(sym_action.data):
                    l.info("detected write-what-where vulnerability")
                    self.crash_type = Vulnerability.WRITE_WHAT_WHERE
                else:
                    l.info("detected write-x-where vulnerability")
                    self.crash_type = Vulnerability.WRITE_X_WHERE

                return

        return
