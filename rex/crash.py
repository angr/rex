import logging

l = logging.getLogger("rex.Crash")

import angr
import tracer
from rex.exploit import CannotExploit
from rex.exploit.cgc import CGCExploit
from rex.exploit.linux import LinuxExploit
from rex.vulnerability import Vulnerability

class NonCrashingInput(Exception):
    pass

class Crash(object):
    '''
    Triage a crash using angr.
    '''

    def __init__(self, binary, crash):
        '''
        :param binary: path to the binary which crashed
        :param crash: string of input which crashed the binary
        '''

        self.binary = binary
        self.crash  = crash

        self._p = angr.Project(binary)
        self.tracer = tracer.Tracer(binary, crash)

        if not self.tracer.crash_mode:
            l.error("input provided did not cause a crash in %s", binary)
            raise NonCrashingInput

        # run the tracer, grabbing the crash state
        t_result = self.tracer.run()
        if not isinstance(t_result, tuple):
            l.warning("TODO unable to analyze crash because angr deadended")
            raise NonCrashingInput

        prev, state = t_result

        # a path leading up to the crashing basic block
        self.prev   = prev

        # the state at crash time
        self.state  = state

        # crash type
        self.crash_type = None

        self.symbolic_mem = { }


        region_tails = { }
        for act in prev.actions:
            if act.type == "mem" and act.action == "write":
                what = act.data.ast
                if not (isinstance(what, int) or isinstance(what, long)):
                    if self.state.se.symbolic(what):
                        what_l = len(what) / 8
                        if self.state.se.symbolic(act.addr.ast):
                            l.warning("symbolic write target address is symbolic")
                        target = self.state.se.any_int(act.addr.ast)
                        if target in region_tails:
                            region_key = region_tails[target]
                            while region_key not in self.symbolic_mem:
                                region_key = region_tails[region_key]
                            self.symbolic_mem[region_key] += what_l
                        elif (target + what_l) in self.symbolic_mem:
                            self.symbolic_mem[target] = what_l + self.symbolic_mem[target + what_l]
                        elif target not in self.symbolic_mem or (self.symbolic_mem[target] + what_l) > self.symbolic_mem[target]:
                            self.symbolic_mem[target] = what_l

                        region_tails[target + what_l] = target

### EXPOSED
    def exploitable(self):
        '''
        determine if the crash is exploitable
        '''

        ip = self.state.regs.ip
        bp = self.state.regs.bp

        # we assume a symbolic eip is always exploitable
        if self.state.se.symbolic(ip):
            # how much control of ip do we have?
            if self._symbolic_control(ip) == self.state.arch.bits:
                l.info("detected ip overwrite vulnerability")
                self.crash_type = Vulnerability.IP_OVERWRITE
            else:
                l.info("detected partial ip overwrite vulnerability")
                self.crash_type = Vulnerability.PARTIAL_IP_OVERWRITE

            return True

        # XXX
        # not sure how easily exploitable this will be unless they start
        # using the leave instruction
        if self.state.se.symbolic(bp):
            # how much control of bp do we have
            if self._symbolic_control(bp) == self.state.arch.bits:
                l.info("detected bp overwrite vulnerability")
                self.crash_type = Vulnerability.BP_OVERWRITE
            else:
                l.info("detected partial bp overwrite vulnerability")
                self.crash_type = Vulnerability.PARTIAL_BP_OVERWRITE

            return True

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

                return True

        return False

    def exploit(self, **kwargs):
        '''
        craft an exploit for a crash
        '''

        # if this crash hasn't been classified, classify it now
        if self.crash_type == None:
            if not self.exploitable():
                raise CannotExploit

        os = self._p.loader.main_bin.os
        if os == "cgc":
            exploit = CGCExploit(self, **kwargs)
        elif os == "unix":
            exploit = LinuxExploit(self, **kwargs)
        else:
            raise CannotExploit("unimplemented OS")

        exploit.initialize()
        return exploit

### UTIL

    def _symbolic_control(self, ast):
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
