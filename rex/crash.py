import logging

l = logging.getLogger("rex.Crash")

import os
import angr
import angrop
import tracer
import hashlib
from rex.exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from rex.vulnerability import Vulnerability
from simuvex import SimMemoryError, s_options as so

class NonCrashingInput(Exception):
    pass

class Crash(object):
    '''
    Triage a crash using angr.
    '''

    def __init__(self, binary, crash=None, pov_file=None, aslr=None, constrained_addrs=None, crash_state=None,
                 prev_path=None):
        '''
        :param binary: path to the binary which crashed
        :param crash: string of input which crashed the binary
        :param pov_file: CGC PoV describing a crash
        :param aslr: analyze the crash with aslr on or off
        :param constrained_addrs: list of addrs which have been constrained during exploration
        :param crash_state: an already traced crash state
        :param prev_path: path leading up to the crashing block
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

        if crash_state is None:
            # run the tracer, grabbing the crash state
            remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                              so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS}
            add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                           so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES}
            self._tracer = tracer.Tracer(binary, input=self.crash, pov_file=self.pov_file, resiliency=False,
                                         add_options=add_options, remove_options=remove_options)
            prev, crash_state = self._tracer.run(constrained_addrs)

            if crash_state is None:
                l.warning("input did not cause a crash")
                raise NonCrashingInput

            l.debug("done tracing input")
            # a path leading up to the crashing basic block
            self.prev   = prev

            # the state at crash time
            self.state  = crash_state
        else:
            self.state = crash_state
            self.prev = prev_path
            self._tracer = None

        # list of actions added during exploitation, probably better object for this attribute to belong to
        self.added_actions = [ ]

        # hacky trick to get all bytes
        #memory_writes = [ ]
        #for var in self.state.memory.mem._name_mapping.keys():
        #    memory_writes.extend(self.state.memory.addrs_for_name(var))

        memory_writes = sorted(self.state.memory.mem.get_symbolic_addrs())
        l.debug("filtering writes")
        memory_writes = [m for m in memory_writes if m/0x1000 != 0x4347c]
        memory_writes = [m for m in memory_writes if any("stdin" in v for v in self.state.memory.load(m, 1).variables)]
        l.debug("done filtering writes")

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

        return self.crash_type in [Vulnerability.ARBITRARY_READ, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

    def exploit(self, blacklist_symbolic_explore=True, **kwargs):
        '''
        craft an exploit for a crash
        '''

        # crash should have been classified at this point
        if not self.exploitable():
            raise CannotExploit("non-exploitable crash")

        if blacklist_symbolic_explore:
            if "blacklist_techniques" in kwargs:
                kwargs["blacklist_techniques"].add("explore_for_exploit")
            else:
                kwargs["blacklist_techniques"] = {"explore_for_exploit"}

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

        if self.crash_type in [Vulnerability.ARBITRARY_READ]:
            self._explore_arbitrary_read(path_file)
        elif self.crash_type in [Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]:
            self._explore_arbitrary_write(path_file)
        else:
            raise ValueError("unknown explorable crash type: %s", self.crash_type)

    def point_to_flag(self, path_file=None):
        '''
        Create a testcase which points an arbitrary-read crash at the flag page.

        :param path_file: file to dump testcase to
        '''

        if not self.crash_type in [Vulnerability.ARBITRARY_READ]:
            raise CannotExploit("only arbitrary-reads can be exploited this way")

        # iterate over addr seeing if we can find an acceptable address to point to
        cgc_magic_page_addr = 0x4347c000
        addr = cgc_magic_page_addr
        while addr < cgc_magic_page_addr + 0x1000 and \
            not self.state.se.satisfiable(extra_constraints=(self.violating_action.addr == addr,)):
            addr += 1

        if addr >= cgc_magic_page_addr + 0x1000:
            raise CannotExploit("unable to point arbitrary-read at the flag page")

        cp = self.state.copy()
        cp.add_constraints(self.violating_action.addr == addr)
        new_input = cp.posix.dumps(0)

        if path_file is not None:
            with open(path_file, 'w') as f:
                f.write(new_input)

        return new_input

    def _explore_arbitrary_read(self, path_file=None):
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

        read_addr = max_addr
        self.state.add_constraints(self.violating_action.addr == read_addr)
        l.debug("constraining input to read from address %#x", read_addr)

        l.info("starting a new crash exploration phase based off the crash at address 0x%x", self.violating_action.ins_addr)

        new_input = self.state.posix.dumps(0)
        if path_file is not None:
            l.info("dumping new crash evading input into file '%s'", path_file)
            with open(path_file, 'w') as f:
                f.write(new_input)

        # create a new crash object starting here
        self.__init__(self.binary, new_input, constrained_addrs=self.constrained_addrs + [self.violating_action])

    def _explore_arbitrary_write(self, path_file=None):
        # crash type was an arbitrary-write, this routine doesn't care about taking advantage of the write
        # it just wants to try to find a more valuable crash by pointing the write at some writable memory

        # find a writable data segment

        elf_objects = self.project.loader.all_elf_objects

        assert len(elf_objects) > 0, "target binary is not ELF or CGC, unsupported by rex"

        chosen_segment = None
        for eobj in elf_objects:
            for segment in eobj.segments:
                if segment.is_writable:
                    chosen_segment = segment
                    break
            if chosen_segment is not None:
                break

        assert chosen_segment is not None, "unable to find a writable segment, TODO: look through dynamically allocd mem"

        write_addr = chosen_segment.min_addr
        self.state.add_constraints(self.violating_action.addr == write_addr)
        l.debug("constraining input to write to address %#x", write_addr)

        l.info("starting a new crash exploration phase based off the crash at address %#x", self.violating_action.ins_addr)

        new_input = self.state.posix.dumps(0)
        if path_file is not None:
            l.info("dumping new crash evading input into file '%s'", path_file)
            with open(path_file, 'w') as f:
                f.write(new_input)

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
        cp.added_actions = list(self.added_actions)
        cp.symbolic_mem = self.symbolic_mem.copy()
        cp.crash_type = self.crash_type
        cp._tracer = self._tracer

        return cp

### UTIL

    def _symbolic_control(self, st):
        '''
        determine the amount of symbolic bits in an ast, useful to determining how much control we have
        over registers
        '''

        sbits = 0

        for bitidx in xrange(self.state.arch.bits):
            if st[bitidx].symbolic:
                sbits += 1

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
        for a in list(self.prev.state.log.actions) + list(self.state.log.actions):
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

### CLASS METHODS
    @classmethod
    def quick_triage(cls, binary, crash):
        """
        Quickly triage a crash with just QEMU. Less accurate, but much faster.
        :param binary: path to binary which crashed
        :param crash: input which caused crash
        :return: a vulnerability classification, or None if crash could not be classified
        """

        l.debug("quick triaging crash against '%s'", binary)
        r = tracer.Runner(binary, crash)
        if not r.crash_mode:
            raise NonCrashingInput("input did not cause a crash")

        if r.os != "cgc":
            raise ValueError("quick_triage is only available for CGC binaries")

        project = angr.Project(binary)
        # triage the crash based of the register values and memory at crashtime
        # look for the most valuable crashes first

        pc = r.reg_vals['eip']
        l.debug("checking if ip is null")
        if pc == 0:
            return Vulnerability.NULL_DEREFERENCE

        l.debug("checking if ip register points to executable memory")
        # was ip mapped?
        ip_overwritten = False
        try:
            perms = r.memory.permissions(pc)
            # check if the execute bit is marked, this is an AST
            l.debug("ip points to mapped memory")
            if not perms.symbolic and not ((perms & 4) == 4).args[0]:
                ip_overwritten = True

        except SimMemoryError:
            ip_overwritten = True

        if ip_overwritten:
            # let's see if we can classify it as a partial overwrite
            # this is done by seeing if the most signifigant bytes of
            # pc could be a mapping
            cgc_object = project.loader.all_elf_objects[0]
            base = cgc_object.get_min_addr() & 0xff000000
            while base < cgc_object.get_max_addr():
                if pc & 0xff000000 == base:
                    return Vulnerability.PARTIAL_IP_OVERWRITE
                base += 0x01000000

            return Vulnerability.IP_OVERWRITE

        l.debug("checking if a read or write caused the crash")
        # wasn't an ip overwrite, check reads and writes
        start_state = project.factory.entry_state(addr=pc)
        pth = project.factory.path(start_state)
        next_pth = pth.step(num_inst=1)[0]

        posit = None
        for a in next_pth.actions:
            if a.type == 'mem':

                # we will take the last memory action, so things like an `add` instruction
                # are triaged as a 'write' opposed to a 'read'
                if a.action == 'write':
                    l.debug("write detected")
                    posit = Vulnerability.WRITE_WHAT_WHERE
                elif a.action == 'read':
                    l.debug("read detected")
                    posit = Vulnerability.ARBITRARY_READ
                else:
                    # sanity checking
                    raise ValueError("unrecognized memory action encountered %s" % a.action)

        if posit is None:
            l.debug("crash was not able to be triaged")
            posit = 'unknown'

        # returning 'unknown' if crash does not fall into one of our obvious categories
        return posit
