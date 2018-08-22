import logging

from tracer import TracerPoV

l = logging.getLogger("rex.Crash")

import os
import angr
import random
import tracer
import hashlib
import operator
from rex.exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from rex.vulnerability import Vulnerability
from angr import sim_options as so
from angr.state_plugins.trace_additions import ChallRespInfo, ZenPlugin
from angr.state_plugins.preconstrainer import SimStatePreconstrainer
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream


class NonCrashingInput(Exception):
    pass


class Crash(object):
    """
    Triage a crash using angr.
    """

    def __init__(self, binary, crash=None, pov_file=None, aslr=None, constrained_addrs=None, crash_state=None,
                 prev_path=None, hooks=None, format_infos=None, rop_cache_tuple=None, use_rop=True,
                 explore_steps=0, angrop_object=None, argv=None):
        """
        :param binary           : Path to the binary which crashed.
        :param crash            : String of input which crashed the binary.
        :param pov_file         : CGC PoV describing a crash.
        :param aslr             : Analyze the crash with aslr on or off.
        :param constrained_addrs: List of addrs which have been constrained
                                  during exploration.
        :param crash_state      : An already traced crash state.
        :param prev_path        : Path leading up to the crashing block.
        :param hooks            : Dictionary of simprocedure hooks, addresses
                                  to simprocedures.
        :param format_infos     : A list of atoi FormatInfo objects that should
                                  be used when analyzing the crash.
        :param rop_cache_tuple  : A angrop tuple to load from.
        :param use_rop          : Whether or not to use rop.
        :param explore_steps    : Number of steps which have already been explored, should
                                  only set by exploration methods.
        :param angrop_object    : An angrop object, should only be set by
                                  exploration methods.
        :param argv             : Optionally specify argv params (i,e,: ['./calc', 'parm1']).
        """

        self.binary = binary
        self.crash  = crash
        self.constrained_addrs = [ ] if constrained_addrs is None else constrained_addrs
        self.hooks = {} if hooks is None else hooks
        self.explore_steps = explore_steps

        if self.explore_steps > 10:
            raise CannotExploit("Too many steps taken during crash exploration")

        self.project = angr.Project(binary)
        for addr, proc in self.hooks.items():
            self.project.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)

        # we search for ROP gadgets now to avoid the memory exhaustion bug in pypy
        # hash binary contents for rop cache name
        binhash = hashlib.md5(open(self.binary, 'rb').read()).hexdigest()
        rop_cache_path = os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(self.binary), binhash))

        if use_rop:
            if angrop_object is not None:
                self.rop = angrop_object
            else:
                self.rop = self.project.analyses.ROP()
                if rop_cache_tuple is not None:
                    l.info("loading rop gadgets from cache tuple")
                    self.rop._load_cache_tuple(rop_cache_tuple)
                elif os.path.exists(rop_cache_path):
                    l.info("loading rop gadgets from cache '%s'", rop_cache_path)
                    self.rop.load_gadgets(rop_cache_path)
                else:
                    if angr.misc.testing.is_testing:
                        self.rop.find_gadgets_single_threaded(show_progress=False)
                    else:
                        self.rop.find_gadgets(show_progress=False)
                    self.rop.save_gadgets(rop_cache_path)
        else:
            self.rop = None

        if self.project.loader.main_object.os == 'cgc':
            self.project.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

        self.os = self.project.loader.main_object.os

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
                              so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES}
            add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                           so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS}

            # faster place to check for non-crashing inputs

            # optimized crash check
            if self.project.loader.main_object.os == 'cgc':

                if not tracer.QEMURunner(binary, input=self.crash).crash_mode:
                    if not tracer.QEMURunner(binary, input=self.crash, report_bad_args=True).crash_mode:
                        l.warning("input did not cause a crash")
                        raise NonCrashingInput

            if pov_file is None and self.crash is None:
                raise ValueError("must specify crash or pov_file")

            if pov_file is not None and self.crash is not None:
                raise ValueError("cannot specify both a pov_file and an crash")

            if pov_file is not None:
                input_data = TracerPoV(pov_file)
            else:
                input_data = self.crash

            r = tracer.QEMURunner(binary=binary, input=input_data, argv=argv)

            kwargs = {}
            if self.project.loader.main_object.os == 'cgc':
                cgc = True
            elif self.project.loader.main_object.os.startswith('UNIX'):
                if argv is None:
                    argv = ['./binary']
                kwargs['args'] = argv
                cgc = False
            else:
                raise ValueError("Can't analyze binary for OS %s" % self.project.loader.main_object.os)

            s = self.project.factory.full_init_state(
                mode='tracing',
                add_options=add_options,
                remove_options=remove_options,
                **kwargs
            )
            s.register_plugin('posix', SimSystemPosix(
                stdin=SimFileStream(name='stdin', ident='aeg_stdin'),
                stdout=SimFileStream(name='stdout'),
                stderr=SimFileStream(name='stderr'),
                argc=s.posix.argc,
                argv=s.posix.argv,
                environ=s.posix.environ,
                auxv=s.posix.auxv,
            ))
            s.register_plugin('preconstrainer', SimStatePreconstrainer(self.constrained_addrs))
            s.preconstrainer.preconstrain_file(input_data, s.posix.stdin, True)
            if cgc:
                s.preconstrainer.preconstrain_flag_page(r.magic)

            simgr = self.project.factory.simgr(
                s,
                save_unsat=True,
                hierarchy=False,
                save_unconstrained=r.crash_mode
            )

            self._t = angr.exploration_techniques.Tracer(trace=r.trace, resiliency=False, keep_predecessors=2)
            if r.crash_mode:
                self._c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                                   crash_addr=r.crash_addr)
                simgr.use_technique(self._c)
            simgr.use_technique(self._t)
            simgr.use_technique(angr.exploration_techniques.Oppologist())

            if cgc:
                s = simgr.one_active
                ChallRespInfo.prep_tracer(s, format_infos)
                ZenPlugin.prep_tracer(s)

            simgr.run()

            # if there was no crash we'll have to use the previous path's state
            if 'crashed' in simgr.stashes:
                # the state at crash time
                self.state = simgr.crashed[0]
                # a path leading up to the crashing basic block
                self.prev = self._t.predecessors[-1]
            else:
                self.state = simgr.traced[0]
                self.prev = self.state

            zp = self.state.get_plugin('zen_plugin') if cgc else None
            if 'crashed' not in simgr.stashes and zp is not None and len(zp.controlled_transmits) == 0:
                l.warning("input did not cause a crash")
                raise NonCrashingInput

            l.debug("done tracing input")

        else:
            self.state = crash_state
            self.prev = prev_path
            self._t = None
            self._c = None

        # list of actions added during exploitation, probably better object for this attribute to belong to
        self.added_actions = [ ]

        # hacky trick to get all bytes
        #memory_writes = [ ]
        #for var in self.state.memory.mem._name_mapping.keys():
        #    memory_writes.extend(self.state.memory.addrs_for_name(var))

        memory_writes = sorted(self.state.memory.mem.get_symbolic_addrs())
        l.debug("filtering writes")
        memory_writes = [m for m in memory_writes if m//0x1000 != 0x4347c]
        user_writes = [m for m in memory_writes if any("stdin" in v for v in self.state.memory.load(m, 1).variables)]
        flag_writes = [m for m in memory_writes if any(v.startswith("cgc-flag") for v in self.state.memory.load(m, 1).variables)]
        l.debug("done filtering writes")

        self.symbolic_mem = self._segment(user_writes)
        self.flag_mem = self._segment(flag_writes)

        # crash type
        self.crash_types = [ ]
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

        return self.one_of(exploitables)

    def explorable(self):
        '''
        determine if the crash can be explored with the 'crash explorer'.
        :return: True if the crash's type lends itself to exploring, only 'arbitrary-read' for now
        '''

        # TODO add arbitrary receive into this list
        explorables = [Vulnerability.ARBITRARY_READ, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

        return self.one_of(explorables)

    def leakable(self):
        '''
        determine if the crash can potentially cause an information leak using the point-to-flag technique
        :return: True if the 'point-to-flag' technique can be applied to this crash
        '''

        return self.one_of([Vulnerability.ARBITRARY_READ, Vulnerability.ARBITRARY_TRANSMIT])

    def _prepare_exploit_factory(self, blacklist_symbolic_explore=True, **kwargs):
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

        return exploit

    def exploit(self, blacklist_symbolic_explore=True, **kwargs):
        '''
        craft an exploit for a crash
        '''

        factory = self._prepare_exploit_factory(blacklist_symbolic_explore, **kwargs)

        factory.initialize()
        return factory

    def yield_exploits(self, blacklist_symbolic_explore=True, **kwargs):
        '''
        craft an exploit for a crash
        '''

        factory = self._prepare_exploit_factory(blacklist_symbolic_explore, **kwargs)

        for exploit in factory.yield_exploits():
            yield exploit

    def explore(self, path_file=None):
        '''
        explore a crash further to find new bugs
        '''

        # crash should be classified at this point
        if not self.explorable():
                raise CannotExplore("non-explorable crash")

        self._reconstrain_flag_data(self.state)

        assert self.violating_action is not None

        if self.one_of([Vulnerability.ARBITRARY_READ]):
            self._explore_arbitrary_read(path_file)
        elif self.one_of([Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]):
            self._explore_arbitrary_write(path_file)
        else:
            raise CannotExplore("unknown explorable crash type: %s", self.crash_types)

    def point_to_flag(self):
        '''
        Create a testcase which points an arbitrary-read crash at the flag page.
        '''
        if not self.one_of([Vulnerability.ARBITRARY_READ, Vulnerability.ARBITRARY_TRANSMIT]):
            raise CannotExploit("only arbitrary-reads can be exploited this way")

        violating_actions = [ ]

        if self.one_of([Vulnerability.ARBITRARY_READ]):
            if self.violating_action:
                violating_actions.append((self.state, self.violating_action.addr))

        if self.project.loader.main_object.os == 'cgc':
            zp = self.state.get_plugin('zen_plugin')
            for st, addr in zp.controlled_transmits:
                st.preconstrainer.remove_preconstraints()
                violating_actions.append((st, addr))

        for st, va in violating_actions:
            try:
                cp = self._get_state_pointing_to_flag(st, va)
                self._reconstrain_flag_data(cp)
                yield ChallRespInfo.atoi_dumps(cp)
            except CannotExploit:
                l.warning("crash couldn't be pointed at flag skipping")
                pass

        # look for contiguous flag bytes of length 4 or longer and try to leak only one
        max_tries = 20
        num_tries = 0
        for start, length in self.flag_mem.items():
            if length < 4:
                continue
            data = self.state.memory.load(start, length)
            four_flag_offset = self._four_flag_bytes_offset(data)
            if four_flag_offset is not None:
                leak_addr = start + four_flag_offset
                l.debug("found flag at addr %#x", leak_addr)
                for st, va in violating_actions:
                    if num_tries > max_tries:
                        l.warning("passed the maximum number of tries")
                        break
                    num_tries += 1
                    try:
                        cp = self._get_state_pointing_to_addr(st, va, leak_addr)
                        self._reconstrain_flag_data(cp)
                        l.debug("pointed successfully")
                        yield ChallRespInfo.atoi_dumps(cp)
                        # okay we got one we are done
                        return
                    except CannotExploit:
                        l.warning("crash couldn't be pointed at flag skipping")
                        pass

    @staticmethod
    def _four_flag_bytes_offset(ast):
        """
        checks if an ast contains 4 contiguous flag bytes
        if so returns the offset in bytes, otherwise returns None
        :return: the offset or None
        """
        if ast.op != "Concat":
            return None

        offset = 0
        flag_start_off = None
        first_flag_index = None

        for arg in ast.args:
            # if it's not byte aligned
            if offset % 8 != 0:
                offset += arg.size()//8
                continue

            # check if the arg is a flag byte
            if arg.op == "BVS" and len(arg.variables) == 1 and list(arg.variables)[0].startswith("cgc-flag-byte-"):
                # we found a flag byte
                flag_byte = int(list(arg.variables)[0].split("-")[-1].split("_")[0], 10)

                if flag_start_off is None:
                    # no start
                    flag_start_off = offset // 8
                    first_flag_index = flag_byte
                elif (offset//8 - flag_start_off) != flag_byte - first_flag_index:
                    # not contiguous
                    flag_start_off = offset//8
                    first_flag_index = flag_byte
                else:
                    # contiguous
                    if flag_byte-first_flag_index == 3:
                        return flag_start_off
            else:
                flag_start_off = None
                first_flag_index = None

            offset += arg.size()

        return None

    @staticmethod
    def _get_state_pointing_to_flag(state, violating_addr):
        cgc_magic_page_addr = 0x4347c000

        # see if we can point randomly inside the flag (prevent people filtering exactly 0x4347c000)
        rand_addr = random.randint(cgc_magic_page_addr, cgc_magic_page_addr+0x1000-4)
        if state.se.satisfiable(extra_constraints=(violating_addr == rand_addr,)):
            cp = state.copy()
            cp.add_constraints(violating_addr == rand_addr)
            return cp

        # see if we can point anywhere at flag
        if state.se.satisfiable(extra_constraints=
                                (violating_addr >= cgc_magic_page_addr,
                                 violating_addr < cgc_magic_page_addr+0x1000-4)):
            cp = state.copy()
            cp.add_constraints(violating_addr >= cgc_magic_page_addr)
            cp.add_constraints(violating_addr < cgc_magic_page_addr+0x1000-4)
            return cp
        else:
            raise CannotExploit("unable to point arbitrary-read at the flag page")

    @staticmethod
    def _get_state_pointing_to_addr(state, violating_addr, goal_addr):
        if state.se.satisfiable(extra_constraints=(violating_addr == goal_addr,)):
            cp = state.copy()
            cp.add_constraints(violating_addr == goal_addr)
            return cp
        else:
            raise CannotExploit("unable to point arbitrary-read at the flag copy")


    def _explore_arbitrary_read(self, path_file=None):
        # crash type was an arbitrary-read, let's point the violating address at a
        # symbolic memory region

        largest_regions = sorted(self.symbolic_mem.items(),
                key=operator.itemgetter(1),
                reverse=True)

        min_read = self.state.se.min(self.violating_action.addr)
        max_read = self.state.se.max(self.violating_action.addr)

        # filter addresses which fit between the min and max possible address
        largest_regions = [x[0] for x in largest_regions if min_read <= x[0] <= max_read]

        # populate the rest of the list with addresses from the binary
        min_addr = self.project.loader.main_object.min_addr
        max_addr = self.project.loader.main_object.max_addr
        pages = range(min_addr, max_addr, 0x1000)
        pages = [x for x in pages if min_read <= x <= max_read]

        read_addr = None
        constraint = None
        for addr in largest_regions + pages:
            read_addr = addr
            constraint = self.violating_action.addr == addr

            if self.state.se.satisfiable(extra_constraints=(constraint,)):
                break

            constraint = None

        if constraint is None:
            raise CannotExploit("unable to find suitable read address, cannot explore")

        self.state.add_constraints(constraint)

        l.debug("constraining input to read from address %#x", read_addr)

        l.info("starting a new crash exploration phase based off the crash at address 0x%x", self.violating_action.ins_addr)

        new_input = ChallRespInfo.atoi_dumps(self.state)
        if path_file is not None:
            l.info("dumping new crash evading input into file '%s'", path_file)
            with open(path_file, 'w') as f:
                f.write(new_input)

        # create a new crash object starting here
        use_rop = False if self.rop is None else True
        self.__init__(self.binary,
                new_input,
                explore_steps=self.explore_steps + 1,
                constrained_addrs=self.constrained_addrs + [self.violating_action],
                use_rop=use_rop,
                angrop_object=self.rop)

    def _explore_arbitrary_write(self, path_file=None):
        # crash type was an arbitrary-write, this routine doesn't care about taking advantage
        # of the write it just wants to try to find a more valuable crash by pointing the write
        # at some writable memory

        # find a writable data segment

        elf_objects = self.project.loader.all_elf_objects

        assert len(elf_objects) > 0, "target binary is not ELF or CGC, unsupported by rex"

        min_write = self.state.se.min(self.violating_action.addr)
        max_write = self.state.se.max(self.violating_action.addr)

        segs = [ ]
        for eobj in elf_objects:
            segs.extend(filter(lambda s: s.is_writable, eobj.segments))

        segs = [s for s in segs if s.min_addr <= min_write <= s.max_addr or min_write <= s.min_addr <= max_write]

        write_addr = None
        constraint = None
        for seg in segs:
            for page in range(seg.min_addr, seg.max_addr, 0x1000):
                write_addr = page
                constraint = self.violating_action.addr == page

                if self.state.se.satisfiable(extra_constraints=(constraint,)):
                    break

                constraint = None

        if constraint is None:
            raise CannotExploit("Cannot point write at any writeable segments")

        self.state.add_constraints(constraint)
        l.debug("constraining input to write to address %#x", write_addr)

        l.info("starting a new crash exploration phase based off the crash at address %#x",
                self.violating_action.ins_addr)
        new_input = ChallRespInfo.atoi_dumps(self.state)
        if path_file is not None:
            l.info("dumping new crash evading input into file '%s'", path_file)
            with open(path_file, 'w') as f:
                f.write(new_input)

        use_rop = False if self.rop is None else True
        self.__init__(self.binary,
                new_input,
                explore_steps=self.explore_steps + 1,
                constrained_addrs=self.constrained_addrs + [self.violating_action],
                use_rop=use_rop,
                angrop_object=self.rop)

    def copy(self):
        cp = Crash.__new__(Crash)
        cp.binary = self.binary
        cp.crash = self.crash
        cp.project = self.project
        cp.os = self.os
        cp.aslr = self.aslr
        cp.prev = self.prev.copy()
        cp.state = self.state.copy()
        cp.rop = self.rop
        cp.added_actions = list(self.added_actions)
        cp.symbolic_mem = self.symbolic_mem.copy()
        cp.flag_mem = self.flag_mem.copy()
        cp.crash_types = self.crash_types
        cp._t = self._t
        cp._c = self._c
        cp.violating_action = self.violating_action
        cp.explore_steps = self.explore_steps
        cp.constrained_addrs = list(self.constrained_addrs)

        return cp

### UTIL
    def _reconstrain_flag_data(self, state):

        l.info("reconstraining flag")

        replace_dict = dict()
        for c in state.preconstrainer.preconstraints:
            if any([v.startswith('cgc-flag') or v.startswith("random") for v in list(c.variables)]):
                concrete = next(a for a in c.args if not a.symbolic)
                symbolic = next(a for a in c.args if a.symbolic)
                replace_dict[symbolic.cache_key] = concrete
        cons = state.se.constraints
        new_cons = []
        for c in cons:
            new_c = c.replace_dict(replace_dict)
            new_cons.append(new_c)
        state.release_plugin("solver")
        state.add_constraints(*new_cons)
        state.downsize()
        state.se.simplify()

    def one_of(self, crash_types):
        '''
        Test if a self's crash has one of the vulnerabilities described in crash_types
        '''

        if not isinstance(crash_types, (list, tuple)):
            crash_types = [crash_types]

        return bool(len(set(self.crash_types).intersection(set(crash_types))))

    @staticmethod
    def _segment(memory_writes):
        segments = { }
        memory_writes = sorted(memory_writes)

        if len(memory_writes) == 0:
            return segments

        current_w_start = memory_writes[0]
        current_w_end = current_w_start + 1

        for write in memory_writes[1:]:
            write_start = write
            write_len = 1

            # segment is completely seperate
            if write_start > current_w_end:
                # store the old segment
                segments[current_w_start] = current_w_end - current_w_start

                # new segment, update start and end
                current_w_start = write_start
                current_w_end = write_start + write_len
            else:
                # update the end of the current segment, the segment `write` exists within current
                current_w_end = max(current_w_end, write_start + write_len)


        # write in the last segment
        segments[current_w_start] = current_w_end - current_w_start

        return segments

    def _symbolic_control(self, st):
        '''
        determine the amount of symbolic bits in an ast, useful to determining how much control we have
        over registers
        '''

        sbits = 0

        for bitidx in range(self.state.arch.bits):
            if st[bitidx].symbolic:
                sbits += 1

        return sbits

    def _triage_crash(self):
        ip = self.state.regs.ip
        bp = self.state.regs.bp

        # any arbitrary receives or transmits
        # TODO: receives
        zp = self.state.get_plugin('zen_plugin') if self.project.loader.main_object.os == 'cgc' else None
        if zp is not None and len(zp.controlled_transmits):
            l.debug("detected arbitrary transmit vulnerability")
            self.crash_types.append(Vulnerability.ARBITRARY_TRANSMIT)

        # we assume a symbolic eip is always exploitable
        if self.state.se.symbolic(ip):
            # how much control of ip do we have?
            if self._symbolic_control(ip) >= self.state.arch.bits:
                l.info("detected ip overwrite vulnerability")
                self.crash_types.append(Vulnerability.IP_OVERWRITE)
            else:
                l.info("detected partial ip overwrite vulnerability")
                self.crash_types.append(Vulnerability.PARTIAL_IP_OVERWRITE)

            return

        if self.state.se.symbolic(bp):
            # how much control of bp do we have
            if self._symbolic_control(bp) >= self.state.arch.bits:
                l.info("detected bp overwrite vulnerability")
                self.crash_types.append(Vulnerability.BP_OVERWRITE)
            else:
                l.info("detected partial bp overwrite vulnerability")
                self.crash_types.append(Vulnerability.PARTIAL_BP_OVERWRITE)

            return

        # if nothing obvious is symbolic let's look at actions

        # grab the all actions in the last basic block
        symbolic_actions = [ ]
        if self._c is not None:
            recent_actions = reversed(self._c.last_state.history.recent_actions)
            state = self._c.last_state
        else:
            recent_actions = reversed(self.state.history.actions)
            state = self.state
        for a in recent_actions:
            if a.type == 'mem':
                if self.state.se.symbolic(a.addr):
                    symbolic_actions.append(a)

        # TODO: pick the crashing action based off the crashing instruction address,
        # crash fixup attempts will break on this
       #import ipdb; ipdb.set_trace()
        for sym_action in symbolic_actions:
            if sym_action.action == "write":
                if self.state.se.symbolic(sym_action.data):
                    l.info("detected write-what-where vulnerability")
                    self.crash_types.append(Vulnerability.WRITE_WHAT_WHERE)
                else:
                    l.info("detected write-x-where vulnerability")
                    self.crash_types.append(Vulnerability.WRITE_X_WHERE)

                self.violating_action = sym_action
                break

            if sym_action.action == "read":
                # special vulnerability type, if this is detected we can explore the crash further
                l.info("detected arbitrary-read vulnerability")
                self.crash_types.append(Vulnerability.ARBITRARY_READ)

                self.violating_action = sym_action
                break

        return

class QuickCrash(object):

    def __init__(self, binary, crash, argv=None):
        """
        Quickly triage a crash with just QEMU. Less accurate, but much faster.
        :param binary: Path to binary which crashed.
        :param crash : Input which caused crash.
        :param argv  : Optionally specify argv params (i,e,: ['./calc', 'parm1']).
        """

        self.binary = binary

        self.crash = crash

        self.bb_count = None
        self.crash_pc, self.kind = self._quick_triage(binary, crash, argv=argv)

    def _quick_triage(self, binary, crash, argv=None):

        l.debug("quick triaging crash against '%s'", binary)

        arbitrary_syscall_arg = False
        r = tracer.QEMURunner(binary, crash, record_trace=True, use_tiny_core=True, record_core=True, argv=argv)

        self.bb_count = len(r.trace)

        if not r.crash_mode:

            # try again to catch bad args
            r = tracer.QEMURunner(binary, crash, report_bad_args=True, record_core=True, argv=argv)
            arbitrary_syscall_arg = True
            if not r.crash_mode:
                raise NonCrashingInput("input did not cause a crash")

            l.debug("detected an arbitrary transmit or receive")

        if r.os != "cgc":
            raise ValueError("QuickCrash is only available for CGC binaries")

        if r.is_multicb:
            project = angr.Project(binary[r.crashed_binary])
        else:
            project = angr.Project(binary)

        # triage the crash based of the register values and memory at crashtime
        # look for the most valuable crashes first

        pc = r.reg_vals['eip']
        l.debug('crash occured at %#x', pc)

        if arbitrary_syscall_arg:
            l.debug("checking which system call had bad args")

            syscall_num = r.reg_vals['eax']
            vulns = {2: Vulnerability.ARBITRARY_TRANSMIT,
                     3: Vulnerability.ARBITRARY_RECEIVE}

            # shouldn't ever happen but in case it does
            if syscall_num not in vulns:
                return pc, None

            return pc, vulns[syscall_num]

        l.debug("checking if ip is null")
        if pc < 0x1000:
            return pc, Vulnerability.NULL_DEREFERENCE

        l.debug("checking if ip register points to executable memory")

        if project.loader.main_object.os == 'cgc':
            start_state = project.factory.entry_state(addr=pc, add_options={so.TRACK_MEMORY_ACTIONS})
        elif project.loader.main_object.os.startswith('UNIX'):
            start_state = project.factory.entry_state(addr=pc, add_options={so.TRACK_MEMORY_ACTIONS}, args=argv)
        else:
            raise ValueError("Can't analyse OS %s" % project.loader.main_object.os)

        # was ip mapped?
        ip_overwritten = False
        try:
            perms = start_state.memory.permissions(pc)
            # check if the execute bit is marked, this is an AST
            l.debug("ip points to mapped memory")
            if not perms.symbolic and not ((perms & 4) == 4).args[0]:
                l.debug("ip appears to be uncontrolled")
                return pc, Vulnerability.UNCONTROLLED_IP_OVERWRITE

        except angr.SimMemoryError:
            ip_overwritten = True

        if ip_overwritten:
            # let's see if we can classify it as a partial overwrite
            # this is done by seeing if the most signifigant bytes of
            # pc could be a mapping
            cgc_object = project.loader.all_elf_objects[0]
            base = cgc_object.min_addr & 0xff000000
            while base < cgc_object.max_addr:
                if pc & 0xff000000 == base:
                    l.debug("ip appears to only be partially controlled")
                    return pc, Vulnerability.PARTIAL_IP_OVERWRITE
                base += 0x01000000

            l.debug("ip appears to be completely controlled")
            return pc, Vulnerability.IP_OVERWRITE

        # wasn't an ip overwrite, check reads and writes
        l.debug("checking if a read or write caused the crash")

        # set registers
        start_state.regs.eax = r.reg_vals['eax']
        start_state.regs.ebx = r.reg_vals['ebx']
        start_state.regs.ecx = r.reg_vals['ecx']
        start_state.regs.edx = r.reg_vals['edx']
        start_state.regs.esi = r.reg_vals['esi']
        start_state.regs.edi = r.reg_vals['edi']
        start_state.regs.esp = r.reg_vals['esp']
        start_state.regs.ebp = r.reg_vals['ebp']

        next_pth = project.factory.successors(start_state, num_inst=1).successors[0]

        posit = None
        for a in next_pth.history.recent_actions:
            if a.type == 'mem':

                target_addr = start_state.se.eval(a.addr)
                if target_addr < 0x1000:
                    l.debug("attempt to write or read to address of NULL")
                    return pc, Vulnerability.NULL_DEREFERENCE

                # we will take the last memory action, so things like an `add` instruction
                # are triaged as a 'write' opposed to a 'read'
                if a.action == 'write':
                    l.debug("write detected")
                    posit = Vulnerability.WRITE_WHAT_WHERE
                    # if it's trying to write to a non-writeable address which is mapped
                    # it's most likely uncontrolled
                    if target_addr & 0xfff00000 == 0:
                        l.debug("write attempt at a suspiciously small address, assuming uncontrolled")
                        return pc, Vulnerability.UNCONTROLLED_WRITE

                    try:
                        perms = start_state.memory.permissions(target_addr)
                        if not perms.symbolic and not ((perms & 2) == 2).args[0]:
                            l.debug("write attempt at a read-only page, assuming uncontrolled")
                            return pc, Vulnerability.UNCONTROLLED_WRITE

                    except angr.SimMemoryError:
                        pass

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
        return pc, posit
