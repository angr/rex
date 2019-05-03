import os
import angr
import random
import hashlib
import logging
import operator
import pickle

from angr import sim_options as so
from angr.state_plugins.trace_additions import ChallRespInfo, ZenPlugin
from angr.state_plugins.preconstrainer import SimStatePreconstrainer
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream
import archr
from tracer import TracerPoV, TinyCore

from .exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from .vulnerability import Vulnerability
from .enums import CrashInputType
from .preconstrained_file_stream import SimPreconstrainedFileStream


l = logging.getLogger("rex.Crash")
l.setLevel(logging.INFO)


class NonCrashingInput(Exception):
    pass


class Crash:
    """
    Triage and exploit a crash using angr.
    """

    def __init__(self, target, crash=None, pov_file=None, aslr=None, constrained_addrs=None,
                 hooks=None, format_infos=None, tracer_bow=None,
                 explore_steps=0,
                 input_type=CrashInputType.STDIN, port=None, use_crash_input=False,
                 checkpoint_path=None, crash_state=None, prev_state=None,
                 #
                 # angrop-related settings
                 #
                 rop_cache_tuple=None, use_rop=True, fast_mode=False, angrop_object=None, rop_cache_path=None,
                 ):
        """
        :param target:              archr Target that contains the binary that crashed.
        :param crash:               String of input which crashed the binary.
        :param pov_file:            CGC PoV describing a crash.
        :param aslr:                Analyze the crash with aslr on or off.
        :param constrained_addrs:   List of addrs which have been constrained
                                    during exploration.
        :param hooks:               Dictionary of simprocedure hooks, addresses
                                    to simprocedures.
        :param format_infos:        A list of atoi FormatInfo objects that should
                                    be used when analyzing the crash.
        :param tracer_bow:          The bow instance to use for tracing operations
        :param explore_steps:       Number of steps which have already been explored, should
                                    only set by exploration methods.
        :param checkpoint_path:     Path to a checkpoint file that provides initial_state, prev_state, crash_state, and
                                    so on.
        :param crash_state:         An already traced crash state.
        :param prev_state:          The predecessor of the final crash state.

        angrop-related settings:
        :param rop_cache_tuple:     A angrop tuple to load from.
        :param use_rop:             Whether or not to use rop.
        :param angrop_object:       An angrop object, should only be set by exploration methods.
        """

        self.target = target # type: archr.targets.Target
        self.constrained_addrs = [ ] if constrained_addrs is None else constrained_addrs
        self.hooks = {} if hooks is None else hooks
        self.use_crash_input = use_crash_input
        self.input_type = input_type
        self.target_port = port
        self.crash = crash
        self.tracer_bow = tracer_bow if tracer_bow is not None else archr.arsenal.QEMUTracerBow(self.target)

        self.explore_steps = explore_steps
        if self.explore_steps > 10:
            raise CannotExploit("Too many steps taken during crash exploration")

        self._use_rop = use_rop
        self._rop_fast_mode = fast_mode
        self._rop_cache_tuple = rop_cache_tuple

        self.angr_project_bow = None
        self.project = None
        self.binary = None
        self.rop = None
        self.initial_state = None
        self.state = None
        self.prev = None
        self._t = None
        self._traced = None
        self.added_actions = [ ]  # list of actions added during exploitation

        self.symbolic_mem = None
        self.flag_mem = None
        self.crash_types = [ ]  # crash type
        self.violating_action = None  # action (in case of a bad write or read) which caused the crash

        # Initialize
        self._initialize(angrop_object, rop_cache_path, checkpoint_path, crash_state, prev_state)

        # ASLR-related stuff
        if aslr is None:
            if self.is_cgc:
                # cgc has no ASLR, but we don't assume a stackbase
                self.aslr = False
            else:
                # We assume Linux is going to enforce stack-based ASLR
                self.aslr = True
        else:
            self.aslr = aslr

        # Work
        self._work(pov_file, format_infos)

    #
    # Public methods
    #

    def exploitable(self):
        """
        Determine if the crash is exploitable.

        :return: True if the crash's type is generally considered exploitable, False otherwise
        """

        exploitables = [Vulnerability.IP_OVERWRITE, Vulnerability.PARTIAL_IP_OVERWRITE, Vulnerability.BP_OVERWRITE,
                Vulnerability.PARTIAL_BP_OVERWRITE, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

        return self.one_of(exploitables)

    def explorable(self):
        """
        Determine if the crash can be explored with the 'crash explorer'.

        :return: True if the crash's type lends itself to exploring, only 'arbitrary-read' for now
        """

        # TODO add arbitrary receive into this list
        explorables = [Vulnerability.ARBITRARY_READ, Vulnerability.WRITE_WHAT_WHERE, Vulnerability.WRITE_X_WHERE]

        return self.one_of(explorables)

    def leakable(self):
        """
        Determine if the crash can potentially cause an information leak using the point-to-flag technique.

        :return: True if the 'point-to-flag' technique can be applied to this crash
        """

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

        our_open_fd = kwargs.get('our_open_fd', None)
        if self.input_type == CrashInputType.TCP:
            opts = kwargs.get('shellcode_opts', {})
            # are there open sockets that can receive our input?
            try:
                open_fds = {'fd': [fd for fd in self.state.posix.fd if
                            self.state.posix.fd[fd].read_storage.ident.startswith('aeg_stdin') and
                            self.state.solver.eval(self.state.posix.fd[fd].read_storage.pos) > 0]
                }
            except StopIteration:
                open_fds = { }

            if open_fds:
                # there is an open socket
                # try dupsh to get a shell
                opts['default'] = 'dupsh'
                opts['shellcode_args'] = open_fds
                our_open_fd = open_fds['fd'][0]
            else:
                # There is no open socket, need to connect back
                opts['default'] = 'connectback'
                # TODO: change these and parameterize them
                opts['shellcode_args'] = {'host': "127.0.0.1", "port": 9999}

            kwargs['shellcode_opts'] = opts
            kwargs['our_open_fd'] = our_open_fd

        if self.is_cgc:
            exploit = CGCExploitFactory(self, **kwargs)
        else:
            exploit = ExploitFactory(self, **kwargs)

        return exploit

    def exploit(self, blacklist_symbolic_explore=True, **kwargs):
        """
        Initialize an exploit factory, with which you can build exploits.

        :return:    An initialized ExploitFactory instance.
        :rtype:     ExploitFactory
        """

        factory = self._prepare_exploit_factory(blacklist_symbolic_explore, **kwargs)

        factory.initialize()
        return factory

    def yield_exploits(self, blacklist_symbolic_explore=True, **kwargs):
        """
        craft an exploit for a crash
        """

        factory = self._prepare_exploit_factory(blacklist_symbolic_explore, **kwargs)

        for exploit in factory.yield_exploits():
            yield exploit

    def explore(self, path_file=None):
        """
        explore a crash further to find new bugs
        """

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
            raise CannotExplore("unknown explorable crash type: %s" % self.crash_types)

    def point_to_flag(self):
        """
        [CGC only] Create a test case which points an arbitrary-read crash at the flag page.
        """
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
                l.warning("Crash couldn't be pointed at flag. Skipping.")

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

    def memory_control(self):
        """
        determine what symbolic memory we control which is at a constant address

        TODO: be able to specify that we want to know about things relative to a certain address

        :return:        A mapping from address to length of data controlled at that address
        """

        control = { }

        # PIE binaries will give no global control without knowledge of the binary base
        if self.project.loader.main_object.pic:
            return control

        min_addr = self.project.loader.main_object.min_addr
        max_addr = self.project.loader.main_object.max_addr
        for addr in self.symbolic_mem:
            if addr >= min_addr and addr < max_addr:
                control[addr] = self.symbolic_mem[addr]

        return control

    def stack_control(self, below_sp=True):
        """
        determine what symbolic memory we control on the stack.

        :param bool below_sp:   True if we only want to find the number of symbolic bytes equal to or beneath the stack
                                pointer.
        :return:                A mapping from address to length of data controlled at that address
        """

        control = { }

        if self.state.solver.symbolic(self.state.regs.sp):
            l.warning("detected symbolic sp when gauging stack control")
            return control

        sp = self.state.solver.eval(self.state.regs.sp)
        sp_base = self.initial_state.solver.eval(self.initial_state.regs.sp)
        for addr in self.symbolic_mem:
            # discard our fake heap etc
            if addr > sp_base:
                continue

            if below_sp:
                # if the region is below sp it gets added
                if addr > sp:
                    control[addr] = self.symbolic_mem[addr]

                # if sp falls into the region it gets added starting at sp
                elif addr + self.symbolic_mem[addr] > sp:
                    control[sp] = addr + self.symbolic_mem[addr] - sp

            else:
                control[addr] = self.symbolic_mem[addr]

        STACK_ARGS_THRESHOLD = 5
        MIN_FREEDOM = 2

        # additional heuristic check: if the address is too close to sp, it might be a stack variable used
        # by the last called function. it might be already constrained to some fixed value.
        filtered_control = { }
        for addr, size in control.items():
            if addr <= sp < addr + size:
                gap_start, gap_end = None, None
                # test up to STACK_ARGS_THRESHOLD words above sp
                arch = self.state.arch
                for i in range(STACK_ARGS_THRESHOLD):
                    v = self.state.memory.load(sp + i * arch.bytes, arch.bytes, endness=arch.memory_endness)
                    if len(self.state.solver.eval_upto(v, MIN_FREEDOM)) < MIN_FREEDOM:
                        # oops
                        if gap_start is None:
                            gap_start = sp + i * arch.bytes
                        gap_end = sp + (i + 1) * arch.bytes

                if gap_start is not None and gap_end is not None:
                    l.warning("Gap around stack poiner is detected. Refining controlled regions.")
                    # break the controlled region
                    filtered_control[addr] = gap_start - addr
                    filtered_control[gap_end] = addr + size - gap_end
                    continue

            filtered_control[addr] = size

        return filtered_control

    def copy(self):
        cp = Crash.__new__(Crash)
        cp.target = self.target
        cp.tracer_bow = self.tracer_bow
        cp.binary = self.binary
        cp.crash = self.crash
        cp.input_type = self.input_type
        cp.project = self.project
        cp.aslr = self.aslr
        cp.prev = self.prev.copy()
        cp.state = self.state.copy()
        cp.initial_state = self.initial_state
        cp.rop = self.rop
        cp.added_actions = list(self.added_actions)
        cp.symbolic_mem = self.symbolic_mem.copy()
        cp.flag_mem = self.flag_mem.copy()
        cp.crash_types = self.crash_types
        cp._t = self._t
        cp.violating_action = self.violating_action
        cp.use_crash_input = self.use_crash_input
        cp.explore_steps = self.explore_steps
        cp.constrained_addrs = list(self.constrained_addrs)
        cp.core_registers = self.core_registers.copy() if self.core_registers is not None else None

        return cp

    def checkpoint(self, path):
        """
        Save intermediate results (traced states, etc.) to a file to allow faster exploit generation in the future.

        :param str path:    Path to the file which saves intermediate states.
        :return:            None
        """

        s = {
            'initial_state': self.initial_state,
            'crash_state': self.state,
            'prev_state': self.prev,
            'core_registers': self.core_registers,
        }

        with open(path, "wb") as f:
            pickle.dump(s, f)

    def checkpoint_restore(self, path):
        """
        Restore from a checkpoint file.

        :param str path:    Path to the file which saves intermediate states.
        :return:            None
        """

        with open(path, "rb") as f:
            try:
                s = pickle.load(f)
            except EOFError as ex:
                raise EOFError("Fail to restore from checkpoint %s", path)

        keys = {'initial_state',
                'crash_state',
                'prev_state',
                'core_registers',
                }

        if not isinstance(s, dict):
            raise TypeError("The checkpoint file has an incorrect format.")

        for k in keys:
            if k not in s:
                raise KeyError("Key %s is not found in the checkpoint file." % k)

        self.initial_state = s['initial_state']
        self.state = s['crash_state']
        self.prev = s['prev_state']
        self.core_registers = s['core_registers']

    @property
    def is_cgc(self):
        """
        Are we working on a CGC binary?
        """
        if self.project.loader.main_object.os == 'cgc':
            return True
        elif self.project.loader.main_object.os.startswith('UNIX'):
            return False
        else:
            raise ValueError("Can't analyze binary for OS %s" % self.project.loader.main_object.os)

    @property
    def is_linux(self):
        """
        Are we working on a Linux binary?
        """

        return self.project.loader.main_object.os.startswith('UNIX')

    def one_of(self, crash_types):
        """
        Test if a self's crash has one of the vulnerabilities described in crash_types
        """

        if not isinstance(crash_types, (list, tuple)):
            crash_types = [crash_types]

        return bool(len(set(self.crash_types).intersection(set(crash_types))))

    #
    # Private methods
    #

    def _initialize(self, rop_obj, rop_cache_path, checkpoint_path, crash_state, prev_state):
        """
        Initialization steps.
        - Create a new angr project.
        - Load or collect ROP gadgets.
        - Restore states from a previous checkpoint if available.

        :return:    None
        """

        # Initialize an angr Project
        dsb = archr.arsenal.DataScoutBow(self.target)
        self.angr_project_bow = archr.arsenal.angrProjectBow(self.target, dsb)
        self.project = self.angr_project_bow.fire()
        self.binary = self.target.resolve_local_path(self.target.target_path)

        # Add custom hooks
        for addr, proc in self.hooks.items():
            self.project.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)

        # ROP-related stuff
        if self._use_rop:
            if rop_obj is not None:
                self.rop = rop_obj
            else:
                if not rop_cache_path:
                    # we search for ROP gadgets now to avoid the memory exhaustion bug in pypy
                    # hash binary contents for rop cache name
                    binhash = hashlib.md5(open(self.binary, 'rb').read()).hexdigest()
                    rop_cache_path = os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(self.binary), binhash))
                self.rop = self._initialize_rop(fast_mode=self._rop_fast_mode, rop_cache_tuple=self._rop_cache_tuple,
                                                rop_cache_path=rop_cache_path)
        else:
            self.rop = None

        if self.project.loader.main_object.os == 'cgc':
            self.project.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

        # Load cached/intermediate states
        self.core_registers = None
        if crash_state is not None and prev_state is not None:
            self.state = crash_state
            self.prev = prev_state
        elif checkpoint_path is not None:
            l.info("Loading checkpoint file at %#s.", checkpoint_path)
            self.checkpoint_restore(checkpoint_path)
            self._traced = True
        else:
            self.state = None
            self.prev = None
            self.initial_state = None
            self._traced = False

    def _work(self, pov_file, format_infos):
        """
        Perform tracing, memory write filtering, and crash triaging.

        :return:    None
        """

        if not self._traced:
            # Begin tracing!
            self._preconstraining_input_data = None
            self._has_preconstrained = False
            self._trace(pov_file=pov_file,
                        format_infos=format_infos,
                        )

        l.info("Filtering memory writes.")
        self._filter_memory_writes()

        l.info("Triaging the crash.")
        self._triage_crash()

    def _trace(self, pov_file=None, format_infos=None):
        """
        Symbolically trace the target program with the given input. A NonCrashingInput exception will be raised if the
        target program does not crash with the given input.

        :param pov_file:        CGC-specific setting.
        :param format_infos:    CGC-specific setting.
        :return:                None.
        """

        # sanity check
        if pov_file is None and self.crash is None:
            raise ValueError("Must specify either crash or pov_file.")
        if pov_file is not None and self.crash is not None:
            raise ValueError("Cannot specify both a pov_file and a crash.")

        # faster place to check for non-crashing inputs
        if self.is_cgc:
            cgc_flag_page_magic = self._cgc_get_flag_page_magic()
        else:
            cgc_flag_page_magic = None

        # Prepare the initial state

        if pov_file is not None:
            input_data = TracerPoV(pov_file)
        else:
            input_data = self.crash

        # collect a concrete trace
        save_core = False
        r = self.tracer_bow.fire(testcase=input_data, save_core=save_core)

        if save_core:
            # if a coredump is available, save a copy of all registers in the coredump for future references
            if r.core_path and os.path.isfile(r.core_path):
                tiny_core = TinyCore(r.core_path)
                self.core_registers = tiny_core.registers
            else:
                l.error("Cannot find core file (path: %s). Maybe the target process did not crash?",
                        r.core_path)

        if self.initial_state is None:
            self.initial_state = self._create_initial_state(input_data, cgc_flag_page_magic=cgc_flag_page_magic)

        simgr = self.project.factory.simulation_manager(
            self.initial_state,
            save_unsat=False,
            hierarchy=False,
            save_unconstrained=r.crashed
        )

        # trace symbolically!
        self._t = r.tracer_technique(keep_predecessors=2)
        simgr.use_technique(self._t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        if self.is_cgc:
            s = simgr.one_active
            ChallRespInfo.prep_tracer(s, format_infos)
            ZenPlugin.prep_tracer(s)
        simgr.run()

        # tracing completed
        # if there was no crash we'll have to use the previous path's state
        if 'crashed' in simgr.stashes:
            # the state at crash time
            self.state = simgr.crashed[0]
            # a path leading up to the crashing basic block
            self.prev = self._t.predecessors[-1]
        else:
            self.state = simgr.traced[0]
            self.prev = self.state

        zp = self.state.get_plugin('zen_plugin') if self.is_cgc else None
        if 'crashed' not in simgr.stashes and zp is not None and len(zp.controlled_transmits) == 0:
            l.warning("Input did not cause a crash.")
            raise NonCrashingInput
        l.debug("Done tracing input.")

    def _create_initial_state(self, input_data, cgc_flag_page_magic=None):

        # run the tracer, grabbing the crash state
        remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                          so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES, so.SIMPLIFY_MEMORY_WRITES,
                          so.ALL_FILES_EXIST}
        add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                       so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS}

        socket_queue = None
        stdin_file = None  # the file that will be fd 0

        if self.input_type == CrashInputType.TCP:
            socket_queue = [ ]
            for i in range(10):
                # Initialize the first N socket pairs
                input_sock = SimPreconstrainedFileStream(
                    preconstraining_handler=self._preconstrain_file,
                    name="aeg_tcp_in_%d" % i,
                    ident='aeg_stdin_%d' % i
                )
                output_sock = SimFileStream(name="aeg_tcp_out_%d" % i)
                socket_queue.append([input_sock, output_sock])
        else:
            stdin_file = SimPreconstrainedFileStream(
                preconstraining_handler=self._preconstrain_file,
                name='stdin',
                ident='aeg_stdin'
            )
        self._preconstraining_input_data = input_data

        state_bow = archr.arsenal.angrStateBow(self.target, self.angr_project_bow)
        initial_state = state_bow.fire(
            mode='tracing',
            add_options=add_options,
            remove_options=remove_options,
        )

        # initialize other settings
        initial_state.register_plugin('posix', SimSystemPosix(
            stdin=stdin_file,
            stdout=SimFileStream(name='stdout'),
            stderr=SimFileStream(name='stderr'),
            argc=initial_state.posix.argc,
            argv=initial_state.posix.argv,
            environ=initial_state.posix.environ,
            auxv=initial_state.posix.auxv,
            socket_queue=socket_queue,
        ))

        initial_state.register_plugin('preconstrainer', SimStatePreconstrainer(self.constrained_addrs))
        if self.is_cgc:
            initial_state.preconstrainer.preconstrain_flag_page(cgc_flag_page_magic)

        # Loosen certain libc limits on symbolic input
        initial_state.libc.buf_symbolic_bytes = 3000
        initial_state.libc.max_symbolic_strchr = 3000
        initial_state.libc.max_str_len = 3000
        initial_state.libc.max_buffer_size = 16384

        return initial_state

    def _preconstrain_file(self, fstream):
        """
        Use preconstrainer to preconstrain an input file to the specified input data upon the first read on the stream.

        :param fstream: The file stream where the read happens.
        :return:        None
        """

        if not self._has_preconstrained:
            l.info("Preconstraining file stream %s upon the first read()." % fstream)
            self._has_preconstrained = True
            fstream.state.preconstrainer.preconstrain_file(self._preconstraining_input_data, fstream, set_length=True)
        else:
            l.error("Preconstraining is attempted twice, but currently Rex only supports preconstraining one file. "
                    "Ignored.")

    def _cgc_get_flag_page_magic(self):
        """
        [CGC only] Get the magic content in flag page for CGC binaries.

        :return:    The magic page content.
        """

        r = self.tracer_bow.fire(save_core=True, record_magic=True, testcase=self.crash)
        if not r.crashed:
            if not self.tracer_bow.fire(save_core=True, testcase=self.crash, report_bad_args=True).crashed:
                l.warning("input did not cause a crash")
                raise NonCrashingInput
        return r.magic_contents

    def _explore_arbitrary_read(self, path_file=None):
        # crash type was an arbitrary-read, let's point the violating address at a
        # symbolic memory region

        largest_regions = sorted(self.symbolic_mem.items(),
                key=operator.itemgetter(1),
                reverse=True)

        min_read = self.state.solver.min(self.violating_action.addr)
        max_read = self.state.solver.max(self.violating_action.addr)

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

            if self.state.solver.satisfiable(extra_constraints=(constraint,)):
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
        self.__init__(self.target,
                new_input,
                tracer_bow=self.tracer_bow,
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

        min_write = self.state.solver.min(self.violating_action.addr)
        max_write = self.state.solver.max(self.violating_action.addr)

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

                if self.state.solver.satisfiable(extra_constraints=(constraint,)):
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
        self.__init__(self.target,
                new_input,
                tracer_bow=self.tracer_bow,
                explore_steps=self.explore_steps + 1,
                constrained_addrs=self.constrained_addrs + [self.violating_action],
                use_rop=use_rop,
                angrop_object=self.rop)

    def _filter_memory_writes(self):
        """
        Filter all writes to memory and split them to symbolic memory bytes and flag memory bytes.

        :return:    None
        """

        memory_writes = sorted(self.state.memory.mem.get_symbolic_addrs())
        if self.is_cgc:
            # remove all memory writes that directly end up in the CGC flag page (0x4347c000 - 0x4347d000)
            memory_writes = [m for m in memory_writes if m // 0x1000 != 0x4347c]
        user_writes = [m for m in memory_writes if
                       any("aeg_stdin" in v for v in self.state.memory.load(m, 1).variables)]
        if self.is_cgc:
            flag_writes = [m for m in memory_writes if
                           any(v.startswith("cgc-flag") for v in self.state.memory.load(m, 1).variables)]
        else:
            flag_writes = []

        l.debug("Finished filtering memory writes.")

        self.symbolic_mem = self._segment(user_writes)
        self.flag_mem = self._segment(flag_writes)

    def _triage_crash(self):
        """
        Crash triaging. Fill in crash_types.

        :return:    None
        """

        ip = self.state.regs.ip
        bp = self.state.regs.bp

        # any arbitrary receives or transmits
        # TODO: receives
        zp = self.state.get_plugin('zen_plugin') if self.is_cgc else None
        if zp is not None and len(zp.controlled_transmits):
            l.debug("detected arbitrary transmit vulnerability")
            self.crash_types.append(Vulnerability.ARBITRARY_TRANSMIT)

        # we assume a symbolic eip is always exploitable
        if self.state.solver.symbolic(ip):
            # how much control of ip do we have?
            if self._symbolic_control(ip) >= self.state.arch.bits:
                l.info("detected ip overwrite vulnerability")
                self.crash_types.append(Vulnerability.IP_OVERWRITE)
            else:
                l.info("detected partial ip overwrite vulnerability")
                self.crash_types.append(Vulnerability.PARTIAL_IP_OVERWRITE)

            return

        if self.state.solver.symbolic(bp):
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
        if self._t is not None and self._t.last_state is not None:
            recent_actions = reversed(self._t.last_state.history.recent_actions)
            state = self._t.last_state
            # TODO: this is a dead assignment! what was this supposed to be?
        else:
            recent_actions = reversed(self.state.history.actions)
            state = self.state
        for a in recent_actions:
            if a.type == 'mem':
                if self.state.solver.symbolic(a.addr.ast):
                    symbolic_actions.append(a)

        # TODO: pick the crashing action based off the crashing instruction address,
        # crash fixup attempts will break on this
        #import ipdb; ipdb.set_trace()
        for sym_action in symbolic_actions:
            if sym_action.action == "write":
                if self.state.solver.symbolic(sym_action.data):
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

    def _reconstrain_flag_data(self, state):
        """
        [CGC only] Constrain data in the flag page.
        """

        l.info("reconstraining flag")

        replace_dict = dict()
        for c in state.preconstrainer.preconstraints:
            if any([v.startswith('cgc-flag') or v.startswith("random") for v in list(c.variables)]):
                concrete = next(a for a in c.args if not a.symbolic)
                symbolic = next(a for a in c.args if a.symbolic)
                replace_dict[symbolic.cache_key] = concrete
        cons = state.solver.constraints
        new_cons = []
        for c in cons:
            new_c = c.replace_dict(replace_dict)
            new_cons.append(new_c)
        state.release_plugin("solver")
        state.add_constraints(*new_cons)
        state.downsize()
        state.solver.simplify()

    def _symbolic_control(self, st):
        """
        Determine the amount of symbolic bits in an AST, useful to determining how much control we have
        over registers.

        :param st:  A claripy AST object to examine.
        :return:    Number of symbolic bits in the AST.
        :rtype:     int
        """

        sbits = 0

        for bitidx in range(self.state.arch.bits):
            if st[bitidx].symbolic:
                sbits += 1

        return sbits

    def _initialize_rop(self, fast_mode=False, rop_cache_tuple=None, rop_cache_path=None):
        """
        Use angrop to generate ROP gadgets and such.

        :return:    An angr.analyses.ROP instance.
        """

        rop = self.project.analyses.ROP(fast_mode=fast_mode)
        if rop_cache_tuple is not None:
            l.info("Loading rop gadgets from cache tuple...")
            rop._load_cache_tuple(rop_cache_tuple)
        elif os.path.exists(rop_cache_path):
            l.info("Loading rop gadgets from cache file %s...", rop_cache_path)
            rop.load_gadgets(rop_cache_path)
        else:
            l.info("Collecting ROP gadgets... don't panic if you see tons of error messages!")
            if angr.misc.testing.is_testing:
                rop.find_gadgets_single_threaded(show_progress=False)
            else:
                rop.find_gadgets(show_progress=False)
            rop.save_gadgets(rop_cache_path)
        return rop

    #
    # Static methods
    #

    @staticmethod
    def _four_flag_bytes_offset(ast):
        """
        [CGC only] checks if an ast contains 4 contiguous flag bytes
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
        """
        [CGC only] Point an arbitrary-read location at the flag page.

        :param state:           angr SimState instance.
        :param violating_addr:  The address where the arbitrary-read points to.
        :return:                The new state with the arbitrary-read constrained to an address within the flag page.
        :rtype:                 angr.SimState
        """

        cgc_magic_page_addr = 0x4347c000

        # see if we can point randomly inside the flag (prevent people filtering exactly 0x4347c000)
        rand_addr = random.randint(cgc_magic_page_addr, cgc_magic_page_addr+0x1000-4)
        if state.solver.satisfiable(extra_constraints=(violating_addr == rand_addr,)):
            cp = state.copy()
            cp.add_constraints(violating_addr == rand_addr)
            return cp

        # see if we can point anywhere at flag
        if state.solver.satisfiable(extra_constraints=
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
        if state.solver.satisfiable(extra_constraints=(violating_addr == goal_addr,)):
            cp = state.copy()
            cp.add_constraints(violating_addr == goal_addr)
            return cp
        else:
            raise CannotExploit("unable to point arbitrary-read at the flag copy")

    @staticmethod
    def _segment(memory_writes):
        """
        Given a set of addresses, group into a dict mapping from address to length

        :param Iterable memory_writes:   Addresses in memory
        :return dict:               A map from start address to the length of continuous addresses after the start
        """
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

    @staticmethod
    def input_type_to_channel_type(input_type):
        if input_type == CrashInputType.TCP:
            return 'tcp'
        elif input_type == CrashInputType.TCP6:
            return 'tcp6'
        elif input_type == CrashInputType.UDP:
            return 'udp'
        elif input_type == CrashInputType.UDP6:
            return 'udp6'
        raise NotImplementedError("Unsupported input type %s." % input_type)
