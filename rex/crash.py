import os
import angr
import random
import hashlib
import logging
import operator
import pickle
from typing import Union, Tuple

from angr import sim_options as so
from angr.state_plugins.trace_additions import ChallRespInfo, ZenPlugin
from angr.state_plugins.preconstrainer import SimStatePreconstrainer
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream
from angr.exploration_techniques.tracer import TracingMode
import archr
from archr.analyzers.angr_state import SimArchrMount, SimArchrProcMount
from tracer import TracerPoV, TinyCore

from .exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from .vulnerability import Vulnerability
from .enums import CrashInputType
from .preconstrained_file_stream import SimPreconstrainedFileStream


l = logging.getLogger("rex.Crash")


class NonCrashingInput(Exception):
    pass

class BaseCrash:
    """
    Some basic functionalities: handles angrop
    """

    def __init__(self, use_rop=True, fast_mode=False, angrop_object=None, rop_cache_path=None, rop_cache_tuple=None):
        """
        :param use_rop:             Whether or not to use rop.
        :param fast_mode:           whether to use fast_mode in angrop
        :param angrop_object:       whether to directly load existing angrop_object
        :param rop_cache_path:      path of pickled angrop gadget cache
        :param rop_cache_tuple:     A angrop tuple to load from.
        """
        self.binary = None
        self.project = None
        self.rop = angrop_object

        self._use_rop = use_rop
        self._rop_fast_mode = fast_mode
        self._rop_cache_tuple = rop_cache_tuple
        self._rop_cache_path = rop_cache_path

    def _initialize_rop(self):
        """
        Use angrop to generate ROP gadgets and such.

        :return:    An angr.analyses.ROP instance.
        """
        # sanity check
        if self.rop:
            return
        if not self._use_rop:
            self.rop = None
            return

        # always have a cache path
        if not self._rop_cache_path:
            # we search for ROP gadgets now to avoid the memory exhaustion bug in pypy
            # hash binary contents for rop cache name
            binhash = hashlib.md5(open(self.binary, 'rb').read()).hexdigest()
            self._rop_cache_path = os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(self.binary), binhash))

        # finally, create an angrop object
        rop = self.project.analyses.ROP(fast_mode=self._rop_fast_mode)
        if self._rop_cache_tuple is not None:
            l.info("Loading rop gadgets from cache tuple...")
            rop._load_cache_tuple(self._rop_cache_tuple)
        elif os.path.exists(self._rop_cache_path):
            l.info("Loading rop gadgets from cache file %s...", self._rop_cache_path)
            rop.load_gadgets(self._rop_cache_path)
        else:
            l.info("Collecting ROP gadgets... don't panic if you see tons of error messages!")
            if angr.misc.testing.is_testing:
                rop.find_gadgets_single_threaded(show_progress=False)
            else:
                rop.find_gadgets(show_progress=False)
            rop.save_gadgets(self._rop_cache_path)
        self.rop = rop

class SimCrash(BaseCrash):
    """
    Advanced crash object handling symbolic states
    """
    def __init__(self, crash_state=None, prev_state=None, checkpoint_path=None,
                 constrained_addrs=None, **kwargs):
        """
        :param crash_state:         An already traced crash state.
        :param prev_state:          The predecessor of the final crash state.
        :param checkpoint_path:     Path to a checkpoint file that provides initial_state, prev_state, crash_state, and
                                    so on.
        :param constrained_addrs:   List of addrs which have been constrained
                                    during exploration.
        """
        super().__init__(**kwargs)

        self._crash_state = crash_state
        self._prev_state = prev_state
        self._checkpoint_path = checkpoint_path

        self.project = None
        self.constrained_addrs = [ ] if constrained_addrs is None else constrained_addrs
        self.initial_state = None
        self.state = None
        self.prev = None
        self.core_registers = None
        self._traced = None
        self.crash_input = None

    def _initialize_project(self):
        assert self.project is not None

        if self.is_cgc:
            self.project.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

        # Load cached/intermediate states
        if self._crash_state is not None and self._prev_state is not None:
            self.state = self._crash_state
            self.prev = self._prev_state
            self._traced = True
        elif self._checkpoint_path is not None:
            l.info("Loading checkpoint file at %#s.", self._checkpoint_path)
            self.restore_checkpoint(self._checkpoint_path)
            self._traced = True
        else:
            self.state = None
            self.prev = None
            self.initial_state = None
            self._traced = False

    def get_sim_open_fds(self):
        try:
            open_fds = {'fd': [fd for fd in self.state.posix.fd if
                        self.state.posix.fd[fd].read_storage.ident.startswith('aeg_stdin') and
                        self.state.solver.eval(self.state.posix.fd[fd].read_storage.pos) > 0]
            }
        except StopIteration:
            open_fds = { }
        return open_fds

    def _preconstrain_file(self, fstream):
        """
        Use preconstrainer to preconstrain an input file to the specified input data upon the first read on the stream.

        :param fstream: The file stream where the read happens.
        :return:        None
        """


        l.info("Preconstraining file stream %s upon the first read().", fstream)
        fstream.state.preconstrainer.preconstrain_file(self.crash_input, fstream, set_length=True)

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

    ####### checkpoint related ########
    def restore_checkpoint(self, path):
        """
        Restore from a checkpoint file.

        :param str path:    Path to the file which saves intermediate states.
        :return:            None
        """
        with open(path, "rb") as f:
            try:
                s = pickle.load(f)
            except EOFError as ex:
                raise EOFError("Fail to restore from checkpoint %s" % path) from ex

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

    def save_checkpoint(self, path):
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

class CommCrash(SimCrash):
    """
    Even more advanced crash object handling target communication and tracing
    """
    def __init__(self, target, tracer_bow=None, angr_project_bow=None, input_type=CrashInputType.STDIN, port=None,
                 trace_addr : Union[int, Tuple[int, int]]=None, delay=0, pre_fire_hook=None,
                 pov_file=None, format_infos=None, **kwargs):
        """
        :param target:              archr Target that contains the binary that crashed.
        :param tracer_bow:          The bow instance to use for tracing operations
        :param angr_project_bow:    The project bow to use, can be used for custom hooks and syscalls
        :param input_type:          the way the program takes input, usually CrashInputType.STDIN
        :param port:                In the case where the target takes TCP input, which port to connect to
        :param trace_addr:          Used in half-way tracing, this is the tuple (address, occurrence) where tracing starts
        :param delay:               Some targets need time to initialize, use this argument to tell tracer wait for
                                    several seconds before trying to set up connection
        :param pre_fire_hook:       function hook that is executed after the target is launched before the input is sent
                                    to the target
        :param pov_file:            CGC PoV describing a crash.
        :param format_infos:        A list of atoi FormatInfo objects that should
                                    be used when analyzing the crash.
        """
        super().__init__(**kwargs)

        # communication related
        self.target = target # type: archr.targets.Target
        self.tracer_bow = tracer_bow if tracer_bow is not None else archr.arsenal.QEMUTracerBow(self.target)
        self.input_type = input_type
        self.target_port = port
        self.delay = delay
        self.pre_fire_hook = pre_fire_hook
        self.angr_project_bow = angr_project_bow
        self.binary = self.target.resolve_local_path(self.target.target_path)

        # tracing related
        self.trace_addr = trace_addr if type(trace_addr) in {type(None), tuple} else (trace_addr, 1)
        self.trace_bb_addr = None
        self.halfway_tracing = bool(trace_addr)
        self._t = None
        self._traced = None
        self.trace_result = None

        # cgc related
        self.pov_file = pov_file
        self.format_infos = format_infos

    def _create_project(self):
        """
        create an angr project through archr
        """
        # Initialize an angr Project

        # pass tracer_bow to datascoutanalyzer to make addresses in angr consistent with those
        # in the analyzer
        if self.angr_project_bow is None:
            # for core files we don't want/need a datascout analyzer
            scout = None if self.halfway_tracing else archr.arsenal.DataScoutBow(self.target, analyzer=self.tracer_bow)
            self.angr_project_bow = archr.arsenal.angrProjectBow(self.target, scout_analyzer=scout)

        if not self.halfway_tracing:
            self.project = self.angr_project_bow.fire()
        else:
            # to enable halfway-tracing, we need to generate a coredump at the wanted address first
            # and use the core dump to create an angr project
            channel, test_case = self._prepare_channel()
            r = self.tracer_bow.fire(testcase=test_case, channel=channel, save_core=True, record_trace=True,
                                     trace_bb_addr=self.trace_addr, crash_addr=self.trace_addr, delay=self.delay,
                                     pre_fire_hook=self.pre_fire_hook)
            self.trace_result = r
            self._traced = True

            l.debug("Loading the core dump @ %s into angr...", r.core_path)
            self.project = self.angr_project_bow.fire(core_path=r.core_path)

            self.project.loader.main_object = self.project.loader.elfcore_object._main_object

    def _create_initial_state(self, testcase, cgc_flag_page_magic=None):

        # run the tracer, grabbing the crash state
        remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                          so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES, so.SIMPLIFY_MEMORY_WRITES,
                          so.ALL_FILES_EXIST, so.UNICORN, so.CPUID_SYMBOLIC}
        add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
                       so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS, so.KEEP_IP_SYMBOLIC}
        assert type(testcase) == bytes, "TracePov is no longer supported"

        stdin_file = None
        socket_queue = None
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

        # if we already have a core dump, use it to create the initial state
        if self.halfway_tracing:
            self.project.loader.main_object = self.project.loader.elfcore_object
            initial_state = self.project.factory.blank_state(
                mode='tracing',
                add_options=add_options,
                remove_options=remove_options)
            self.project.loader.main_object = self.project.loader.elfcore_object._main_object
            self.trace_bb_addr = initial_state.solver.eval(initial_state.regs.pc)
            initial_state.fs.mount('/', SimArchrMount(self.target))
        else:
            state_bow = archr.arsenal.angrStateBow(self.target, self.angr_project_bow)
            initial_state = state_bow.fire(
                mode='tracing',
                add_options=add_options,
                remove_options=remove_options,
            )

        posix = SimSystemPosix(
            stdin=stdin_file,
            stdout=SimFileStream(name='stdout'),
            stderr=SimFileStream(name='stderr'),
            argc=initial_state.posix.argc,
            argv=initial_state.posix.argv,
            environ=initial_state.posix.environ,
            auxv=initial_state.posix.auxv,
            socket_queue=socket_queue,
        )
        # initialize other settings
        initial_state.register_plugin('posix', posix)
        initial_state.fs.mount('/proc', SimArchrProcMount(self.target))  # this has to happen after posix initializes

        initial_state.register_plugin('preconstrainer', SimStatePreconstrainer(self.constrained_addrs))
        if self.is_cgc:
            initial_state.preconstrainer.preconstrain_flag_page(cgc_flag_page_magic)

        # if we use halfway tracing, we need to reconstruct the sockets
        # as a hack, we trigger the allocation of all sockets
        # FIXME: this should be done properly, maybe let user to provide a hook
        if self.halfway_tracing:
            for i in range(3, 10):
                initial_state.posix.open_socket(str(i))

        # Loosen certain libc limits on symbolic input
        initial_state.libc.buf_symbolic_bytes = 3000
        initial_state.libc.max_symbolic_strchr = 3000
        initial_state.libc.max_str_len = 3000
        initial_state.libc.max_buffer_size = 16384

        return initial_state

    def _trace(self):
        """
        Symbolically trace the target program with the given input. A NonCrashingInput exception will be raised if the
        target program does not crash with the given input.

        :return:                None.
        """

        # faster place to check for non-crashing inputs
        if self.is_cgc:
            cgc_flag_page_magic = self._cgc_get_flag_page_magic()
        else:
            cgc_flag_page_magic = None

        # transform input to channel and test_case
        channel, test_case = self._prepare_channel()

        # Prepare the initial state
        if self.initial_state is None:
            self.initial_state = self._create_initial_state(test_case, cgc_flag_page_magic=cgc_flag_page_magic)

        # collect a concrete trace
        # with trace_addr enabled, the trace collected starts with the basic block where trace_addr belongs
        # which means the trace and the state may be inconsistent.
        # But our tracer is smart enough to resolve the inconsistency
        if not self.trace_result:
            save_core = True
            if isinstance(self.tracer_bow, archr.arsenal.RRTracerBow):
                save_core = False
            r = self.tracer_bow.fire(testcase=test_case, channel=channel, save_core=save_core,
                                     trace_bb_addr=self.trace_bb_addr, pre_fire_hook=self.pre_fire_hook)

            if save_core:
                # if a coredump is available, save a copy of all registers in the coredump for future references
                if r.core_path and os.path.isfile(r.core_path):
                    tiny_core = TinyCore(r.core_path)
                    self.core_registers = tiny_core.registers
                else:
                    l.error("Cannot find core file (path: %s). Maybe the target process did not crash?",
                            r.core_path)
            self.trace_result = r

        simgr = self.project.factory.simulation_manager(
            self.initial_state,
            save_unsat=False,
            hierarchy=False,
            save_unconstrained=self.trace_result.crashed
        )

        # trace symbolically!
        # since we have already grabbed mapping info through datascoutbow in angr_project_bow, we can assume
        # there are no aslr slides
        self._t = self.trace_result.tracer_technique(keep_predecessors=2, copy_states=False, mode=TracingMode.Strict, aslr=False, fast_forward_to_entry=(not self.halfway_tracing))
        simgr.use_technique(self._t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        if self.is_cgc:
            s = simgr.one_active
            ChallRespInfo.prep_tracer(s, self.format_infos)
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

    def _prepare_channel(self):
        """
        translate pov_file or input to channel and test_case
        """
        # sanity check
        if self.pov_file is None and self.crash_input is None:
            raise ValueError("Must specify either crash or pov_file.")
        if self.pov_file is not None and self.crash_input is not None:
            raise ValueError("Cannot specify both a pov_file and a crash.")

        # prepare channel and test_case
        if self.pov_file is not None:
            test_case = TracerPoV(self.pov_file)
            channel = None
        else:
            input_data = self.crash_input
            channel = self.input_type_to_channel_type(self.input_type)
            if channel != "stdio":
                channel += ":0"
            test_case = input_data

        return channel, test_case

    def _cgc_get_flag_page_magic(self):
        """
        [CGC only] Get the magic content in flag page for CGC binaries.

        :return:    The magic page content.
        """

        r = self.tracer_bow.fire(save_core=True, record_magic=True, testcase=self.crash_input)
        if not r.crashed:
            if not self.tracer_bow.fire(save_core=True, testcase=self.crash_input, report_bad_args=True).crashed:
                l.warning("input did not cause a crash")
                raise NonCrashingInput
        return r.magic_contents

    @staticmethod
    def input_type_to_channel_type(input_type):
        if input_type == CrashInputType.STDIN:
            return "stdio"
        elif input_type == CrashInputType.TCP:
            return 'tcp'
        elif input_type == CrashInputType.TCP6:
            return 'tcp6'
        elif input_type == CrashInputType.UDP:
            return 'udp'
        elif input_type == CrashInputType.UDP6:
            return 'udp6'
        raise NotImplementedError("Unsupported input type %s." % input_type)

class Crash(CommCrash):
    """
    Triage and exploit a crash using angr.
    The highest level crash object, perform analysis on the crash state.
    """

    def __init__(self, target, crash=None, pov_file=None, aslr=None,
                 use_crash_input=False, explore_steps=0, **kwargs):
        """
        :param crash:               String of input which crashed the binary.
        :param pov_file:            CGC PoV describing a crash.
        :param aslr:                Analyze the crash with aslr on or off.
        :param use_crash_input:     if a byte is not constrained by the generated exploits,
                                    use the original crash input to fill the byte.
        """
        super().__init__(target, **kwargs)

        self.use_crash_input = use_crash_input
        self.crash_input = crash
        self.crash_types = [ ]  # crash type

        self.explore_steps = explore_steps
        if self.explore_steps > 10:
            raise CannotExploit("Too many steps taken during crash exploration")

        self.symbolic_mem = None
        self.flag_mem = None
        self.added_actions = [ ]  # list of actions added during exploitation
        self.violating_action = None  # action (in case of a bad write or read) which caused the crash

        # Initialize
        self._initialize()

        # by default, we assume non-cgc OS has ASLR on
        self.aslr = aslr
        if aslr is None:
            self.aslr = not self.is_cgc

        # Work
        self._work()

    #
    # Public methods
    #

    def one_of(self, crash_types):
        """
        Test if a self's crash has one of the vulnerabilities described in crash_types
        """

        if not isinstance(crash_types, (list, tuple)):
            crash_types = [crash_types]

        return bool(len(set(self.crash_types).intersection(set(crash_types))))

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
            open_fds = self.get_sim_open_fds()
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
            if min_addr <= addr < max_addr:
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
            if addr > sp_base | 0xfff:
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
        cp.angr_project_bow = self.angr_project_bow
        cp.binary = self.binary
        cp.trace_addr = self.trace_addr
        cp.trace_bb_addr = self.trace_bb_addr
        cp.delay = self.delay
        cp.crash_input = self.crash_input
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

    #
    # Private methods
    #

    def _initialize(self):
        """
        Initialization steps.
        - Create a new angr project.
        - Load or collect ROP gadgets.
        - Restore states from a previous checkpoint if available.

        :return:    None
        """

        self._create_project()
        self._initialize_rop()
        self._initialize_project()


    def _work(self):
        """
        Perform tracing, memory write filtering, and crash triaging.

        :return:    None
        """

        if not self._traced:
            self._trace()

        l.info("Filtering memory writes.")
        self._filter_memory_writes()

        l.info("Triaging the crash.")
        self._triage_crash()

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
        use_rop = self.rop is not None
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

        use_rop = self.rop is not None
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

        memory_writes = sorted(self.state.memory.get_symbolic_addrs())
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
        else:
            recent_actions = reversed(self.state.history.actions)
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

    def _reconstrain_flag_data(self, state):# pylint:disable=no-self-use
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
