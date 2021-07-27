import os
import re
import angr
import random
import hashlib
import logging
import operator
import pickle

import archr
import claripy
from tracer import TracerPoV
from angr.state_plugins.trace_additions import ChallRespInfo, ZenPlugin
from angr.state_plugins.preconstrainer import SimStatePreconstrainer
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream
from angr.exploration_techniques.tracer import TracingMode
from archr.analyzers.angr_state import SimArchrProcMount

from .exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from .vulnerability import Vulnerability
from .enums import CrashInputType
from .preconstrained_file_stream import SimPreconstrainedFileStream
from .crash_tracer import TraceMode, SimTracer, HalfwayTracer, DumbTracer, NonCrashingInput
from .exploit.actions import RexOpenChannelAction, RexSendAction


l = logging.getLogger("rex.Crash")


class BaseCrash:
    """
    Some basic functionalities: handles angrop
    """

    def __init__(self, use_rop=True, fast_mode=False, rop_cache_path=None):
        """
        :param use_rop:             Whether or not to use rop.
        :param fast_mode:           whether to use fast_mode in angrop, fast_mode can generate
                                    no gadgets some times
        :param rop_cache_path:      path of pickled angrop cache
        """
        self.project = None
        self.tracer = None
        self.binary = None
        self.libc_binary = None
        self.rop = None
        self.libc_rop = None

        self._use_rop = use_rop
        self._rop_fast_mode = fast_mode
        self._rop_cache_path = rop_cache_path
        self._rop_cache = None
        self._bad_bytes = []

    def initialize_rop(self):
        """
        Use angrop to generate ROP gadgets and such for the target binary.

        :return:    An angr.analyses.ROP instance.
        """
        # sanity check
        if self.rop:
            return
        if not self._use_rop:
            self.rop = None
            return

        # finally, create an angrop object
        rop = self.project.analyses.ROP(fast_mode=self._rop_fast_mode, rebase=False)
        rop.set_badbytes(self._bad_bytes)
        if self._rop_cache and self._rop_cache[0]:
            l.info("Loading rop gadgets from cache")
            rop._load_cache_tuple(self._rop_cache[0])
        else:
            l.info("Collecting ROP gadgets... don't panic if you see tons of error messages!")
            l.info("It may take several minutes to finish...")
            if angr.misc.testing.is_testing:
                rop.find_gadgets_single_threaded(show_progress=False)
            else:
                rop.find_gadgets(show_progress=True)
        self.rop = rop

    def _identify_libc(self):
        mapping = self.tracer.angr_project_bow._mem_mapping
        lib_folder = self.tracer.angr_project_bow._lib_folder
        lib_names = [ x for x in mapping.keys() if re.match(r"^(libuC)?libc(\.|-)", os.path.basename(x)) ]
        if not len(lib_names):
            return None, None
        if len(lib_names) > 1:
            l.warning("more than 1 potential libc detected: %s", lib_names)

        return mapping[lib_names[0]], os.path.join(lib_folder, os.path.basename(lib_names[0]))

    def initialize_libc_rop(self):
        # sanity check
        if self.libc_rop:
            return
        if not self._use_rop:
            self.libc_rop = None
            return

        base_addr, self.libc_binary = self._identify_libc()
        if not self.libc_binary:
            return

        # finally, create an angrop object
        bin_opts = {"base_addr": base_addr}
        project = angr.Project(self.libc_binary, auto_load_libs=False, main_opts=bin_opts)
        libc_rop = project.analyses.ROP(fast_mode=self._rop_fast_mode, rebase=False)
        libc_rop.set_badbytes(self._bad_bytes)
        if self._rop_cache and self._rop_cache[1]:
            l.info("Loading libc rop gadgets from cache")
            libc_rop._load_cache_tuple(self._rop_cache[1])
        else:
            l.info("Collecting ROP gadgets in libc... don't panic if you see tons of error messages!")
            l.info("It may take several minutes to finish...")
            if angr.misc.testing.is_testing:
                libc_rop.find_gadgets_single_threaded(show_progress=False)
            else:
                libc_rop.find_gadgets(show_progress=True)
        self.libc_rop = libc_rop

    def soft_load_cache(self):
        if not self._rop_cache_path:
            self._rop_cache_path = self._get_cache_path(self.binary)
        if not os.path.exists(self._rop_cache_path):
            return
        with open(self._rop_cache_path, "rb") as f:
            self._rop_cache = pickle.load(f)

    def soft_save_cache(self):
        if not self._rop_cache_path:
            self._rop_cache_path = self._get_cache_path(self.binary)
        # do not overwrite existing cache
        if os.path.exists(self._rop_cache_path):
            return
        rop_cache_tuple = self.rop._get_cache_tuple() if self.rop else None
        libc_rop_cache_tuple = self.libc_rop._get_cache_tuple() if self.libc_rop else None
        rop_cache = (rop_cache_tuple, libc_rop_cache_tuple)
        with open(self._rop_cache_path, "wb") as f:
            pickle.dump(rop_cache, f)

    @staticmethod
    def _get_cache_path(binary):
        # hash binary contents for rop cache name
        binhash = hashlib.md5(open(binary, 'rb').read()).hexdigest()
        return os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(binary), binhash))

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
        self.crash_input = None

    def initialize_project(self):
        assert self.project is not None

        if self.is_cgc:
            self.project.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

        # Load cached/intermediate states
        if self._crash_state is not None and self._prev_state is not None:
            self.state = self._crash_state
            self.prev = self._prev_state
        elif self._checkpoint_path is not None:
            l.info("Loading checkpoint file at %#s.", self._checkpoint_path)
            self.restore_checkpoint(self._checkpoint_path)
        else:
            self.state = None
            self.prev = None
            self.initial_state = None

    def get_sim_open_fds(self):
        try:
            open_fds = {'fd': [fd for fd in self.state.posix.fd if
                        self.state.posix.fd[fd].read_storage.ident.startswith('aeg_input') and
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
    def __init__(self, target, crash=None, pov_file=None, actions=None,
                 trace_mode=TraceMode.FULL_SYMBOLIC, tracer_opts=None,
                 input_type=CrashInputType.STDIN, port=None,
                 delay=0, pre_fire_hook=None,
                 format_infos=None, **kwargs):
        """
        :param target:              archr Target that contains the binary that crashed.
        :param crash:               String of input which crashed the binary.
        :param pov_file:            CGC PoV describing a crash.
        :param actions:             archr actions to interact with the target
        :param trace_mode           the tracer to use. Currently supports "dumb", "halfway" and "full_symbolic"
        :param tracer_opts          specify options for tracer, see CrashTracer
        :param input_type:          the way the program takes input, usually CrashInputType.STDIN
        :param port:                In the case where the target takes TCP input, which port to connect to
        :param trace_addr:          Used in half-way tracing, this is the tuple (address, occurrence) where tracing starts
        :param delay:               Some targets need time to initialize, use this argument to tell tracer wait for
                                    several seconds before trying to set up connection
        :param pre_fire_hook:       function hook that is executed after the target is launched before the input is sent
                                    to the target
        :param actions:             the actions to interact with the target, if specified, crash or pov_file will be ignored
                                    during interaction with the target
        :param format_infos:        A list of atoi FormatInfo objects that should
                                    be used when analyzing the crash.
        """
        super().__init__(**kwargs)

        # sanity check
        # TODO: support other tracers
        if trace_mode != TraceMode.DUMB and actions:
            raise NotImplementedError("actions only support dumb tracer at the moment")

        # input related, ensure crash_input is a list of input
        # ensure actions are defined
        self.pov_file = pov_file
        self.crash_input, self.actions, self.sim_input = self._input_preparation(crash, actions, input_type)

        # communication related
        self.target = target # type: archr.targets.Target
        self.input_type = input_type
        self.target_port = port
        self.delay = delay
        self.pre_fire_hook = pre_fire_hook

        self.binary = self.target.resolve_local_path(self.target.target_path)
        self._test_case = None
        self._channel = None

        # tracing related
        if tracer_opts is None: tracer_opts = {}
        tracer_opts['tracer_bow'] = tracer_opts.pop("tracer_bow", None) or archr.arsenal.QEMUTracerBow(self.target)
        self._tracer_opts = tracer_opts

        is_cgc = self.target.target_os == 'cgc'
        if trace_mode == TraceMode.FULL_SYMBOLIC:
            self.tracer = SimTracer(self, **tracer_opts, is_cgc=is_cgc)
        elif trace_mode == TraceMode.HALFWAY:
            self.tracer = HalfwayTracer(self, **tracer_opts, is_cgc=is_cgc)
        elif trace_mode == TraceMode.DUMB:
            self.tracer = DumbTracer(self, **tracer_opts, is_cgc=is_cgc)
        else:
            raise ValueError("Unknown trace_mode: %s" % trace_mode)

        self._t = None
        self.trace_result = None

        # cgc related
        self.format_infos = format_infos

    def _input_preparation(self, crash_input, actions, input_type):
        # FIXME: current implementation assumes there is no short read
        # it can be fixed by implementing a "read stop" mechanism in precontrained_file
        assert not self.pov_file, "POV file is not supported anymore!"
        assert actions or crash_input

        channel = self.input_type_to_channel(input_type)

        if actions:
            crash_input = b''
            sim_input = []
            for act in actions:
                if type(act) == RexSendAction:
                    crash_input += act.data
                    sim_input.append(act.sim_data)
            sim_input = claripy.Concat(*sim_input)
        else:
            open_act = RexOpenChannelAction(channel_name=channel)
            send_act = RexSendAction(crash_input, channel_name=channel)
            actions = [open_act, send_act]
            sim_input = send_act.sim_data
        if not crash_input:
            raise ValueError("Crash input is empty! If you are using actions," +
                             "plz make sure there is at least one RexSendAction in it!")
        return crash_input, actions, sim_input

    def concrete_trace(self):
        """
        collect a concrete trace
        """
        self.tracer.tracer_bow.pickup_env()

        # use the last input as the taint to locate the communication socket fd
        for i in range(len(self.actions)-1, -1, -1):
            act = self.actions[i]
            if type(act) == RexSendAction:
                taint = act.data
                break
        taint = taint[:0x100]
        # FIXME: we disable communication fd analysis for now because of issues with shellphish-qemu releases
        taint = None

        # transform input to channel and test_case
        channel, testcase = self._prepare_channel()
        self.trace_result, self.core_registers = self.tracer.concrete_trace(testcase, channel,
                                                                             self.pre_fire_hook,
                                                                             delay=self.delay,
                                                                             actions=self.actions,
                                                                             taint=taint)
        if self.tracer._is_cgc:
            self.tracer.cgc_flag_page_magic = self.trace_result.magic_contents

    def symbolic_trace(self):
        """
        Symbolically trace the target program with the given input. A NonCrashingInput exception will be raised if the
        target program does not crash with the given input.

        :return:                None.
        """

        # Prepare the initial state
        if self.initial_state is None:
            self.initial_state = self._create_initial_state(self._test_case, cgc_flag_page_magic=self.tracer.cgc_flag_page_magic)

        simgr = self.project.factory.simulation_manager(
            self.initial_state,
            save_unsat=False,
            hierarchy=False,
            save_unconstrained=self.trace_result.crashed
        )

        # trace symbolically!
        # since we have already grabbed mapping info through datascoutbow in angr_project_bow, we can assume
        # there are no aslr slides
        forward = isinstance(self.tracer, SimTracer)
        self._t = self.trace_result.tracer_technique(keep_predecessors=2,
                                                     copy_states=False,
                                                     mode=TracingMode.Strict,
                                                     aslr=False,
                                                     fast_forward_to_entry=forward)
        simgr.use_technique(self._t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        if self.is_cgc:
            s = simgr.one_active
            ChallRespInfo.prep_tracer(s, self.format_infos)
            ZenPlugin.prep_tracer(s)
        simgr.run()

        # tracing completed
        # if there was no crash we'll have to use the previous path's state
        if simgr.stashes.get('crashed', []):
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

    def create_project(self):
        """
        create an angr project through archr
        """
        # Initialize an angr Project

        self.project = self.tracer.create_project(self.target)

    def _create_initial_state(self, testcase, cgc_flag_page_magic=None):

        assert type(testcase) in (bytes, tuple, list), "TracePov is no longer supported"

        stdin_file = None
        socket_queue = None
        if self.input_type == CrashInputType.TCP:
            socket_queue = [ ]
            for i in range(10):
                # Initialize the first N socket pairs
                input_sock = SimPreconstrainedFileStream(
                    preconstraining_handler=self._preconstrain_file,
                    name="aeg_tcp_in_%d" % i,
                    ident='aeg_input_tcp_%d' % i,
                    content=self.sim_input
                )
                output_sock = SimFileStream(name="aeg_tcp_out_%d" % i)
                socket_queue.append([input_sock, output_sock])
        else:
            stdin_file = SimPreconstrainedFileStream(
                preconstraining_handler=self._preconstrain_file,
                name='stdin',
                ident='aeg_input_stdin',
                content=self.sim_input
            )

        # if we already have a core dump, use it to create the initial state
        initial_state = self.tracer.create_state(self.target)

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

        # Loosen certain libc limits on symbolic input
        initial_state.libc.buf_symbolic_bytes = 3000
        initial_state.libc.max_symbolic_strchr = 3000
        initial_state.libc.max_str_len = 3000
        initial_state.libc.max_buffer_size = 16384

        initial_state = self.tracer.bootstrap_state(initial_state)

        return initial_state

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
            test_case = self.crash_input
            channel = self.input_type_to_channel(self.input_type)
        self._channel = channel
        self._test_case = test_case
        return channel, test_case

    @staticmethod
    def input_type_to_channel(input_type):
        channel = Crash._input_type_to_channel_type(input_type)
        if channel != "stdio":
            channel += ":0"
        return channel

    @staticmethod
    def _input_type_to_channel_type(input_type):
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

    @property
    def is_cgc(self):
        """
        Are we working on a CGC binary?
        """
        return self.target.target_os == 'cgc'

    @property
    def is_linux(self):
        """
        Are we working on a Linux binary?
        """
        return self.target.target_os == 'linux'

class Crash(CommCrash):
    """
    Triage and exploit a crash using angr.
    The highest level crash object, perform analysis on the crash state.
    """
    def __init__(self, target, crash=None, pov_file=None, actions=None,
                       aslr=None, use_crash_input=True, explore_steps=0, **kwargs):
        """
        :param aslr:                Analyze the crash with aslr on or off.
        :param use_crash_input:     if a byte is not constrained by the generated exploits,
                                    use the original crash input to fill the byte.
        """
        # for backward compatibility, inputs are specified in Crash
        super().__init__(target, crash=crash, pov_file=pov_file, actions=actions, **kwargs)

        self.use_crash_input = use_crash_input
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
        # this has to happen after _initialize so the project is initialized
        self.aslr = aslr
        if aslr is None:
            self.aslr = not self.is_cgc

        # Work
        self._work()

        # rop related initialization
        self.soft_load_cache()
        self.initialize_rop()
        self.initialize_libc_rop()
        self.soft_save_cache()

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

    def libc_memory_control(self):
        """
        determine what symbolic memory we control which is at a constant address in libc if libc_rop is enabled

        TODO: be able to specify that we want to know about things relative to a certain address

        :return:        A mapping from address to length of data controlled at that address
        """

        control = { }

        if self.aslr or self.libc_rop is None:
            return control

        # PIE binaries will give no global control without knowledge of the binary base
        if self.aslr and self.libc_rop.project.loader.main_object.pic: # unless aslr is off, we're shit out of luck
            return control

        min_addr = self.libc_rop.project.loader.main_object.min_addr
        max_addr = self.libc_rop.project.loader.main_object.max_addr
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
        stack_core_obj = self.project.loader.find_object_containing(sp)
        stack_max_addr = stack_core_obj.max_addr if stack_core_obj is not None else (sp + 0xfff) & ~0xfff
        MAX_RETURN_ADDR_SP_DISTANCE = 16
        for addr in self.symbolic_mem:
            # we have to do max now since with halfway_tracing the initial_state.regs.sp is no longer guaranteed to be
            # the highest. we need some wiggle room to make sure our stack is included, figure it if there's a better
            # way to do this later

            # discard our fake heap etc
            if addr > stack_max_addr:
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
                # however, we want to make sure that we don't incorrectly believe that we control the stored return
                # address on the stack - we do not want to overwrite it with shellcode!
                if self.state._ip.symbolic and addr < sp <= addr + control[addr]:
                    for distance in range(0, MAX_RETURN_ADDR_SP_DISTANCE, self.state.arch.bytes):
                        expr = self.state.memory.load(sp - distance,
                                                      size=self.state.arch.bytes,
                                                      endness=self.state.arch.memory_endness)
                        if not self.state.solver.satisfiable(extra_constraints=(expr != self.state._ip,)):
                            # oops we found the stored return address in this region - break it into two
                            chunk_size = control[addr]
                            chunk0_size = sp - distance - addr
                            control[addr] = chunk0_size
                            chunk1_addr = sp - distance + self.state.arch.bytes
                            control[chunk1_addr] = chunk_size - self.state.arch.bytes - control[addr]
                            break

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
                    l.warning("Gap around stack pointer is detected. Refining controlled regions.")
                    # break the controlled region
                    filtered_control[addr] = gap_start - addr
                    if addr + size - gap_end > 0:
                        filtered_control[gap_end] = addr + size - gap_end
                    continue

            filtered_control[addr] = size

        return filtered_control

    def copy(self):
        cp = Crash.__new__(Crash)
        cp.target = self.target
        cp.binary = self.binary
        cp.libc_binary = self.libc_binary
        cp.tracer = self.tracer
        cp.trace_result = self.trace_result
        cp.crash_input = self.crash_input
        cp.pov_file = self.pov_file
        cp.input_type = self.input_type
        cp.project = self.project
        cp.aslr = self.aslr
        cp.prev = self.prev.copy()
        cp.state = self.state.copy()
        cp.initial_state = self.initial_state
        cp.rop = self.rop
        cp.libc_rop = self.libc_rop
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
        cp.actions = self.actions
        cp._rop_cache_path = self._rop_cache_path
        cp.sim_input = self.sim_input
        cp._bad_bytes = self._bad_bytes

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

        self.concrete_trace()
        self.create_project()
        self.initialize_project()

    def _work(self):
        """
        Perform tracing, memory write filtering, and crash triaging.

        :return:    None
        """
        self.symbolic_trace()

        l.info("Filtering memory writes.")
        self._filter_memory_writes()

        l.info("Triaging the crash.")
        self._triage_crash()

        l.info("Identifying bad_bytes")
        self._bad_bytes = self.tracer.identify_bad_bytes(self)
        l.debug("idenfity bad bytes: %s", [hex(x) for x in self._bad_bytes])

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
        tracer_opts = self._tracer_opts.copy()
        tracer_opts["tracer_bow"] = self.tracer.tracer_bow
        self.__init__(self.target,
                crash=new_input,
                tracer_opts=tracer_opts,
                explore_steps=self.explore_steps + 1,
                constrained_addrs=self.constrained_addrs + [self.violating_action],
                use_rop=self._use_rop)

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

        tracer_opts = self._tracer_opts.copy()
        tracer_opts["tracer_bow"] = self.tracer.tracer_bow
        self.__init__(self.target,
                new_input,
                tracer_opts=tracer_opts,
                explore_steps=self.explore_steps + 1,
                constrained_addrs=self.constrained_addrs + [self.violating_action],
                use_rop=self._use_rop)

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
                       any("aeg_input" in v for v in self.state.memory.load(m, 1).variables)]
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
        recent_actions = reversed(self.state.history.actions)
        for a in recent_actions:
            if a.type == 'mem' and self.state.solver.symbolic(a.addr.ast):
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
            if any(v.startswith('cgc-flag') or v.startswith("random") for v in list(c.variables)):
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
