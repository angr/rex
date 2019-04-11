from abc import ABC
from abc import abstractmethod

import claripy
import logging
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream


_l = logging.getLogger(name=__name__)
_l.setLevel(logging.DEBUG)

class SensitiveTarget(ABC):

    def __init__(self):
        pass

    @abstractmethod
    def taint_state(self, state):
        pass


class ArgvSensitiveTarget(SensitiveTarget):

    def __init__(self, argv_idx):
        super().__init__()
        self.argv_idx = argv_idx

    def taint_state(self, state):
        argv_start_address = state.se.eval(state.posix.argv)
        target_argv_pointer = argv_start_address + state.arch.bytes * self.argv_idx
        target_argv_address = state.mem[target_argv_pointer].long.concrete
        original_argv_size = len(state.mem[target_argv_address].string.concrete)

        _l.debug("Storing sensitive data at {}, size of sensitive data is {}".format(hex(target_argv_address), 8*original_argv_size))

        state.memory.store(target_argv_address, claripy.BVS('sensitive_argv{}'.format(self.argv_idx), 8*original_argv_size) )



class FileSensitiveTarget(SensitiveTarget):

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def taint_state(self, state):
        raise NotImplementedError


class AddressSensitiveTarget(SensitiveTarget):

    def __init__(self, start_addr, end_addr):
        super().__init__()
        self.start_addr = start_addr
        self.end_addr = end_addr

    def taint_state(self, state):
        raise NotImplementedError
