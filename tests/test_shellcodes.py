import re
import random
import unittest

import archinfo
import angr

import pwnlib

from angr.procedures.definitions import SimLibrary
from angr.simos import SimLinux
from archinfo import Endness
from rex.exploit import Shellcodes


arch_to_pwntools = {
    'ARMEL': 'arm',
    'MIPS32': 'mips',
    'X86': 'i386',
    'AMD64': 'amd64',
}
endness_to_pwntools = {
    Endness.LE: 'little',
    Endness.BE: 'big'
}

class TestRunDupsh(unittest.TestCase):
    def _run_dupsh(self, arch, fd_to_dup):
        print(f"Testing shellcode to dup fd {fd_to_dup} for architecture {arch}!")
        shellcode = Shellcodes['unix'][arch.name]['dupsh'](fd=(fd_to_dup,)).raw(arch=arch)
        if arch.name == 'ARMEL':
            # VEX sucks at decoding SVC instructions with operands that are non-zero, so we replace them
            shellcode = shellcode.replace(b'\x01\xdf', b'\x00\xdf').replace(b'\x41\xdf', b'\x00\xdf')
        with pwnlib.context.context.local(arch=arch_to_pwntools[arch.name],
                                          endian=endness_to_pwntools[arch.memory_endness]):
            elf_path = pwnlib.asm.make_elf(shellcode, extract=False)
        proj = angr.Project(elf_path, auto_load_libs=False)
        assert isinstance(proj.simos, SimLinux)
        syscall_lib : SimLibrary = proj.simos.syscall_library

        dups_to_check = {0, 1, 2}

        class logging_dup2(angr.SimProcedure):  # pylint:disable=invalid-name
            def run(self, fd1, fd2):  # pylint:disable=arguments-differ
                fd1 = self.state.solver.eval_one(fd1)
                fd2 = self.state.solver.eval_one(fd2)
                print(f"dup2({fd1}, {fd2})")
                assert fd1 == fd_to_dup, 'did not dup2 the correct source file descriptor'
                assert fd2 in dups_to_check, \
                    'dup2\'ed to a file descriptor that was either not requested or already dup\'ed'
                dups_to_check.remove(fd2)

        class logging_execve(angr.SimProcedure):  # pylint:disable=invalid-name
            def run(self, binary, argv, envp):  # pylint:disable=arguments-differ
                assert not dups_to_check, "Shellcode failed to dup some fds: " + repr(dups_to_check)
                binary = self.state.mem[binary].string.concrete
                assert re.fullmatch(b'/+bin/+sh', binary), \
                    f"The shellcode executed {bin} instead of /bin/sh"
                progname = self.state.mem[argv].deref.string.concrete
                assert progname == b'sh' or re.fullmatch(b'/+bin/+sh', progname), \
                    f"The shellcode did not set argv[0] correctly, instead it set it to {progname}"
                assert self.state.mem[argv].uintptr_t.array(2)[1].concrete == 0, \
                    "The shellcode didn't NULL terminate argv"
                assert self.state.solver.eval_one(envp) == 0 or \
                       self.state.mem[envp].uintptr_t.concrete == 0, \
                    "envp is incorrect"
                self.exit(0)

        syscall_lib.add('dup2', logging_dup2)
        syscall_lib.add('execve', logging_execve)

        state = proj.factory.entry_state(add_options={
            angr.options.TRACK_MEMORY_ACTIONS,
            angr.options.TRACK_REGISTER_ACTIONS,
            angr.options.TRACK_CONSTRAINT_ACTIONS
        })
        simgr = proj.factory.simulation_manager(state)
        simgr.run()
        assert simgr.deadended and not simgr.errored, f"An error occurred: {simgr.errored[0]}"

    def test_ArchX86(self):
        self._run_dupsh(archinfo.ArchX86(), random.randint(0, 60))

    def test_ArchAMD64(self):
        self._run_dupsh(archinfo.ArchAMD64(), random.randint(0, 60))

    def test_ArchMIPS32_LE(self):
        self._run_dupsh(archinfo.ArchMIPS32(endness=Endness.LE), random.randint(0, 60))

    def test_ArchMIPS32_BE(self):
        self._run_dupsh(archinfo.ArchMIPS32(endness=Endness.BE), random.randint(0, 60))

    def test_ArchARMEL(self):
        self._run_dupsh(archinfo.ArchMIPS32(endness=Endness.BE), random.randint(0, 60))

if __name__ == '__main__':
    unittest.main()
