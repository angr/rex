import os
import shutil
import random
import struct
import socket
import signal
import resource
import tempfile

import angr
import tracer

import logging

l = logging.getLogger("rex.pov_testing.cgc_pov_tester")

class CGCPovTester(object):
    registers = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

    def __init__(self, expected_type=None, expected_register=None):
        self.expected_type = expected_type
        self.expected_register = expected_register

    def test_binary_pov(self, pov_filename, cb_path, enable_randomness=True):
        # Test the binary pov

        # sanity checks
        if not os.path.isfile(pov_filename):
            raise ValueError("pov is does not exist")

        if not os.access(pov_filename, os.X_OK):
            raise ValueError("pov is not executable")

        if not os.path.isfile(cb_path):
            raise ValueError("cb does not exist")

        if not os.access(cb_path, os.X_OK):
            raise ValueError("cb is not executable")

        # create the communication pipes
        pov_r, pov_w = os.pipe()
        challenge_r, challenge_w = os.pipe()
        negotiation_pov, negotiation_infra = socket.socketpair()

        qemu_path = os.path.join(os.path.dirname(tracer.__file__), '..',
                                 'bin', 'tracer-qemu-cgc')

        # create directory for core files
        directory = tempfile.mkdtemp(prefix='rex-test-', dir='/tmp')
        cb_path = os.path.realpath(cb_path)

        # fork off the challenge binary
        challenge_bin_pid = os.fork()
        if challenge_bin_pid == 0:
            # cd in tempdir
            os.chdir(directory)

            # set up core dumping, only used by type1 though

            # pylint:disable=no-member
            resource.setrlimit(
                    resource.RLIMIT_CORE,
                    (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
                    )

            devnull = open('/dev/null', 'w')

            # close the other entry
            os.close(pov_w)
            os.close(challenge_r)

            os.dup2(pov_r, 0)  # read from pov as stdin
            os.dup2(challenge_w, 1)  # write to the pov
            os.dup2(devnull.fileno(), 2)  # silence segfault message

            if enable_randomness:
                seed = str(random.randint(0, 100000))
                argv = [qemu_path, "-seed", seed, "-magicdump", "magic", cb_path]
            else:
                argv = [qemu_path, "-magicdump", "magic", cb_path]
            os.execve(qemu_path, argv, os.environ)

            assert False, "failed to execute target binary %s" % cb_path

        # fork off the pov binary
        pov_pid = os.fork()
        if pov_pid == 0:

            # close the other entry
            os.close(pov_r)
            os.close(challenge_w)

            os.dup2(challenge_r, 0)  # read from challenge's stdout
            os.dup2(pov_w, 1)  # write to challenge's stdin

            # file descriptor 3 is the negotiation server
            os.dup2(negotiation_pov.fileno(), 3)

            os.execve(qemu_path, [qemu_path, pov_filename], os.environ)

        # clean up the pipes in the host
        os.close(challenge_r)
        os.close(challenge_w)
        os.close(pov_r)
        os.close(pov_w)

        l.debug("challenge_r: %d", challenge_r)
        l.debug("challenge_w: %d", challenge_w)
        l.debug("pov_r: %d", pov_r)
        l.debug("pov_w: %d", pov_w)
        l.debug("pov_pid: %d", pov_pid)
        l.debug("challenge_bin_pid: %d", challenge_bin_pid)

        # negiotation is specific to type1 / type2
        result = self._do_binary_negotiation(negotiation_infra, directory,
                                             challenge_bin_pid)

        # wait for pov to terminate
        os.waitpid(pov_pid, 0)

        # clean up test directory
        shutil.rmtree(directory)

        return result

    def _do_binary_negotiation(self, negotiation_pipe, directory,
                               challenge_binary_pid):
        """
        Negotiate with a PoV binary
        :param negotiation_pipe: pipe to read negotiation materials from
        :param directory: directory core file will be found
        :param challenge_binary_pid: pid of the challenge binary, we will wait
        for it to exit
        :return: boolean describing whether the binary pov behaved correctly
        """

        pov_type = struct.unpack("<I", negotiation_pipe.recv(4))[0]

        # check pov type before doing the correct negotiation
        if self.expected_type is not None:
            if pov_type != self.expected_type:
                l.error("received incorrect pov type")
                return False

        l.debug("recieved pov_type of %d\n", pov_type)
        if pov_type == 1:
            l.debug("entering type1 negotiation")
            return self._do_binary_negotiation_type_1(negotiation_pipe, directory,
                                                      challenge_binary_pid)
        elif pov_type == 2:
            l.debug("entering type2 negotiation")
            return self._do_binary_negotiation_type_2(negotiation_pipe, directory,
                                                      challenge_binary_pid)
        else:
            l.error("Invalid pov type: %d", pov_type)
            return False

    def _do_binary_negotiation_type_1(self, negotiation_pipe, directory,
                                      challenge_binary_pid):
        """
        Negotiate with a Type 1 PoV binary
        :param negotiation_pipe: pipe to read negotiation materials from
        :param directory: directory core file will be found
        :param challenge_binary_pid: pid of the challenge binary, we will wait
        for it to exit
        :return: boolean describing whether the binary pov behaved correctly
        """

        ipmask = struct.unpack("<I", negotiation_pipe.recv(4))[0]
        regmask = struct.unpack("<I", negotiation_pipe.recv(4))[0]
        regnum = struct.unpack("<I", negotiation_pipe.recv(4))[0]

        l.debug("recieved a ipmask of %#x", ipmask)
        l.debug("recieved a regmask of %#x", regmask)
        l.debug("recieved a regnum of %#x", regnum)

        register = CGCPovTester.registers[regnum]
        if self.expected_register is not None:
            if register != self.expected_register:
                l.error("unexpected register number received during negotiation")
                return False

        if bin(regmask).count("1") < 20:
            l.error("received a regmask with not enough bits set")
            return False
        if bin(ipmask).count("1") < 20:
            l.error("received a ipmask with not enough bits set")
            return False

        reg_val = random.randint(0, 0xffffffff)
        ip_val = random.randint(0, 0xffffffff)

        l.debug("requesting a register value of %#x", reg_val)
        l.debug("requesting a ip value of %#x", ip_val)

        negotiation_pipe.send(
                struct.pack("<I", ip_val) + struct.pack("<I", reg_val)
                )

        l.debug("waiting on challenge binary...")

        _, returncode = os.waitpid(challenge_binary_pid, 0)

        l.debug("... challenge binary terminated")

        # only check the relevant bits
        returncode &= 0x7f

        if returncode not in [signal.SIGSEGV, signal.SIGILL]:
            l.error("challenge binary did not crash, instead returned exit code %d", returncode)
            return False

        corefile = None
        for item in os.listdir(directory):
            if item.endswith('.core'):
                corefile = os.path.join(directory, item)
                break

        if corefile is None:
            l.error("no core file found, challenge binary crashed?")
            return False

        l.debug("found corefile for challenge in file %s", corefile)

        # load core file and grab registers
        p = angr.Project(corefile)
        set_reg_value = None
        set_ip_value = None
        for reg, val in p.loader.main_bin.initial_register_values():
            if reg == register:
                set_reg_value = val
            if reg == "eip":
                set_ip_value = val

        if set_ip_value is None:
            l.error("eip's value not found in core file")
            return False
        if set_reg_value is None:
            l.error("%s's value not found in core file", register)
            return False

        l.debug("register value set to: %#x", set_reg_value)
        l.debug("ip value set to: %#x", set_ip_value)

        register_set = set_reg_value & regmask == reg_val & regmask
        ip_set = set_ip_value & ipmask == ip_val & ipmask

        if not ip_set:
            l.warning("Ip was not set correctly")

        if not register_set:
            l.warning("Register was not set correctly")

        # clean up the dropped core
        os.remove(corefile)

        return register_set and ip_set

    @staticmethod
    def _do_binary_negotiation_type_2(negotiation_pipe, directory,
                                      challenge_bin_pid):
        """
        Negotiate with a Type 2 PoV binary
        :param negotiation_pipe: pipe to read negotiation materials from
        :param directory: directory core file to be found in
        :param challenge_bin_pid: pid of the challenge binary, we will for
        it to exit
        :return: boolean describing whether the binary pov behaved correctly
        """

        # have the exploit leak from the magic page, believe this is fixed
        region_addr = 0x4347c000
        region_size = 0x1000
        read_size = 4

        type2_vals = [region_addr, region_size, read_size]
        type2_vals_elems = map(lambda x: struct.pack("<I", x), type2_vals)
        l.debug("sent off type2 params (%#x, %#x, %#x)", region_addr, region_size, read_size)
        negotiation_pipe.send(''.join(type2_vals_elems))

        # receive the leaked flag data
        flag_data = negotiation_pipe.recv(read_size)

        l.debug("received flag data %#x", struct.unpack("<I", flag_data)[0])

        # check if it exists within the region
        magic_data = open(os.path.join(directory, 'magic')).read()
        succeeded = flag_data in magic_data

        l.debug("pov successful? %s", succeeded)

        # wait for the challenge to exit
        os.waitpid(challenge_bin_pid, 0)

        return succeeded
