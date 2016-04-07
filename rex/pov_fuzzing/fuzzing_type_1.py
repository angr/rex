import logging
import tempfile
from collections import defaultdict
from multiprocessing import Pool
from rex.pov_testing import CGCPovTester

import angr
import tracer
import compilerex
import fuzzing_type_1_c_template

l = logging.getLogger("rex.fuzzing_type_1")
logging.getLogger("cle.elfcore").setLevel("CRITICAL")
l.setLevel("DEBUG")


NUM_CGC_BITS = 20


class ByteAnalysis(object):
    def __init__(self):
        self.valid_bytes = set()
        self.bytes_that_dont_crash = set()
        self.bytes_that_cause_diff_crash = set()
        self.bytes_that_change_registers = set()
        self.register_pattern_maps = dict()
        self.register_bitmasks = dict()


class CrashFuzzerException(Exception):
    pass


# TODO move to it's own project?
# TODO make this fast bprm->core_dump
# have qemu write to stderr?
def _get_reg_vals(binary_input_byte):
    binary, test_input, c = binary_input_byte
    r = tracer.Runner(binary, input=test_input)
    if not r.crash_mode:
        return [c, None]
    else:
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
        r = tracer.Runner(self.binary, input=self.crash)
        if not r.crash_mode:
            raise CrashFuzzerException("input did not crash the binary")

        self._p = angr.Project(self.binary)

        self.orig_regs = r.reg_vals

        self.pool = None
        self.byte_analysis = dict()
        self.reg_analysis = defaultdict(dict)
        self.run()

    def run(self):
        self.pool = Pool(processes=8)
        # for each byte of input we will try all possible characters and determine how they change bits in the registers
        for i in range(84, len(self.crash)):
            self.analyze_byte(i)
        self.pool.close()

    def analyze_byte(self, byte_index):
        l.info("fuzzing byte %d", byte_index)
        bytes_to_regs = dict()

        bytes_that_change_crash = set()
        bytes_that_dont_crash = set()
        bytes_that_dont_affect_regs = set()
        bytes_that_affect_regs = set()

        binary_input_bytes = []
        for i in xrange(256):
            input = self.crash[:byte_index] + chr(i) + self.crash[byte_index+1:]
            binary_input_bytes.append((self.binary, input, chr(i)))
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
        for c in bytes_to_regs.keys():
            reg_vals = bytes_to_regs[c]
            num_diff = 0
            for r in reg_vals.keys():
                if reg_vals[r] != self.orig_regs[r]:
                    num_diff += 1

            if num_diff == 0:
                bytes_that_dont_affect_regs.add(c)
            elif num_diff > 1 and reg_vals["eip"] != self.orig_regs["eip"] and \
                    self._p.loader.main_bin.contains_addr(reg_vals["eip"]):
                bytes_that_change_crash.add(c)
            else:
                bytes_that_affect_regs.add(c)

        # the goal here is to find which bits of regs are contolled here
        all_reg_vals = defaultdict(set)
        for c in bytes_that_affect_regs:
            reg_vals = bytes_to_regs[c]
            for reg in reg_vals.keys():
                all_reg_vals[reg].add(reg_vals[reg])

        byte_analysis = ByteAnalysis()
        self.byte_analysis[byte_index] = byte_analysis
        byte_analysis.valid_bytes = set(bytes_to_regs.keys())

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
                    raise CrashFuzzerException("byte affects more than 8 bits?")

                # might want to check for impossible bit patterns
                if controlled_bits != 0:
                    # check that all bitmasks are possible for those bits

                    # now map the patterns were not possible
                    all_patterns = set()
                    for i in range(2**number_bits):
                        pattern = 0
                        for n, index in enumerate(bit_indices):
                            if (1 << n) & i != 0:
                                pattern |= (1 << index)

                        all_patterns.add(pattern)

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
                    l.info("Register %s has the following bitmask %s for byte %d of the input",
                           reg, hex(controlled_bits), byte_index)
                    byte_analysis.register_bitmasks[reg] = controlled_bits

    def exploitable(self):
        reg_bitmasks = defaultdict(int)
        for byte_analysis in self.byte_analysis.values():
            for r in byte_analysis.register_bitmasks:
                reg_bitmasks[r] |= byte_analysis.register_bitmasks[r]

        if bin(reg_bitmasks["eip"]).count("1") < NUM_CGC_BITS:
            return False

        for r in reg_bitmasks:
            if r == "eip":
                continue
            if bin(reg_bitmasks[r]).count("1") >= NUM_CGC_BITS:
                return True
        return False

    def _create_translation_c(self, general_reg):
        # create the bit_pattern table
        # then we inject the bit pattern translation table into the c code
        translation_tables = []
        c_codes = []
        for i, byte_analysis in self.byte_analysis.items():
            if general_reg in byte_analysis.register_bitmasks and byte_analysis.register_bitmasks[general_reg] != 0:
                # now get the bits
                reg_map = byte_analysis.register_pattern_maps[general_reg]
                collapsed_map = dict()
                for pattern, c in reg_map.items():
                    collapsed = self.collapse_bits(pattern, byte_analysis.register_bitmasks[general_reg])
                    collapsed_map[collapsed] = c

                # now make the c table
                table_name = "reg_byte_%d_table" % i
                translation_table = "char " + table_name + "[] = {"
                num_bits = bin(byte_analysis.register_bitmasks[general_reg]).count("1")
                for j in range(2**num_bits):
                    if j in collapsed_map:
                        translation_table += hex(ord(collapsed_map[j])) + ", "
                    else:
                        raise CrashFuzzerException()
                # remove last ", " and add }
                translation_table = translation_table[:-2] + "};\n"
                translation_tables.append(translation_table)

                code = \
"""key_val = collapse_bits(reg_val, %#x);
new_char = %s[key_val];
payload[%d] = new_char;""" % (byte_analysis.register_bitmasks[general_reg], table_name, i)
                c_codes.append(code)

        # now create the translation code
        translation_code = "\n".join(translation_tables) + "\n\n" + "\n\n".join(c_codes)

        return translation_code

    def dump_c(self, filename=None):
        if not self.exploitable():
            raise CrashFuzzerException("Not exploitable")

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
        # general reg should be non-None
        if general_reg is None:
            raise CrashFuzzerException("Must be a bug, it was 'exploitable' but we can't find a register to set")

        translation_c_general = self._create_translation_c(general_reg)
        translation_c_eip = self._create_translation_c("eip")

        encoded_payload = ""
        for c in self.crash:
            encoded_payload += "\\x%02x" % ord(c)

        fmt_args = dict()
        fmt_args["register"] = general_reg
        fmt_args["regmask"] = hex(reg_bitmasks[general_reg])
        fmt_args["ipmask"] = hex(reg_bitmasks["eip"])
        fmt_args["payload"] = encoded_payload
        fmt_args["payloadsize"] = str(len(self.crash))
        fmt_args["generalregtranslate"] = translation_c_general
        fmt_args["ipregtranslate"] = translation_c_eip

        # TODO using .format is annoying because of all the curly braces
        # figure out how to do this better
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

        pov_tester = CGCPovTester()
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
