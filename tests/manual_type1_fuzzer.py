from rex import pov_fuzzing
import os

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_fuzzer = pov_fuzzing.Type1CrashFuzzer(bin_location + "/tests/cgc/CROMU_00071", crash='2\n1BA\n\n2\n1BB\n\n2\n1BC\n\n2\n1BD\n\n2\n1BE\n\n2\n1BF\n\n2\n1BG\n\n2\n1BH\n\n2\n1BI\n\n2\n1BJ\n\n2\n1BK\n\n2\nAAA\n\n2/111/1BA/1/1/1BB/2/2/1BC/3/3/1BD/4/4/1BE/5/5/1BF/6/6/1BG/7/7/1BH/8/8/1BI/9/9/1BJ/10/10/1BK/14/14/AAA/2586475074/0\n13\n')

for i in range(10):
    if not pov_fuzzer.test_binary():
        raise Exception("wtf")
