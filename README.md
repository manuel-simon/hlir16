
# HLIR for P4-16

This program uses [`p4c`](https://github.com/p4lang/p4c) to generate a temporary JSON file
from a `.p4` source file, loads it,
and creates a convenient Python representation out of it.

Supposing that the environment variable `P4C` contains the path to `p4c`
and/or `T4P4S` to the [T4P4S compiler](https://github.com/P4ELTE/t4p4s)
(either the P4-14 based version, or the experimental P4-16 based one,
which uses this library),
you can run the example the following way.
It can be run using either Python 2 or Python 3.

~~~.bash
python test_hlir16.py "$P4C/testdata/p4_16_samples/vss-example.p4" 16

python test_hlir16.py "$T4P4S/examples/l2_switch_test.p4" 14
~~~

Note that the program accesses some arbitrary elements of the representation.
If you load different files, their structure will be different as well,
and you might get an exception because you're trying to access non-existing constructs.
