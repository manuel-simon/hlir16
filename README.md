
# HLIR for P4-16

This program uses [`p4c`](https://github.com/p4lang/p4c) to generate a temporary JSON file
from a `.p4` source file, loads it,
and creates a convenient Python representation out of it.

Supposing that the environment variable `P4C` contains the path to `p4c`,
you can run the example the following way.
It can be run using either Python 2 or Python 3.

~~~.bash
python test_hlir16.py "$P4C" "$P4C/testdata/p4_16_samples/vss-example.p4"
~~~
