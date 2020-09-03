#!/usr/bin/env python

# Copyright 2017 Eotvos Lorand University, Budapest, Hungary
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import print_function
import pprint
import hlir16


def indentprint(data):
    from pprint import pformat
    lines = pformat(data).splitlines(True)
    print(''.join(['        {}'.format(line) for line in lines]))


def load_p4_using_args():
    import sys

    if len(sys.argv) <= 1:
        print("TODO usage")
        sys.exit()

    p4c_file = sys.argv[1]
    p4v      = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    p4c_path = sys.argv[3] if len(sys.argv) > 3 else None

    program = hlir16.load_p4(p4c_file, p4v, p4c_path)

    # If we got an int, it's an error code.
    if type(program) is int:
        print("TODO error message", program)
        sys.exit(program)

    return program


program = load_p4_using_args()

decltypes = [
    'Declaration_Instance',
    'Declaration_MatchKind',
    'Method',
    'P4Control',
    'P4Parser',
    'Type_Control',
    'Type_Error',
    'Type_Extern',
    'Type_Header',
    'Type_Package',
    'Type_Parser',
    'Type_Struct',
    'Type_Typedef',
]

for decltype in decltypes:
    print(decltype)
    indentprint(program.declarations[decltype])

print("-----------------------")

print(program)
print(program.is_vec())
print(program.xdir())

print("-----------------------")

print(program.declarations)

print("-----------------------")

print(program.declarations.xdir())
print(program.declarations.is_vec())
print(len(program.declarations))

print("-----------------------")

for idx, e in enumerate(program.declarations):
    print(idx, program.declarations[idx])

pprint.pprint(program.declarations['Type_Control'])
pprint.pprint(program.declarations['Type_Control'][0].applyParams.parameters.vec)
for decl in program.declarations['Type_Control']:
    for e in decl.applyParams.parameters.vec:
        if e.type is None:
            continue
        print(decl.name, e.direction, e.type.path, e.type.path.name, e.type.path.absolute, e.name, e.id)

# Note: it is also possible to set custom attributes
program.add_attrs({'controls': program.declarations['Type_Control']})

print(len(program.controls))
print(program.controls[0].applyParams.parameters[0].name)
