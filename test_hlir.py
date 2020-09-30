#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node
import hlir16.hlir
from hlir16.hlir_attrs import set_additional_attrs

import sys
import pprint
import os.path


def indentprint(data):
    lines = pprint.pformat(data).splitlines(True)
    print(''.join([f'        {line}' for line in lines]))


def load_p4(p4_file, p4_version=16, add_attrs=True):
    p4_file = os.path.expandvars(p4_file)
    json_filename = hlir16.hlir.p4_to_json(p4_file)

    import simdjson
    with open(json_filename, 'r') as json:
        json_contents = simdjson.load(json)

    hlir = hlir16.hlir.walk_json_from_top(json_contents)
    if type(error_code := hlir) is not P4Node:
        print(f"Could not load P4 file {p4_file}, error code: {error_code}")
        sys.exit(error_code)

    if add_attrs:
        set_additional_attrs(hlir, p4_version)

    return hlir


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("TODO usage")
        sys.exit()

    program = load_p4(sys.argv[1])
    p4_version = int(sys.argv[2]) if len(sys.argv) > 2 else 16

    hlir = load_p4(program, p4_version)

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
