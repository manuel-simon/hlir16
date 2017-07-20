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


import json
import subprocess
import os
import tempfile
from p4node import P4Node

from utils_hlir16 import *


def has_method(obj, method_name):
    return hasattr(obj, method_name) and callable(getattr(obj, method_name))


def walk_json(node, fun, nodes, skip_elems=['Node_Type', 'Node_ID'], node_parent_chain=[]):
    rets = []
    if type(node) is dict or type(node) is list:
        node_id = node['Node_ID']
        if node_id not in nodes:
            nodes[node_id] = P4Node({
                'incomplete_json_data': True,
                'node_parents': [node_parent_chain],
            })

        if 'vec' in node.keys():
            elems = [(None, elem) for elem in node['vec']]
        else:
            elems = [(key, node[key]) for key in node.keys() if key not in skip_elems]
        rets = [(key, walk_json(elem, fun, nodes, skip_elems, node_parent_chain + [nodes[node_id]])) for (key, elem) in elems if elem != {}]

    return fun(node, rets, nodes, skip_elems, node_parent_chain)


def p4node_creator(node, elems, nodes, skip_elems, node_parent_chain):
    if type(node) is not dict and type(node) is not list:
        # note: types: string, bool, int
        return node

    node_id = node['Node_ID']
    p4node = nodes[node_id]

    p4node.add_attrs({
        "id": node_id,
        "json_data": node,
    })

    if node_parent_chain not in p4node.node_parents:
        p4node.node_parents += [node_parent_chain]

    if 'Node_Type' in node.keys():
        p4node.add_attrs({"node_type": node['Node_Type']})
        p4node.remove_attr('incomplete_json_data')

    if 'vec' in node.keys():
        no_key_elems = [elem for key, elem in elems]
        nodes[node_id].set_vec(no_key_elems)
    else:
        for key, subnode in elems:
            nodes[node_id].add_attrs({key: subnode})

    return nodes[node_id]


def create_p4_json_file(p4c_filename, p4_version=None, p4c_path=None, json_filename=None):
    """Translates the P4 file into a JSON file.
    If no filename is given, a temporary one is created."""
    if p4c_path is None:
        p4c_path = os.environ['P4C']

    p4test = os.path.join(p4c_path, "build", "p4test")
    p4include = os.path.join(p4c_path, "p4include")

    if json_filename is None:
        json_file = tempfile.NamedTemporaryFile(prefix="p4_out_", suffix=".p4.json")
        json_file.close()
        json_filename = json_file.name

    version_opts = ['--p4v', str(p4_version)] if p4_version is not None else []

    opts = [p4test, "-I", p4include, p4c_filename] + version_opts + ["--toJSON", json_filename]

    errcode = subprocess.call(
        [p4test, p4c_filename, "-I", p4include, "--toJSON", json_filename] + version_opts)

    return (errcode, json_filename)


ERR_CODE_NO_PROGRAM = -1000
def load_p4_json_file(json_filename, p4_version):
    """Returns either ERR_CODE_NO_PROGRAM, an int, or a P4Node object."""
    with open(json_filename, 'r') as f:
        json_root = json.load(f)

    # Note: this can happen if the loaded file does not contain "main".
    if json_root['Node_ID'] is None:
        return ERR_CODE_NO_PROGRAM

    nodes = {}
    walk_json(json_root, p4node_creator, nodes)
    hlir16 = nodes[json_root['Node_ID']]

    set_additional_attrs(hlir16, nodes, p4_version)

    return hlir16


def print_path(full_path, value, root, print_details, max_length=70):
    full_path_txt = ""
    current_node = root
    for elem in full_path:
        if type(elem) is not int:
            current_node = current_node.get_attr(elem)
            current_path = "." + str(elem)
        else:
            if type(current_node) is list:
                subnode = current_node[elem]
                next_node = current_node[elem]
            else:
                subnode = current_node.vec[elem]
                next_node = current_node.vec[elem]

            if type(current_node) is P4Node and type(subnode) is P4Node and subnode.get_attr('node_type') is not None:
                node_type = subnode.get_attr('node_type')
                idx = current_node[node_type].index(subnode)
                current_path = "['{}'][{}]".format(node_type, idx)
            else:
                current_path = "[{}]".format(elem)
            current_node = next_node

        full_path_txt += current_path

        if print_details:
            current_content = ""
            if type(current_node) is list:
                current_content = current_node
            if type(current_node) is P4Node and current_node.is_vec():
                current_content = [subnode.str(show_funs=False) for subnode in current_node.vec]

            current_node_display = current_node.str(show_funs=False) if type(current_node) is P4Node else str(current_node)

            current_node_id = current_node.id if type(current_node) is P4Node else "?"

            print "  - {0:<17}   {1:<6}   {2}   {3}".format(current_path, current_node_id, str(current_node_display)[:max_length], str(current_content)[:max_length])
    print "  *", full_path_txt


def paths_to(node, value, max_depth=20, path=[], root=None, max_length=70, print_details=False, match="prefix"):
    """Finds the paths under node through which the value is accessible.
    The matching is always textual, one of "full", "prefix" or "infix"."""
    if max_depth < 1:
        return

    root = root if root is not None else node

    if (match == "full" and str(node) == str(value)) or (match == "prefix" and str(node).startswith(str(value))) or (match == "infix" and str(value) in str(node)):
        print_path(path, value, root, print_details)
        return

    if type(node) is list:
        for idx, subnode in enumerate(node):
            paths_to(subnode, value, max_depth - 1, path + [idx], root, max_length, print_details, match)
        return

    if type(node) is dict:
        for key in node:
            paths_to(node[key], value, max_depth - 1, path + [key], root, max_length, print_details, match)
        return

    if type(node) != P4Node:
        return

    if node.is_vec():
        for idx, elem in enumerate(node.vec):
            paths_to(node[idx], value, max_depth - 1, path + [idx], root, max_length, print_details, match)
        return

    for attr in node.xdir():
        paths_to(getattr(node, attr), value, max_depth - 1, path + [attr], root, max_length, print_details, match)



def set_additional_attrs(hlir16, nodes, p4_version):
    hlir16.add_common_attrs({
        "all_nodes":
            nodes,
        "p4v":
            p4_version,
    }),

    for idx in hlir16.all_nodes:
        node = hlir16.all_nodes[idx]
        if type(node) is not P4Node:
            continue
        node.add_common_attrs({
            'paths_to':
                # Note: the external lambda makes sure the actual node is the operand,
                # not the last value that the "node" variable takes
                (lambda n: lambda value, print_details=False, match='prefix': paths_to(n, value, print_details=print_details, match=match))(node),
            'by_type':
                (lambda n: lambda typename: P4Node({}, [f for f in hlir16.declarations if f.node_type == typename or f.node_type == 'Type_' + typename]))(node),
        })

    for struct in hlir16.declarations['Type_Struct']:
        hlir16.add_attrs({
            struct.name:
                struct,
        })

    # TODO remove
    if 'IPDB' in os.environ:
        import ipdb
        ipdb.set_trace()


    if hlir16.p4v == 14:
        hlir16.add_attrs({
            'metadatas':
                P4Node({}, [hlir16.standard_metadata_t] + [hlir16.declarations.get(meta.type.path.name, 'Type_Struct') for meta in hlir16.declarations.get('metadata', 'Type_Struct').fields]),
        })
        metadata_inst_names = ['standard_metadata'] + [meta.annotations.annotations.get('name', 'Annotation').expr[0].value for meta in hlir16.declarations.get('metadata', 'Type_Struct').fields]
        for meta, inst_name in zip(hlir16.metadatas, metadata_inst_names):
            meta.add_attrs({'inst_name': inst_name})
    else:
        hlir16.add_attrs({
            'metadatas': [], # TODO
        })

    if hlir16.p4v == 14:
        hlir16.add_attrs({
            'headers':
                hlir16.declarations.get("headers", "Type_Struct").fields,
        })
    else:
        hlir16.add_attrs({
            'headers': [], # TODO
        })

    hlir16.add_attrs({
        'controls':
            hlir16.declarations['Type_Control'],
        'tables':
            [t for ctrl in hlir16.declarations['P4Control']
                for t in ctrl.controlLocals['P4Table']],
        'header_types':
            hlir16.declarations['Type_Header'],
    })

    if p4_version == 16:
        header_instances = hlir16.Parsed_packet.fields['StructField']
    elif p4_version == 14:
        header_instances = hlir16.declarations.get('headers', 'Type_Struct').fields['StructField']

    hlir16.add_attrs({'header_instances': header_instances})

    def add_offsets_to_header(header_type):
        offset = 0
        for fld in header_type.fields:
            fld.add_attrs({'offset': offset})
            size = fld.type.get_attr('size')
            if size is None:
                size = get_type(hlir16, fld).size / 8
            offset += size

    for hdr in hlir16.header_instances:
        hdr.add_attrs({
            'header_type':
                hlir16.declarations.get(hdr.type.path.name, "Type_Header"),
            'bit_offset':
                'TODO',
            'byte_offset':
                'TODO',
            'mask':
                'TODO',
        })

        add_offsets_to_header(hdr.header_type)

    # TODO standard_metadata_t is not accessible in P4-16?
    if hlir16.get_attr('standard_metadata_t') is not None:
        for meta in hlir16.metadatas:
            add_offsets_to_header(meta)


    for table in hlir16.tables:
        # Note: turning the properties into proper properties of the table
        for prop in table.properties.properties:
            table.add_attrs({
                prop.name: prop.value,
            })
        table.remove_attr('properties')

        if table.get_attr('key') is not None:
            table.add_attrs({
                'match_field_names':
                    # TODO probably needs improvement
                    [(str(key.expression.expr.member), str(key.expression.member)) for key in table.key.keyElements if key.expression.expr.get_attr('member')],
                #'match_hdr':
                #    [hlir16.headers.fields],
            })

        if table.get_attr('match_field_names') is not None:
            table.add_attrs({
                'match_type':
                    # TODO more complex than this
                    table.key.keyElements[0].matchType.path.name.upper(),
                'key_length':
                    (sum([hlir16.declarations.get(hlir16.headers.get(header_var_name).type.path.name, 'Type_Header').fields.get(field_name).type.size
                        for header_var_name, field_name in table.match_field_names
                        if hlir16.headers.get(header_var_name) is not None]) +
                        sum([hlir16.declarations.get(hlir16.declarations.get('metadata', 'Type_Struct').fields.get(header_var_name).type.path.name, 'Type_Struct').fields.get(field_name).type.size
                           for header_var_name, field_name in table.match_field_names
                           if hlir16.declarations.get('metadata', 'Type_Struct').fields.get(header_var_name) is not None])
                     +7)/8
            })
        else:
            # TODO is this OK?
            table.add_attrs({
                'match_type':
                    'none',
                'key_length':
                    0,
            })

    # TODO remove
    if 'IPDB' in os.environ:
        import ipdb
        ipdb.set_trace()


def load_p4(filename, p4_version=None, p4c_path=None):
    """Returns either an error code, an int, or a P4Node object."""
    if p4c_path is None:
        p4c_path = os.environ['P4C']

    MOST_RECENT_P4_VERSION = 16
    p4_version = p4_version or MOST_RECENT_P4_VERSION

    if not filename.endswith(".json"):
        (errcode, json_filename) = create_p4_json_file(filename, p4_version, p4c_path)

        if errcode != 0:
            return errcode

    return load_p4_json_file(json_filename, p4_version or MOST_RECENT_P4_VERSION)
