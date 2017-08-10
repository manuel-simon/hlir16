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
import re
from p4node import P4Node

from utils_hlir16 import *


def has_method(obj, method_name):
    return hasattr(obj, method_name) and callable(getattr(obj, method_name))


def walk_json(node, fun, nodes, skip_elems=['Node_Type', 'Node_ID', 'Source_Info'], node_parent_chain=[]):
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

    p4node.id = node_id
    p4node.json_data = node

    if node_parent_chain not in p4node.node_parents:
        p4node.node_parents += [node_parent_chain]

    if 'Node_Type' in node.keys():
        p4node.node_type = node['Node_Type']
        p4node.remove_attr('incomplete_json_data')

    if 'vec' in node.keys():
        no_key_elems = [elem for key, elem in elems]
        nodes[node_id].set_vec(no_key_elems)
    else:
        for key, subnode in elems:
            nodes[node_id].set_attr(key, subnode)

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
    """Returns either ERR_CODE_NO_PROGRAM (an int), or a P4Node object."""
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

    # --------------------------------------------------------------------------
    # Common

    hlir16.define_common_attrs([
        "all_nodes",
        "p4v",
        'paths_to',
        'by_type',
    ]),

    hlir16.all_nodes = nodes
    hlir16.p4v = p4_version

    for idx in hlir16.all_nodes:
        node = hlir16.all_nodes[idx]
        if type(node) is not P4Node:
            continue

        # Note: the external lambda makes sure the actual node is the operand,
        # not the last value that the "node" variable takes
        node.paths_to = (lambda n: lambda value, print_details=False, match='prefix':
            paths_to(n, value, print_details=print_details, match=match))(node),
        node.by_type = (lambda n: lambda typename:
            P4Node({}, [f for f in hlir16.declarations if f.node_type == typename or f.node_type == 'Type_' + typename]))(node),

    # --------------------------------------------------------------------------
    # Structs

    for struct in hlir16.declarations['Type_Struct']:
        hlir16.set_attr(struct.name, struct)

    # --------------------------------------------------------------------------
    # Headers and header types

    hlir16.header_types = hlir16.declarations['Type_Header']

    if hlir16.p4v == 14:
        hlir16.headers = hlir16.declarations.get("headers", "Type_Struct").fields #['StructField']
    elif hlir16.p4v == 16:
        hlir16.headers = hlir16.Parsed_packet.fields #['StructField']

    # --------------------------------------------------------------------------
    # Metadatas and metadata types

    if hlir16.p4v == 14:
        metadatas = hlir16.declarations.get('metadata', 'Type_Struct').fields

        stdmeta = hlir16.standard_metadata_t
        stds  = [( True, stdmeta, "standard_metadata", stdmeta, type_bit_width(hlir16, stdmeta))]
        metas = [( True, meta, meta.inst_name, meta, type_bit_width(hlir16, meta)) for meta in metadatas]
        hdrs  = [(False, hdr, hdr.name, hlir16.declarations.get(hdr.type.path.name, "Type_Header"), get_bit_width(hlir16, hdr)) for hdr in hlir16.headers]

        all_headers = stds + metas + hdrs
        hlir16.all_headers = [hdr_type for _, _, _, hdr_type, _ in all_headers]

        for is_meta, hdr, hdr_name, hdr_type, hdr_bits in all_headers:
            hdr_type.bit_width   = hdr_bits
            hdr_type.byte_width  = bits_to_bytes(hdr_bits)
            hdr_type.inst_name   = hdr_name
            hdr_type.is_metadata = is_meta
            if not is_meta:
                hdr.header_type = hdr_type

        for hdr in hlir16.all_headers:
            for fld in hdr.fields:
                # TODO this computation is probably unnecessary, remove if it is
                fld.type = get_type(hlir16, fld)

                fld.header = hdr
                fld.is_vw = (fld.type.node_type == 'Type_Varbits') # 'Type_Bits' vs. 'Type_Varbits'
    else:
        # TODO
        pass

    # --------------------------------------------------------------------------
    # Header fields

    for hdr in hlir16.all_headers:
        # TODO bit_offset, byte_offset, mask

        offset = 0
        for fld in hdr.fields:
            fld.offset = offset

            size = fld.type.get_attr('size')
            if size is not None:
                fld.size = size
            else:
                size = get_type(hlir16, fld).size / 8
            offset += size
            fld.is_vw = (fld.type.node_type == 'Type_Varbits') # 'Type_Bits' vs. 'Type_Varbits'

    for hdr in hlir16.all_headers:
        if hdr.is_metadata:
            hdr.id = re.sub(r'\[([0-9]+)\]', r'_\1', "header_instance_"+hdr.name)

    for hdr in hlir16.headers:
        # TODO bit_offset, byte_offset, mask
        hdr.header_type = hlir16.declarations.get(hdr.type.path.name, "Type_Header")

    # --------------------------------------------------------------------------
    # Controls and tables

    hlir16.control_types = hlir16.declarations['Type_Control']
    hlir16.controls = hlir16.declarations['P4Control']

    for c in hlir16.declarations['P4Control']:
        c.tables = c.controlLocals['P4Table']
        for t in c.tables:
            t.control = c
        c.actions = c.controlLocals['P4Action']

    hlir16.tables = [t for c in hlir16.controls for t in c.tables]

    for table in hlir16.tables:
        for prop in table.properties.properties:
            table.set_attr(prop.name, prop.value)
        table.remove_attr('properties')

    for c in hlir16.controls:
        for t in c.tables:
            table_actions = []
            for a in t.actions.actionList:
                a.action_object = c.controlLocals.get(a.expression.method.path.name, 'P4Action')
                table_actions.append(a)
            t.actions = table_actions

    # TODO this shall be calculated in the HAL
    def match_type(table):
        lpm = 0
        ternary = 0
        for k in table.key.keyElements:
            mt = k.matchType.path.name
            if mt == 'ternary':
                ternary = 1
            elif mt == 'lpm':
                lpm += 1
        if ternary or lpm > 1: return 'TERNARY'
        elif lpm:              return 'LPM'
        else:                  return 'EXACT'

    # some tables do not have a key (e.g. 'tbl_act*'), we do not want to deal with them for now
    hlir16.tables[:] = [table for table in hlir16.tables if hasattr(table, 'key')]

    for table in hlir16.tables:
        table.match_type = match_type(table)
        key_length = 0
        for k in table.key.keyElements:
            # supposing that k.expression is of form '<header_name>.<name>'
            if k.expression.expr.node_type == 'PathExpression':
                k.header_name = k.expression.expr.path.name
                k.field_name = k.expression.member
            # supposing that k.expression is of form 'hdr.<header_name>.<name>'
            elif k.expression.expr.node_type == 'Member':
                k.header_name = k.expression.expr.member
                k.field_name = k.expression.member
            k.match_type = k.matchType.path.name
            k.id = 'field_instance_' + k.header_name + '_' + k.field_name
            if hlir16.headers.get(k.header_name) is not None:
                k.header = hlir16.headers.get(k.header_name)
                k.header_type = k.header.header_type
            elif hlir16.metadatas.get(k.header_name) is not None:
                k.header = hlir16.metadatas.get(k.header_name)
                header_type_name = k.header.type.path.name
                k.header_type = hlir16.metadata_types.get(header_type_name)
            elif k.header_name == 'standard_metadata':
                # TODO create a header instance for standard_metadata
                #k.header = hlir16.declarations.get('metadata', 'Type_Struct').fields.get(k.header_name)
                header_type_name = 'standard_metadata_t'
                k.header_type = hlir16.metadata_types.get(header_type_name)
            k.width = k.header_type.fields.get(k.field_name).type.size
            key_length += k.width
        table.key_length_bits  = key_length
        table.key_length_bytes = bits_to_bytes(key_length)

    # --------------------------------------------------------------------------
    # References in expressions

    # Header references
    for idx in hlir16.all_nodes:
        node = hlir16.all_nodes[idx]
        if type(node) is not P4Node:
            continue
        if node.node_type == 'Member':
            if node.expr.node_type == 'PathExpression' and node.expr.path.name == 'hdr':
                header_name = node.member
                node.ref = hlir16.headers.get(header_name)

    # Field references
    for idx in hlir16.all_nodes:
        node = hlir16.all_nodes[idx]
        if type(node) is not P4Node:
            continue
        if node.node_type == 'Member':
            if node.expr.node_type == 'Member':
                if hasattr(node.expr, 'ref') and node.expr.ref.node_type == 'StructField':
                    field_name = node.member
                    node.ref = node.expr.ref.header_type.fields.get(field_name)

    # TODO remove
    if 'IPDB' in os.environ:
        import ipdb
        ipdb.set_trace()


def load_p4(filename, p4_version=None, p4c_path=None):
    """Returns either an error code (an int), or a P4Node object."""
    if p4c_path is None:
        p4c_path = os.environ['P4C']

    MOST_RECENT_P4_VERSION = 16
    p4_version = p4_version or MOST_RECENT_P4_VERSION

    if not filename.endswith(".json"):
        (errcode, json_filename) = create_p4_json_file(filename, p4_version, p4c_path)

        if errcode != 0:
            return errcode

    return load_p4_json_file(json_filename, p4_version or MOST_RECENT_P4_VERSION)
