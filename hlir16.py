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
from utils.misc import addError

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

def get_children(node, f = lambda n: True, visited=[]):
    if node in visited: return []

    children = []
    new_visited = visited + [node]
    if f(node): children.append(node)

    if type(node) is list:
        for _, subnode in enumerate(node):
            children.extend(get_children(subnode, f, new_visited))
    elif type(node) is dict:
        for key in node:
            children.extend(get_children(node[key], f, new_visited))

    if type(node) != P4Node:
        return children

    if node.is_vec():
        for idx, _ in enumerate(node.vec):
            children.extend(get_children(node[idx], f, new_visited))

    for attr in node.xdir():
        children.extend(get_children(getattr(node, attr), f, new_visited))

    return children

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
    hlir16.sc_annotations = []

    for idx in hlir16.all_nodes:
        node = hlir16.all_nodes[idx]
        if type(node) is not P4Node:
            continue

        # Note: the external lambda makes sure the actual node is the operand,
        # not the last value that the "node" variable takes
        node.set_attr('paths_to',
            (lambda n: lambda value, print_details=False, match='prefix': paths_to(n, value, print_details=print_details, match=match))(node),
        )
        node.set_attr('by_type',
            (lambda n: lambda typename: P4Node({}, [f for f in hlir16.declarations if f.node_type == typename or f.node_type == 'Type_' + typename]))(node),
        )
        
    # --------------------------------------------------------------------------
    # Annotations (appearing in source code)

    for idx in hlir16.all_nodes:
        node = hlir16.all_nodes[idx]
        if type(node) is not P4Node:
            continue
        if node.node_type == 'Annotations':
            for annot in node.annotations:
                if annot.name!="hidden" and annot.name!="name" and annot.name!="" :
                    hlir16.sc_annotations.append(annot)

    # --------------------------------------------------------------------------
    # Structs

    for struct in hlir16.declarations['Type_Struct']:
        hlir16.set_attr(struct.name, struct)

    # --------------------------------------------------------------------------
    # Resolve all Type_Name and Type_Typedef nodes to real type nodes

    def resolve_type_name_node(type_name_node, parent):
        if parent.node_type == 'P4Program':
            return hlir16.declarations.get(type_name_node.path.name)
        elif parent.node_type == 'ConstructorCallExpression' and parent.constructedType == type_name_node:
            return parent.type
        elif parent.node_type == 'TypeNameExpression' and parent.typeName == type_name_node:
            return parent.type.type
        elif hasattr(parent, 'typeParameters'):
            type_param = parent.typeParameters.parameters.get(type_name_node.path.name)
            if type_param is not None:
                return type_param

        return resolve_type_name_node(type_name_node, parent.node_parents[0][-1]);

    def resolve_type_typedef_node(node):
        return node.type if node.node_type == 'Type_Typedef' else node

    for node in filter(lambda n : type(n) is P4Node and n.node_type == 'Type_Name',
                       map(lambda idx : hlir16.all_nodes[idx], hlir16.all_nodes)):
        for parent in map(lambda p: p[-1], node.node_parents):
            type_updated = False
            resolved_type = resolve_type_name_node(node, parent)
            assert(resolved_type is not None) # All Type_Name nodes must be resolved to a real type node
            resolved_type = resolve_type_typedef_node(resolved_type)

            if parent.is_vec():
                for idx, child in enumerate(parent.vec):
                    if child == node:
                        parent.vec[idx] = resolved_type
                        type_updated = True
            else:
                for attr in {'type', 'typeName', 'baseType', 'constructedType', 'returnType'}:
                    if hasattr(parent, attr) and parent.get_attr(attr) == node:
                        parent.set_attr(attr, resolved_type)
                        type_updated = True
            assert(type_updated) # At least one child node must be updated

    # --------------------------------------------------------------------------
    # Resolve all PathExpression nodes

    def resolve_path_expression_node(path_node, parent):
        resolve_lists = []
        if parent.node_type == 'P4Program':
            return hlir16.declarations.get(path_node.path.name)
        elif parent.node_type == 'KeyElement' and parent.matchType == path_node:
            return [mk for mks in hlir16.declarations.by_type('Declaration_MatchKind')
                    for mk in mks.members if mk.name == path_node.path.name][0]
        elif parent.node_type == 'P4Parser':
            resolve_lists.extend([parent.type.applyParams.parameters, parent.parserLocals, parent.states])
        elif parent.node_type == 'P4Control':
            resolve_lists.extend([parent.type.applyParams.parameters, parent.controlLocals])
        elif parent.node_type == 'P4Action':
            resolve_lists.append(parent.parameters.parameters)
        elif parent.node_type == 'Type_Header':
            resolve_lists.append(parent.fields)

        for resolve_list in resolve_lists:
            tmp_resolved = resolve_list.get(path_node.path.name)
            if tmp_resolved is not None:
                return tmp_resolved

        return resolve_path_expression_node(path_node, parent.node_parents[0][-1])

    for node in filter(lambda n : type(n) is P4Node and n.node_type == 'PathExpression',
                       map(lambda idx : hlir16.all_nodes[idx], hlir16.all_nodes)):
        for parent in map(lambda p: p[-1], node.node_parents):
            resolved_path = resolve_path_expression_node(node, parent)
            assert(resolved_path is not None) # All PathExpression nodes must be resolved

            path_updated = False
            if parent.is_vec():
                for idx, child in enumerate(parent.vec):
                    if child == node:
                        parent.vec[idx] = resolved_path
                        path_updated = True
            else:
                for attr in parent.xdir():
                    if parent.get_attr(attr) == node:
                        parent.set_attr(attr, resolved_path)
                        path_updated = True
            assert(path_updated) # At least one child node must be updated

    # --------------------------------------------------------------------------
    # Package and package instance

    package_instance = hlir16.declarations.by_type('Declaration_Instance')[0] #TODO: what to do when there are more than one instances
    package_name = package_instance.type.baseType.name
    package_params = [hlir16.declarations.get(c.type.name) for c in package_instance.arguments]

    if package_name == 'V1Switch': #v1model
        # ----------------------------------------------------------------------
        # Collecting header instances

        #TODO: is there always a struct containing all headers?
        header_instances = package_instance.type.arguments[0].fields['StructField']
        metadata_instances = package_instance.type.arguments[1].fields['StructField']

        # ----------------------------------------------------------------------
        # Creating the standard metadata

        standard_metadata = P4Node({'node_type' : 'header_instance',
                                    'name' : 'standard_metadata',
                                    'type' : hlir16.declarations.get('standard_metadata_t')})
        metadata_instances.append(standard_metadata)
        hlir16.header_instances = P4Node({'node_type' : 'header_instance_list'}, header_instances + metadata_instances)
    else:
        assert(False) #An unsupported P4 architecture is used!

    # ----------------------------------------------------------------------
    # Collecting header types

    hlir16.header_types = P4Node({'node_type' : 'header_type_list'},
                                 hlir16.declarations['Type_Header'] + [h.type for h in metadata_instances])

    for h in hlir16.header_types:
        h.is_metadata = h.node_type != 'Type_Header'
        h.id = 'header_'+h.name
        offset = 0
        h.bit_width   = sum([f.type.size for f in h.fields])
        h.byte_width  = bits_to_bytes(h.bit_width)
        is_vw = False
        for f in h.fields:
            f.id = 'field_' + h.name + '_' + f.name # TODO
            # TODO bit_offset, byte_offset, mask
            f.offset = offset
            f.size = f.type.size
            offset += f.size
            f.is_vw = (f.type.node_type == 'Type_Varbits') # 'Type_Bits' vs. 'Type_Varbits'
            is_vw |= f.is_vw
            f.preparsed = False #f.name == 'ttl'
        h.is_vw = is_vw

    for hdr in hlir16.header_instances:
        hdr.id = re.sub(r'\[([0-9]+)\]', r'_\1', "header_instance_"+hdr.name)

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
                a.action_object = a.expression.method
                table_actions.append(a)
            t.actions = table_actions

    # TODO this shall be calculated in the HAL
    def match_type(table):
        lpm = 0
        ternary = 0
        for k in table.key.keyElements:
            mt = k.matchType.name
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
            expr = k.expression.get_attr('expr')
            if expr is None:
                key_length += k.expression.type.size
                continue

            # supposing that k.expression is of form '<header_name>.<name>'
            if expr.node_type == 'Parameter':
                k.header_name = expr.name
                k.field_name = k.expression.member
            # supposing that k.expression is of form 'hdr.<header_name>.<name>'
            elif expr.node_type == 'Member':
                k.header_name = expr.member
                k.field_name = k.expression.member
            k.match_type = k.matchType.name
            k.id = 'field_instance_' + k.header_name + '_' + k.field_name

            k.header = hlir16.header_instances.get(k.header_name)

            if k.header is None:
                # TODO seems to happen for some PathExpressions
                pass
            else:
                size = k.get_attr('size')

                if size is None:
                    kfld = k.header.type.fields.get(k.field_name)
                    k.width = kfld.type.size
                else:
                    k.width = size
                key_length += k.width
        table.key_length_bits  = key_length
        table.key_length_bytes = bits_to_bytes(key_length)

    # --------------------------------------------------------------------------
    # Collect more information for packet_in method calls

    def resolve_header_ref(parser_or_control, member_expr):
        return member_expr.expr.type.fields.get(member_expr.member)

    for block_node in hlir16.declarations['P4Parser']:
        for block_param in block_node.type.applyParams.parameters:
            if block_param.type.name == 'packet_in':
                for node in get_children(block_node, lambda n: type(n) is P4Node and n.node_type == 'MethodCallStatement'):
                    method = node.methodCall.method
                    if method.node_type == 'Member' and method.expr.node_type == 'Parameter' \
                       and method.expr.name == block_param.name:
                        if method.member == 'extract':
                            assert(len(method.type.parameters.parameters) in {1, 2})
                            arg0 = node.methodCall.arguments[0]
                            node.call = 'extract_header'
                            node.is_tmp = arg0.node_type == 'Declaration_Variable'
                            if node.is_tmp:
                                node.header = arg0
                            else:
                                node.header = resolve_header_ref(block_node, arg0)
                            node.is_vw = len(method.type.parameters.parameters) == 2
                            if node.is_vw:
                                node.width = node.methodCall.arguments[1]
                        elif method.member in {'lookahead', 'advance', 'length'}:
                            addError('generating hlir16', 'packet_in.{} is not supported yet!'.format(method.member))
                        else:
                            assert(False) #The only possible method calls on packet_in are extract, lookahead, advance and length

    # --------------------------------------------------------------------------
    # Header references in expressions

    if package_name == 'V1Switch': #v1model
        architecture_headers_mapping = [1,0,0,0,0,1]
    else:
        architecture_headers_mapping = []
        addError('generating hlir16', 'Package {} is not supported!'.format(package_name))
    for headers_idx, block_node in zip(architecture_headers_mapping, package_params):
        block_param_name = block_node.type.applyParams.parameters[headers_idx].name
        for node in get_children(block_node, lambda n: type(n) is P4Node and n.node_type == 'Member'
                                 and n.expr.node_type == 'Parameter' and n.expr.name == block_param_name):
            node.header_ref = resolve_header_ref(block_node, node)

    # --------------------------------------------------------------------------
    # Field references in expressions

    for block_node in package_params:
        for node in get_children(block_node, lambda n: type(n) is P4Node and n.node_type == 'Member'
                                 and n.expr.node_type == 'Member' and hasattr(n.expr, 'header_ref')
                                 and n.member in map(lambda m: m.name, n.expr.header_ref.type.fields)):
            node.field_ref = node.expr.header_ref.type.fields.get(node.member)

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
