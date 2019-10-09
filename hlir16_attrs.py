#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


from p4node import P4Node, get_fresh_node_id
import re

from utils_hlir16 import *


def print_path(full_path, value, root, print_details, matchtype, max_length=70):
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
                idx = current_node[node_type].vec.index(subnode)
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
    print " ", matchtype, full_path_txt


def paths_to(node, value, max_depth=20, path=[], root=None, max_length=70, print_details=False, match="prefix"):
    """Finds the paths under node through which the value is accessible.
    The matching is always textual, one of "full", "prefix" or "infix"."""
    if max_depth < 1:
        return

    root = root if root is not None else node

    valuetxt = str(value)
    nodetxt = str(node)
    if valuetxt in nodetxt:
        matchtype="∈"
        if nodetxt.startswith(valuetxt):
            matchtype="<"
        if nodetxt.endswith(valuetxt):
            matchtype=">"
        if nodetxt == valuetxt:
            matchtype="="

        print_path(path, value, root, print_details, matchtype)
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

    for attr in node.xdir(show_colours=False):
        paths_to(getattr(node, attr), value, max_depth - 1, path + [attr], root, max_length, print_details, match)


# TODO this shall be calculated in the HAL
def match_type(table):
    match_types = [k.matchType.ref.name for k in table.key.keyElements]

    if 'ternary' in match_types:
        return 'TERNARY'

    lpm_count = match_types.count('lpm')

    if lpm_count  > 1: return 'TERNARY'
    if lpm_count == 1: return 'LPM'
    if lpm_count == 0: return 'EXACT'


# TODO remove this; instead:
# TODO in set_additional_attrs, replace all type references with the referenced types
def resolve_typeref(hlir16, f):
    # resolving type reference
    if f.type.node_type == 'Type_Name':
        tref = f.type.type_ref
        return hlir16.objects.get(tref.name)
    else:
        return f

def resolve_type_name_node(hlir16, type_name_node, parent):
    if parent.node_type == 'P4Program':
        return hlir16.objects.get(type_name_node.path.name)
    elif parent.node_type == 'ConstructorCallExpression' and parent.constructedType == type_name_node:
        return parent.type
    elif parent.node_type == 'TypeNameExpression' and parent.typeName == type_name_node:
        return parent.type.type
    elif hasattr(parent, 'typeParameters'):
        type_param = parent.typeParameters.parameters.get(type_name_node.path.name)
        if type_param is not None:
            return type_param

    return resolve_type_name_node(hlir16, type_name_node, parent.node_parents[0][-1]);

def resolve_path_expression_node(hlir16, path_node, parent):
    resolve_lists = []
    if parent.node_type == 'P4Program':
        return hlir16.objects.get(path_node.path.name)
    elif parent.node_type == 'KeyElement' and parent.matchType == path_node:
        return [mk for mks in hlir16.objects.by_type('Declaration_MatchKind')
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

    return resolve_path_expression_node(hlir16, path_node, parent.node_parents[0][-1])


def resolve_header_ref(member_expr):
    if hasattr(member_expr, 'expression'):
        return member_expr.expression.type

    return member_expr.expr.ref.type.type_ref.fields.get(member_expr.member)


def attrs_type_boolean(hlir16):
    """Add the proper .size attribute to Type_Boolean"""

    for node in hlir16.all_nodes_by_type('Type_Boolean'):
        node.size = 1


def attrs_annotations(hlir16):
    """Annotations (appearing in source code)"""

    for node in hlir16.all_nodes_by_type('Annotations'):
        for annot in node.annotations:
            if annot.name in ["hidden", "name", ""]:
                continue
            hlir16.sc_annotations.append(annot)


def attrs_structs(hlir16):
    for struct in hlir16.objects['Type_Struct']:
        hlir16.set_attr(struct.name, struct)


def attrs_resolve_types(hlir16):
    """Resolve all Type_Name nodes to real type nodes"""

    for node in hlir16.all_nodes_by_type('Type_Name'):
        resolved_type = resolve_type_name_node(hlir16, node, node)
        assert resolved_type is not None # All Type_Name nodes must be resolved to a real type node
        node.type_ref = resolved_type


def attrs_resolve_pathexprs(hlir16):
    """Resolve all PathExpression nodes"""
    for node in hlir16.all_nodes_by_type('PathExpression'):
        resolved_path = resolve_path_expression_node(hlir16, node, node)
        assert resolved_path is not None # All PathExpression nodes must be resolved
        node.ref = resolved_path


def attrs_member_naming(hlir16):
    """Add naming information to nodes"""

    for enum in hlir16.objects.by_type('Type_Enum'):
        enum.c_name = 'enum_' + enum.name
        for member in enum.members:
            member.c_name = enum.c_name + '_' + member.name

    for error in hlir16.objects.by_type('Type_Error'):
        error.c_name = 'error_' + error.name
        for member in error.members:
            member.c_name = error.c_name + '_' + member.name


def gen_metadata_instance_node(hlir16, metadata_inst_name):
    metadata_type_name = metadata_inst_name + "_t"

    new_inst_node           = P4Node({})
    new_inst_node.node_type = 'header_instance'
    new_inst_node.name      = metadata_inst_name
    new_inst_node.header_ref = hlir16.objects.get(metadata_type_name, 'Type_Struct')
    new_inst_node.type            = P4Node({})
    new_inst_node.type.node_type  = 'Type_Name'
    new_inst_node.type.type_ref   = hlir16.objects.get(metadata_type_name, 'Type_Struct')
    new_inst_node.type.path            = P4Node({})
    new_inst_node.type.path.node_type  = 'StructField'
    new_inst_node.type.path.name       = metadata_inst_name

    return new_inst_node


def known_packages():
    return {'V1Switch', 'PSA_Switch'}


def set_p4_main(hlir16):
    for di in hlir16.objects['Declaration_Instance']:
        bt = di.type.baseType

        name = bt.type_ref.name if hasattr(bt, 'type_ref') else bt.path.name

        if name in known_packages():
            hlir16.p4_main = di
            return


def attrs_hdr_metadata_insts(hlir16):
    """Package and package instance"""

    pkgtype = hlir16.p4_main.type
    package_name = hlir16.p4_model

    hdr_insts = P4Node({}, pkgtype.arguments[0].type_ref.fields['StructField'])
    metadata_insts = P4Node({}, pkgtype.arguments[1].type_ref.fields['StructField'])

    if package_name == 'V1Switch': #v1model
        metadata_inst_names = ['standard_metadata']
    elif package_name == 'PSA_Switch':
        metadata_inst_names = [
            'psa_ingress_parser_input_metadata',
            'psa_egress_parser_input_metadata',
            'psa_ingress_input_metadata',
            'psa_ingress_output_metadata',
            'psa_egress_input_metadata',
            'psa_egress_deparser_input_metadata',
            'psa_egress_output_metadata',
        ]

    for mi_name in metadata_inst_names:
        metadata_insts.append(gen_metadata_instance_node(hlir16, mi_name))

    hlir16.hdr_insts = P4Node({}, hdr_insts)
    hlir16.metadata_insts = P4Node({}, metadata_insts)

    hlir16.header_instances = P4Node({}, hdr_insts + attrs_header_refs_in_parser_locals(hlir16) + metadata_insts)
    hlir16.header_instances_with_refs = P4Node({}, [hi for hi in hlir16.header_instances if hasattr(hi.type, 'type_ref')])


def attrs_header_refs_in_parser_locals(hlir16):
    """Temporary header references in parser locals"""

    def is_tmp_header_inst(local):
        return local.name.startswith('tmp_')

    return P4Node({}, [local for parser in hlir16.objects['P4Parser'] for local in parser.parserLocals if is_tmp_header_inst(local)])



def attrs_collect_header_types(hlir16):
    """Collecting header types"""

    package_name = hlir16.p4_model

    # TODO metadata can be bit<x> too, is not always a struct
    if package_name == 'V1Switch': #v1model
        hlir16.header_types = P4Node({'id' : get_fresh_node_id(), 'node_type' : 'header_type_list'},
                                     hlir16.objects['Type_Header'] + [h.type.type_ref for h in hlir16.metadata_insts if hasattr(h.type, "type_ref")])
    elif package_name == 'PSA_Switch':
        hlir16.header_types = P4Node({'id' : get_fresh_node_id(), 'node_type' : 'header_type_list'},
                                     [h for h in hlir16.objects['Type_Header'] if 'EMPTY' not in h.name] + [h.type.type_ref for h in hlir16.metadata_insts if hasattr(h.type, "type_ref")])

    for h in hlir16.header_types:
        h.valid_fields = P4Node({'node_type': 'custom'}, [f for f in h.fields if resolve_typeref(hlir16, f).node_type == 'StructField'])

    for h in hlir16.header_types:
        h.is_metadata = h.node_type != 'Type_Header'
        h.id = 'header_'+h.name
        offset = 0

        h.bit_width   = sum([resolve_typeref(hlir16, f).type.size for f in h.valid_fields])
        h.byte_width  = bits_to_bytes(h.bit_width)
        is_vw = False
        for f in h.valid_fields:
            f = resolve_typeref(hlir16, f)

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


def set_table_key_attrs(hlir16, table):
    for k in table.key.keyElements:
        k.match_type = k.matchType.ref.name

        expr = k.expression.get_attr('expr')
        if expr is None:
            continue

        # supposing that k.expression is of form '<header_name>.<name>'
        if expr.node_type == 'PathExpression':
            k.header_name = expr.ref.name
            k.field_name = k.expression.member
        # supposing that k.expression is of form 'hdr.<header_name>.<name>'
        elif expr.node_type == 'Member':
            k.header_name = expr.member
            k.field_name = k.expression.member
        k.match_type = k.matchType.ref.name
        k.id = 'field_instance_' + k.header_name + '_' + k.field_name

        k.header = hlir16.header_instances.get(k.header_name)

        if k.header is None:
            # TODO seems to happen for some PathExpressions
            continue

        size = k.get_attr('size')

        if size is None:
            kfld = resolve_typeref(hlir16, k.header.type.type_ref.fields.get(k.field_name))
            k.width = kfld.type.size
        else:
            k.width = size


def key_length(hlir16, k):
    expr = k.expression.get_attr('expr')
    if expr is None:
        return k.expression.type.size

    k.header = hlir16.header_instances.get(k.header_name)

    return k.width if k.header is not None else 0


def table_key_length(hlir16, table):
    return sum((key_length(hlir16, k) for k in table.key.keyElements))


def attrs_controls_tables(hlir16):
    hlir16.control_types = hlir16.objects['Type_Control']
    hlir16.controls = hlir16.objects['P4Control']

    for c in hlir16.objects['P4Control']:
        c.tables = P4Node({}, c.controlLocals['P4Table'])
        for t in c.tables:
            t.control = c
        c.actions = P4Node({}, c.controlLocals['P4Action'])

    main = hlir16.p4_main
    pipeline_elements = main.arguments

    hlir16.tables = P4Node({}, [table for ctrl in hlir16.controls for table in ctrl.controlLocals['P4Table']])

    for table in hlir16.tables:
        for prop in table.properties.properties:
            table.set_attr(prop.name, prop.value)
        table.remove_attr('properties')

    package_name = hlir16.p4_model

    for c in hlir16.controls:
        for t in c.tables:
            for a in t.actions.actionList:
                a.action_object = a.expression.method.ref
            t.actions = P4Node({}, t.actions.actionList)

    for table in hlir16.tables:
        if not hasattr(table, 'key'):
            continue

        table.match_type = match_type(table)

        set_table_key_attrs(hlir16, table)

    for table in hlir16.tables:
        table.key_length_bits  = table_key_length(hlir16, table) if hasattr(table, 'key') else 0
        table.key_length_bytes = bits_to_bytes(table.key_length_bits)


def attrs_extract_node(hlir16, node, method):
    arg0 = node.methodCall.arguments[0]

    node.call   = 'extract_header'
    node.is_tmp = arg0.node_type == 'PathExpression'
    node.header = arg0 if node.is_tmp else resolve_header_ref(arg0)
    node.is_vw  = len(method.type.parameters.parameters) == 2

    if node.is_vw:
        node.width = node.methodCall.arguments[1]


def attrs_extract_nodes(hlir16):
    for node, method in find_extract_nodes(hlir16):
        attrs_extract_node(hlir16, node, method)


def get_children(node, f = lambda n: True, visited=[]):
    if node in visited:
        return []

    children = []
    new_visited = visited + [node]
    if f(node):
        children.append(node)

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

    for attr in node.xdir(show_colours=False):
        children.extend(get_children(getattr(node, attr), f, new_visited))

    return children


def find_extract_nodes(hlir16):
    """Collect more information for packet_in method calls"""

    for block_node in hlir16.objects['P4Parser']:
        for block_param in block_node.type.applyParams.parameters:
            if block_param.type.type_ref.name != 'packet_in':
                continue

            # TODO step takes too long, as it iterates through all children
            for node in get_children(block_node, lambda n: type(n) is P4Node and n.node_type == 'MethodCallStatement'):
                method = node.methodCall.method
                if not hasattr(method, 'expr') or not hasattr(method.expr, 'ref'):
                    # TODO investigate this case further
                    # TODO happens in test-checksum
                    continue
                    
                if (method.node_type, method.expr.node_type, method.expr.ref.name) != ('Member', 'PathExpression', block_param.name):
                    continue

                if method.member == 'extract':
                    assert(len(method.type.parameters.parameters) in {1, 2})

                    yield (node, method)
                elif method.member in {'lookahead', 'advance', 'length'}:
                    raise NotImplementedError('packet_in.{} is not supported yet!'.format(method.member))
                else:
                    assert False #The only possible method calls on packet_in are extract, lookahead, advance and length


def attrs_header_refs_in_exprs(hlir16):
    """Header references in expressions"""

    for member in hlir16.all_nodes_by_type('Member'):
        if not hasattr(member.expr, "ref"):
            # TODO should these nodes also be considered here?
            continue

        def with_ref(node):
            return node.type_ref if hasattr(node, "type_ref") else node

        if not hasattr(member.expr.ref, "type"):
            # TODO should these nodes also be considered here?
            continue

        member_type = with_ref(member.expr.ref.type)

        if (member.expr.node_type, member.expr.ref.node_type, member_type.node_type) != ('PathExpression', 'Parameter', 'Type_Struct'):
            continue

        if member_type in hlir16.header_types:
            member.expr.header_ref = hlir16.header_instances.get(member.expr.ref.name)
        elif with_ref(member_type.fields.get(member.member).type) in hlir16.header_types:
            member.header_ref = resolve_header_ref(member)
        elif member_type.name == 'metadata':
            member.header_ref = member.expr.type
        else:
            raise NotImplementedError('Unable to resolve header reference: {}.{} ({})'.format(member.expr.type.name, member.member, member))


def attrs_field_refs_in_exprs(hlir16):
    """Field references in expressions"""

    for member in hlir16.all_nodes_by_type('Member'):
        if hasattr(member.expr, 'path') and member.expr.path.name == 'standard_metadata':
            member.field_ref = hlir16.objects.get('standard_metadata_t', 'Type_Struct').fields.get('egress_port', 'StructField')
            continue

        if not hasattr(member.expr, 'header_ref'):
            continue
        if member.expr.header_ref is None:
            continue

        ref = member.expr.header_ref.type.type_ref.fields.get(member.member, 'StructField')

        if ref is not None:
            member.field_ref = ref


def set_top_level_attrs(hlir16, nodes, p4_version):
    hlir16.all_nodes = P4Node({}, nodes)
    hlir16.p4v = p4_version
    hlir16.sc_annotations = P4Node({}, [])
    hlir16.all_nodes_by_type = (lambda t: P4Node({}, [n for idx in hlir16.all_nodes for n in [hlir16.all_nodes[idx]] if type(n) is P4Node and n.node_type == t]))


def set_common_attrs(hlir16, node):
    # Note: the external lambda makes sure the actual node is the operand,
    # not the last value that the "node" variable takes
    node.paths_to = (lambda n: lambda value, print_details=False, match='prefix': paths_to(n, value, print_details=print_details, match=match))(node)
    node.by_type  = (lambda n: lambda typename: P4Node({}, [f for f in hlir16.objects if f.node_type in [typename, 'Type_' + typename]]))(node)


def get_ctrlloc_smem_type(loc):
    type = loc.type.baseType if loc.type.node_type == 'Type_Specialized' else loc.type
    return type.path.name


def iter_smems(smem_type, tables):
    found_smems = set()

    for t in tables:
        for loc in t.control.controlLocals['Declaration_Instance']:
            found_smem_type = get_ctrlloc_smem_type(loc)

            if found_smem_type != smem_type:
                continue

            if loc.name in found_smems:
                continue

            found_smems.add(loc.name)

            yield t, loc


def attrs_stateful_memory(hlir16):
    # direct counters
    for table in hlir16.tables:
        table.meters    = P4Node({}, [m for t, m in iter_smems('direct_meter', [table])])
        table.counters  = P4Node({}, [c for t, c in iter_smems('direct_counter', [table])])

    # indirect counters
    hlir16.meters    = P4Node({}, list(iter_smems('meter', hlir16.tables)))
    hlir16.counters  = P4Node({}, list(iter_smems('counter', hlir16.tables)))
    hlir16.registers = P4Node({}, list(iter_smems('register', hlir16.tables)))

    def unique_list(l):
        return list(set(l))

    hlir16.all_meters   = P4Node({}, unique_list(hlir16.meters   + [(t, m) for t in hlir16.tables for m in t.meters]))
    hlir16.all_counters = P4Node({}, unique_list(hlir16.counters + [(t, c) for t in hlir16.tables for c in t.counters]))


def attrs_typedef(hlir16):
    for typedef in hlir16.all_nodes_by_type('Type_Typedef'):
        if hasattr(typedef, 'size'):
            continue

        if not hasattr(typedef.type, 'type_ref'):
            typedef.size = typedef.type.size
        elif hasattr(typedef.type.type_ref, 'size'):
            typedef.size = typedef.type.type_ref.size


def find_p4_nodes(hlir16, nodes):
    for idx in hlir16.all_nodes:
        node = hlir16.all_nodes[idx]
        if type(node) is not P4Node:
            continue

        yield node


def attrs_add_metadata_drop(hlir16):
    """P4 documentation suggests using magic numbers as egress ports:
    const PortId DROP_PORT = 0xF;
    As these constants do not show up in the JSON representation,
    they cannot be present in HLIR.
    This function adds the 'drop' field to standard_metadata_t as a temporary fix."""

    for mi in hlir16.metadata_insts:
        if not hasattr(mi.type, 'type_ref'):
            continue
        mit = mi.type.type_ref

        if 'drop' in [f.name for f in mit.fields]:
            return

        drop_field           = P4Node({})
        drop_field.node_type = 'StructField'
        drop_field.name      = 'drop'
        drop_field.is_vw     = False
        drop_field.preparsed = False
        drop_field.size      = 1
        drop_field.type      = P4Node({})
        drop_field.type.node_type = 'Type_Bits'
        drop_field.type.isSigned  = False
        drop_field.type.size      = 1

        mit.fields.append(drop_field)


def set_p4_model(hlir16):
    package_instance = hlir16.p4_main
    pkgtype = package_instance.type
    bt = pkgtype.baseType
    hlir16.p4_model = bt.type_ref.name if hasattr(bt, 'type_ref') else bt.path.name


def check_is_model_supported(hlir16):
    """Returns whether the loaded model is supported."""

    package_name = hlir16.p4_model
    if package_name not in known_packages():
        raise NotImplementedError('Unsupported model: {}'.format(package_name))


def set_additional_attrs(hlir16, nodes, p4_version, additional_attr_funs = [
        attrs_type_boolean,
        attrs_annotations,
        attrs_structs,
        attrs_resolve_types,
        attrs_resolve_pathexprs,
        attrs_member_naming,
        attrs_hdr_metadata_insts,
        attrs_add_metadata_drop,
        attrs_collect_header_types,
        attrs_controls_tables,
        attrs_extract_nodes,
        attrs_header_refs_in_exprs,
        attrs_field_refs_in_exprs,
        attrs_stateful_memory,
        attrs_typedef,
    ]):

    set_top_level_attrs(hlir16, nodes, p4_version)

    set_p4_main(hlir16)
    set_p4_model(hlir16)

    for node in find_p4_nodes(hlir16, nodes):
        set_common_attrs(hlir16, node)

    check_is_model_supported(hlir16)

    for attrfun in additional_attr_funs:
        attrfun(hlir16)

    return True
