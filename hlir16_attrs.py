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
from utils.misc import addWarning, addError


def print_path(full_path, value, root, print_details, matchtype, nodetxt, max_length=70):
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
    print nodetxt, " ", matchtype, full_path_txt if full_path_txt.strip() != "" else "(the node itself)"


def paths_to(node, value, max_depth=20, path=[], root=None, max_length=70, print_details=False):
    """Finds the paths under node through which the value is accessible."""
    if max_depth < 1:
        return

    root = root if root is not None else node

    valuetxt = str(value)

    if type(node) is P4Node:
        if hasattr(node, 'name'):
            nodetxt = node.name
        else:
            nodetxt = node.str(details=False)
    else:
        nodetxt = str(node)

    if nodetxt is not None and valuetxt in nodetxt:
        matchtype="∊"
        if nodetxt.startswith(valuetxt):
            matchtype="<"
        if nodetxt.endswith(valuetxt):
            matchtype=">"
        if nodetxt == valuetxt:
            matchtype="="

        print_path(path, value, root, print_details, matchtype, nodetxt)
        return

    if type(node) is list:
        for idx, subnode in enumerate(node):
            paths_to(subnode, value, max_depth - 1, path + [idx], root, max_length, print_details)
        return

    if type(node) is dict:
        for key in node:
            paths_to(node[key], value, max_depth - 1, path + [key], root, max_length, print_details)
        return

    if type(node) is not P4Node:
        return

    if node.is_vec():
        if type(node.vec) is dict:
            for key in sorted(node.vec.keys()):
                paths_to(node.vec[key], value, max_depth - 1, path + [key], root, max_length, print_details)
        else:
            for idx, elem in enumerate(node.vec):
                paths_to(node[idx], value, max_depth - 1, path + [idx], root, max_length, print_details)
        return

    for attr in node.xdir(show_colours=False):
        paths_to(getattr(node, attr), value, max_depth - 1, path + [attr], root, max_length, print_details)


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
    if hasattr(f, 'header_ref'):
        return f.header_ref

    if f.type.node_type == 'Type_Name':
        tref = f.type._type_ref
        return hlir16.objects.get(tref.name)

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


def set_annotations(node, annots):
    node.annotations = P4Node({})
    node.annotations.node_type = 'Annotations'
    node.annotations.annotations = P4Node({}, annots)


def untypedef(f):
    while f.node_type == "Type_Typedef":
        f = f.type.type_ref
    return f


def metadata_type_name_to_inst_name(mt_name):
    if mt_name == 'metadata':
        return 'meta'
    return re.sub(r'_t$', '', mt_name)

def gen_metadata_instance_node(hlir16, metadata_type):
    new_inst_node           = P4Node({})
    new_inst_node.node_type = 'StructField'
    new_inst_node.name      = metadata_type_name_to_inst_name(metadata_type.name)
    new_inst_node.preparsed = True
    new_inst_node.type_ref  = metadata_type
    set_annotations(new_inst_node, [])
    new_inst_node.type = P4Node({})
    new_inst_node.type.node_type = 'Type_Name'
    new_inst_node.type.path = P4Node({})
    new_inst_node.type.path.name = metadata_type.name
    new_inst_node.type.path.absolute = True
    new_inst_node.type.type_ref = metadata_type

    new_inst_node.type.type_ref.fields = P4Node({}, [untypedef(f) for f in new_inst_node.type.type_ref.fields])

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


def attrs_add_standard_metadata_t(hlir16):
    """Adds standard metadata if it does not exist."""
    stdmt = hlir16.objects.get('standard_metadata_t', 'Type_Struct')
    if not stdmt:
        stdmt           = P4Node({})
        stdmt.node_type = 'Type_Struct'
        stdmt.name      = "standard_metadata_t"
        stdmt.fields    = P4Node({}, [])

        hlir16.objects.append(stdmt)


def attrs_hdr_metadata_insts(hlir16):
    """Package and package instance"""

    pkgtype = hlir16.p4_main.type
    package_name = hlir16.p4_model

    hdr_insts = P4Node({}, pkgtype.arguments[0].type_ref.fields['StructField'])

    # TODO detect these programatically: these are structs that describe parameters of parsers/controls
    known_not_metadata_structs = [
        'headers',
        'mac_learn_digest_t',
        'mac_learn_digest',
        'parsed_packet',
    ]

    metadata_types = [mt for mt in hlir16.objects['Type_Struct'] if mt.name not in known_not_metadata_structs]

    metadata_insts = [gen_metadata_instance_node(hlir16, mt) for mt in metadata_types]

    hlir16.metadata_insts = P4Node({}, metadata_insts)

    hlir16.header_instances = P4Node({}, hdr_insts + attrs_header_refs_in_parser_locals(hlir16) + metadata_insts)
    hlir16.header_instances_with_refs = P4Node({}, [hi for hi in hlir16.header_instances if hasattr(hi.type, 'type_ref')])


def attrs_header_refs_in_parser_locals(hlir16):
    """Temporary header references in parser locals"""

    def is_tmp_header_inst(local):
        return local.name.startswith('tmp_')

    return P4Node({}, [local for parser in hlir16.objects['P4Parser'] for local in parser.parserLocals if is_tmp_header_inst(local)])


def dlog(num, base=2):
    """Returns the discrete logarithm of num.
    For the standard base 2, this is the number of bits required to store the range 0..num."""
    return [n for n in range(32) if num < base**n][0]


def attrs_add_enum_sizes(hlir16):
    """Types that have members do not have a proper size (bit width) as we get it.
    We need to compute them by hand."""
    enum_types = ['Type_Error', 'Type_Enum']

    for h in hlir16.header_types:
        for f in h.fields:
            tref = resolve_typeref(hlir16, f)._type._type_ref
            if tref.node_type not in enum_types:
                continue

            tref.size = dlog(len(tref.members))
            tref.type = tref
            # TODO is this not needed?
            tref.preparsed = True


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


def attrs_header_types_add_attrs(hlir16):
    """Collecting header types, part 2"""

    for hdrt in hlir16.header_types:
        hdrt.is_metadata = hdrt.node_type != 'Type_Header'
        hdrt.id = 'header_'+hdrt.name
        offset = 0

        hdrt.bit_width   = sum([resolve_typeref(hlir16, f).type._type_ref._type.size for f in hdrt.fields])
        hdrt.byte_width  = bits_to_bytes(hdrt.bit_width)
        is_vw = False
        for f in hdrt.fields:
            tref = resolve_typeref(hlir16, f)

            f.id = 'field_{}_{}'.format(hdrt.name, tref.name)
            # TODO bit_offset, byte_offset, mask
            f.offset = offset
            f.size = tref.type._type_ref._type.size
            f.is_vw = (tref.type.node_type == 'Type_Varbits') # 'Type_Bits' vs. 'Type_Varbits'
            f.preparsed = False #f.name == 'ttl'

            offset += f.size
            is_vw |= f.is_vw
        hdrt.is_vw = is_vw

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


def get_meta_instance(hlir16, metaname):
    # Note: here we suppose that the field names look like this: _<metainst type><possible generated metainst index>_<field name><generated metafield index>
    maybe_meta = [(mi, fld) for mi in hlir16.metadata_insts for fld in mi.type.type_ref.fields if re.match("^_{}[0-9]*_{}[0-9]+$".format(mi.name, fld.name), metaname)]
    if len(maybe_meta) == 0:
        addError("finding metadata field", "Could not find metadata field {}".format(metaname))
    if len(maybe_meta) > 1:
        addError("finding metadata field", "Metadata field {} is ambiguous, {} candidates are: {}".format(metaname, len(maybe_meta), ", ".join(["({};{})".format(mi.name, fld.name) for mi, fld in maybe_meta])))
    return maybe_meta[0]


def key_length(hlir16, keyelement):
    expr = keyelement.expression.get_attr('expr')
    if expr is None:
        return keyelement.expression.type.size

    if expr.type.name == 'metadata':
        meta_inst, _ = get_meta_instance(hlir16, keyelement.field_name)

        keyelement.header = meta_inst

        # TODO is there a better place to set .width for a metadata?
        bit_width = meta_inst.type.type_ref.bit_width

        keyelement.width = bit_width
        keyelement.bit_width = bit_width
        keyelement.byte_width = (bit_width+7)/8

        return bit_width

    keyelement.header = hlir16.header_instances.get(keyelement.header_name)

    return keyelement.width if keyelement.header is not None else 0


def table_key_length(hlir16, table):
    return sum((key_length(hlir16, keyelement) for keyelement in table.key.keyElements))


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
            for node in get_children(block_node, lambda n: type(n) is P4Node and hasattr(n, 'node_type') and n.node_type == 'MethodCallStatement'):
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
        elif member.expr.path.name == 'standard_metadata':
            member.header_ref = hlir16.metadata_insts.get('standard_metadata').type
        elif member.type.node_type == 'Type_Stack':
            raise NotImplementedError('Header stacks are currently not supported')
        else:
            raise NotImplementedError('Unable to resolve header reference: {}.{} ({})'.format(member.expr.type.name, member.member, member))


def attrs_add_metadata_refs(hlir16):
    for expr in hlir16.all_nodes_by_type('PathExpression'):
        if expr.path.name == 'standard_metadata':
            expr.header_ref = hlir16.metadata_insts.get('standard_metadata').type

    for expr in hlir16.all_nodes_by_type('Member'):
        if expr('header_ref.name') == 'metadata':
            meta_inst, fld = get_meta_instance(hlir16, expr.member)
            expr.header_ref = meta_inst
            expr.field_name = fld.name

    for ke in hlir16.all_nodes_by_type('KeyElement'):
        if ke('header_name') == 'meta':
            meta_inst, fld = get_meta_instance(hlir16, ke.field_name)
            ke.header_ref = meta_inst
            ke.field_name = fld.name


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


def set_top_level_attrs(hlir16, p4_version):
    hlir16.p4v = p4_version
    hlir16.sc_annotations = P4Node({}, [])
    hlir16.all_nodes_by_type = (lambda t: P4Node({}, [n for idx in hlir16.all_nodes for n in [hlir16.all_nodes[idx]] if type(n) is P4Node and n.node_type == t]))


def set_common_attrs(hlir16, node):
    # Note: the external lambda makes sure the actual node is the operand,
    # not the last value that the "node" variable takes
    node.paths_to = (lambda n: lambda value, print_details=False: paths_to(n, value, print_details=print_details))(node)
    node.by_type  = (lambda n: lambda typename: P4Node({}, [f for f in hlir16.objects if f.node_type in [typename, 'Type_' + typename]]))(node)


def unique_list(l):
    return list(set(l))


def get_ctrlloc_smem_type(loc):
    type = loc.type.baseType if loc.type.node_type == 'Type_Specialized' else loc.type
    return type.path.name


def get_smems(smem_type, tables):
    """Gets counters and meters for tables."""
    return unique_list([(t, loc)
        for t in tables
        for loc in t.control.controlLocals['Declaration_Instance']
        if get_ctrlloc_smem_type(loc) == smem_type])


def get_registers(hlir16):
    return [r for r in hlir16.objects['Declaration_Instance'] if r.type.baseType.path.name == 'register']


def attrs_stateful_memory(hlir16):
    # direct counters
    for table in hlir16.tables:
        table.meters    = P4Node({}, [m for t, m in get_smems('direct_meter', [table])])
        table.counters  = P4Node({}, [c for t, c in get_smems('direct_counter', [table])])

    # indirect counters
    hlir16.meters    = P4Node({}, get_smems('meter', hlir16.tables))
    hlir16.counters  = P4Node({}, get_smems('counter', hlir16.tables))
    hlir16.registers = P4Node({}, get_registers(hlir16))

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


def find_p4_nodes(hlir16):
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
    This function adds the 'drop' field to the standard_metadata header as a temporary fix."""

    mi = hlir16.metadata_insts.get('standard_metadata', 'StructField')
    mit = mi.type.type_ref

    if 'drop' in [f.name for f in mit.fields]:
        return

    drop_field           = P4Node({})
    drop_field.node_type = 'StructField'
    drop_field.name      = 'drop'
    set_annotations(drop_field, [])
    # drop_field.is_vw     = False
    # drop_field.preparsed = False
    # drop_field.size      = 1
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


def default_attr_funs():
    return [
        attrs_type_boolean,
        attrs_annotations,
        attrs_structs,
        attrs_resolve_types,
        attrs_resolve_pathexprs,
        attrs_member_naming,
        attrs_add_standard_metadata_t,
        attrs_hdr_metadata_insts,
        attrs_add_metadata_drop,
        attrs_collect_header_types,
        attrs_add_enum_sizes,
        attrs_header_types_add_attrs,
        attrs_controls_tables,
        attrs_extract_nodes,
        attrs_header_refs_in_exprs,
        attrs_field_refs_in_exprs,
        attrs_stateful_memory,
        attrs_typedef,
        attrs_add_metadata_refs,
    ]

def set_additional_attrs(hlir16, p4_version, additional_attr_funs = None):
    if additional_attr_funs is None:
        additional_attr_funs = default_attr_funs()

    set_top_level_attrs(hlir16, p4_version)

    set_p4_main(hlir16)
    set_p4_model(hlir16)

    check_is_model_supported(hlir16)

    for node in find_p4_nodes(hlir16):
        set_common_attrs(hlir16, node)

    for attrfun in additional_attr_funs:
        attrfun(hlir16)

    return hlir16
