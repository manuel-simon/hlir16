#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node, get_fresh_node_id
from hlir16.hlir_utils import make_node_group

import hlir16.hlirx_annots
import hlir16.hlirx_regroup

from compiler_log_warnings_errors import addWarning, addError
from compiler_common import unique_everseen, dlog

import re
from collections import Counter


simple_binary_ops = {
    #Binary arithmetic operators
    'Div':'/', 'Mod':'%',
    #Binary comparison operators
    'Grt':'>', 'Geq':'>=', 'Lss':'<', 'Leq':'<=',
    #Bitwise operators
    'BAnd':'&', 'BOr':'|', 'BXor':'^',
    #Boolean operators
    'LAnd':'&&', 'LOr':'||',
    #Equality operators
    'Equ':'==', 'Neq':'!='
}

# TODO currently, AddSat and SubSat are handled exactly as Add and Sub
complex_binary_ops = {'AddSat':'+', 'SubSat':'-', 'Add':'+', 'Sub':'-', 'Mul':'*', 'Shl':'<<', 'Shr':'>>'}


def attrs_resolve_members(hlir):
    for m in hlir.groups.member_exprs.bits.filter('expr.path.name', hlir.news.user_meta_var):
        m.expr.hdr_ref = hlir.allmetas

    for can in hlir.groups.member_exprs.specialized_canonical:
        name = can.expr.path.name
        can.expr.decl_ref = hlir.decl_instances.get(name)
        if can.expr.decl_ref is None:
            if (found := hlir.controls.flatmap('controlLocals').filter('node_type', 'Declaration_Instance').filter('name', name)):
                can.expr.decl_ref = found[0]

    for me in hlir.groups.member_exprs.tables:
        me.table_ref = me.parents.filter('node_type', 'P4Control').flatmap('controlLocals').get(me.expr.path.name)

    for me in hlir.groups.member_exprs.tables:
        me.table_ref = me.parents.filter('node_type', 'P4Control').flatmap('controlLocals').get(me.expr.path.name)


def resolve_header_ref(member_expr):
    if 'expression' in member_expr:
        return member_expr.expression.type

    return member_expr.expr.hdr_ref.urtype.fields.get(member_expr.member)


def attrs_type_boolean(hlir):
    """Add the proper .size attribute to Type_Boolean"""

    for node in hlir.all_nodes.by_type('Type_Boolean'):
        node.size = 1


def attrs_annotations(hlir):
    """Annotations (appearing in source code)"""

    hlir.sc_annotations = P4Node([])

    for node in hlir.all_nodes.by_type('Annotations'):
        for annot in node.annotations:
            if annot.name in ["hidden", "name", ""]:
                continue
            hlir.sc_annotations.append(annot)


def resolve_type_var(hlir, type_var):
    typeargs = type_var.parents.filter('node_type', ('Method', 'Type_Extern', 'Type_Parser')).filter(lambda n: 'typeargs' in n and type_var.name in n.typeargs).map('typeargs')
    return typeargs[0][type_var.name] if len(typeargs) > 0 else None



def set_typeargs(node: P4Node):
    if (method := node).node_type == 'Method':
        type_names = method.type.typeParameters.parameters
        values = method.type.parameters.parameters
    elif (parser := node).node_type == 'Type_Parser':
        typepars = parser.typeParameters.parameters
        apppars = parser.applyParams.parameters
        named_apppars = apppars.filter(lambda n: n.urtype.node_type == 'Type_Name' and n.urtype.path.name in typepars.map('name'))

        type_names = P4Node(sorted(typepars, key=lambda n: n.name))
        values = P4Node(sorted(named_apppars, key=lambda n: n.type.path.name))
    elif (extern := node).node_type == 'Type_Extern':
        if 'parameters' not in extern:
            extern.typeargs = {}
            return
        type_names = extern.typeParameters.parameters
        values = extern.parameters.parameters

    typeargs = dict(zip(type_names.map('name'), values))

    if 'typeargs' in method:
        if node.typeargs != typeargs:
            addError('getting type arguments', f'Found differing sets of type arguments for {node.name}')
        return

    node.typeargs = typeargs


def attrs_typeargs(hlir: P4Node):
    """Resolve all Type_Name nodes to real type nodes"""

    for extern in hlir.all_nodes.by_type('Type_Extern'):
        for method in extern.methods:
            method.env_node = extern

    for extern in hlir.all_nodes.by_type('Type_Extern'):
        set_typeargs(extern)
        for method in extern.map('methods'):
            set_typeargs(method)

    for parser in hlir.all_nodes.by_type('Type_Parser'):
        set_typeargs(parser)


def resolve_type_name(hlir, typename_node):
    if (found := hlir.news.data.get(typename_node.path.name)):
        return found

    retval = resolve_type_name2(hlir, typename_node)
    if retval is None:
        return None

    if retval.node_type == 'Type_Typedef':
        return retval

    return retval

def resolve_metadata_hdr(hlir, typename_node, fld):
    results = hlir.news.meta.flatmap('fields').filter('name', fld.name)
    if len(results) == 1:
        return results[0]

    results = results.filterfalse('type.path.absolute')
    typenames = unique_everseen(results.map('urtype.name'))

    if len(typenames) > 1:
        hdrname = typename_node.parents.filter(lambda n: n.node_type == 'Type_Struct')[0].name
        typenames = ', '.join(typenames)
        assert False, f'Metadata field {hdrname}.{fld.name} has conflicting types ({typenames})'
    return results[0]


def resolve_type_name2(hlir, typename_node):
    if typename_node.path.absolute:
        if (fld := typename_node.parent()).node_type == 'StructField':
            if fld.name == 'parser_error':
                return hlir.errors[0]
            else:
                return resolve_metadata_hdr(hlir, typename_node, fld)

    name = typename_node.path.name
    parents = typename_node.parents

    if (found := parents.filter('node_type', 'ConstructorCallExpression').filter(lambda n: n.constructedType == typename_node)):
        return found[0].type

    if (found := parents.filter('node_type', 'TypeNameExpression').filter(lambda n: n.typeName == typename_node)):
        return found[0].type.type

    if (found := parents.filter(lambda n: 'typeParameters' in n)) and len(found) > 0:
        if (found := found.flatmap('typeParameters.parameters').get(name)):
            return found

    # TODO maybe this is not even needed here
    if (found := hlir.errors.get(name)) is not None:
        return found

    resolves = [retval for grp in hlir.object_groups if (retval := grp.get(name))]
    if len(resolves) > 1:
        return None
    if len(resolves) == 0:
        return None

    return resolves[0]


# TODO remove this function?
def check_resolved(node):
    if 'name' in node:
        addWarning('resolving type', f'Type name {node.name} could not be resolved')
    else:
        addWarning('resolving type', f'Type {node} could not be resolved')


def resolve_type(hlir, node):
    """The node will get a .type_ref attribute if the reference can be resolved.
    Note that in some cases, the reference won't be resolvable,
    such as in the case of the type variable T for packet_in."""
    resolved_type = resolve_type_name(hlir, node)
    assert resolved_type != node

    if resolved_type is None:
        check_resolved(node)
        return

    if resolved_type.node_type == 'Type_Var':
        resolved_type = resolve_type_var(hlir, resolved_type)
        if resolved_type is None:
            # here, we have to suppose that the type name is unused
            # such as in T lookahead<T>() if the function is not called
            return

    node.type_ref = resolved_type

def attrs_resolve_types(hlir):
    """Resolve all Type_Name nodes to real type nodes"""

    for node in hlir.all_nodes.by_type('Type_Name'):
        resolve_type(hlir, node)

    for stmt in hlir.all_nodes.by_type('BlockStatement'):
        if found := stmt.parents.filter('node_type', 'P4Control'):
            stmt.enclosing_control = found[0]

    for node in hlir.all_nodes.by_type('Parameter').filter('type.node_type', 'Type_Var'):
        if (ref := resolve_type_var(hlir, node)):
            node.type.type_ref = ref

    for spcan in hlir.groups.pathexprs.specialized_canonical:
        for par, arg in zip(spcan.urtype.typeParameters.parameters, spcan.type.arguments):
            par.type_ref = arg


def attrs_resolve_pathexprs(hlir):
    """Resolve all PathExpression nodes"""

    for pe in hlir.groups.pathexprs.action:
        pe.action_ref = hlir.map('controls').flatmap('controlLocals').get(pe.path.name)

    for hexpr in hlir.groups.pathexprs.header + hlir.groups.pathexprs.struct + hlir.groups.member_exprs.headers + hlir.groups.member_exprs.structs:
        tname = hexpr.urtype.name
        name = hexpr._expr.path.name

        if hexpr.type.name in hlir.news.meta_types:
            hexpr.hdr_ref = hlir.allmetas
        elif (found := hlir.news.data.get(tname)):
            hexpr.hdr_ref = found
        elif (found := hlir.news.meta.get(tname)):
            hexpr.hdr_ref = hlir.allmetas
        elif (found := hexpr.parents.filter('node_type', 'P4Parser').flatmap('parserLocals').get(name)):
            hexpr.hdr_ref = found
        elif (found := hexpr.parents.filter('node_type', 'P4Control').flatmap('controlLocals').get(name)):
            hexpr.hdr_ref = found

    for pe in hlir.groups.pathexprs.table:
        pe.table_ref = hlir.map('controls').flatmap('controlLocals').get(pe.path.name)

    for mcexpr in hlir.groups.pathexprs.under_mcall:
        mname = mcexpr.path.name

        if (found := hlir.methods.get(mname)):
            mcexpr.action_ref = found
        else:
            mcexpr.action_ref = hlir.controls.flatmap('controlLocals').get(mname)

        mct = mcexpr.urtype
        if mct.node_type == 'Type_Unknown':
            continue

        partype_names = mct.typeParameters.parameters.map('name')
        for t in mct.typeParameters.parameters:
            params = mct.parameters.parameters
            args = mcexpr.parent().arguments
            parargs = {par.type.name: arg.expression for par, arg in zip(params, args) if par.type.node_type == 'Type_Var' if par.type.name in partype_names}
            t.type_ref = parargs[t.name].type

    for pe in hlir.groups.pathexprs.bits + hlir.groups.pathexprs.varbits:
        clocs = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('controlLocals')
        pe.decl_ref = clocs.get(pe.path.name)
        if pe.decl_ref is None:
            if len(pars := clocs.flatmap('parameters.parameters')) > 0:
                parname, parsize = unique_everseen(((par.name, par.urtype.size) for par in pars))[0]
                pe.decl_ref = pars.filter(lambda par: (par.name, par.urtype.size) == (parname, parsize))[0]

    for pe in hlir.groups.pathexprs.extern_under_member:
        clocs = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('controlLocals')
        pe.decl_ref = clocs.get(pe.path.name)
        if pe.decl_ref is None:
            pe.decl_ref = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('type.applyParams.parameters').get(pe.path.name)

    for pe in hlir.groups.pathexprs.under_assign:
        clocs = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('controlLocals')
        pe.decl_ref = clocs.get(pe.path.name)
        if pe.decl_ref is None:
            if len(pars := clocs.flatmap('parameters.parameters')) > 0:
                parname, parsize = unique_everseen(((par.name, par.urtype.size) for par in pars))[0]
                pe.decl_ref = pars.filter(lambda par: (par.name, par.urtype.size) == (parname, parsize))[0]

    for pe in hlir.groups.pathexprs.under_unknown:
        pe.table_ref = pe.parents.filter('node_type', 'P4Control').flatmap('controlLocals').get(pe.path.name)


def attrs_member_naming(hlir):
    """Add naming information to nodes"""

    for enum in hlir.enums:
        enum.c_name = f'enum_{enum.name}'
        for member in enum.members:
            member.c_name = f'{enum.c_name}_{member.name}'

    for error in hlir.errors:
        error.c_name = f'error_{error.name}'
        for member in error.members:
            member.c_name = f'{error.c_name}_{member.name}'


# These have to be specified here, as the model description file gives ZERO HINTS about them
model_specific_infos = {
    "V1Switch": {
        "user_meta_var": "meta",
        "meta_types": [
            "standard_metadata_t",
        ],
    },
    "PSA_Switch": {
        "user_meta_var": "user_meta",
        "meta_types": [
            "psa_ingress_parser_input_metadata_t",
            "psa_egress_parser_input_metadata_t",
            "psa_ingress_input_metadata_t",
            "psa_ingress_output_metadata_t",
            "psa_egress_input_metadata_t",
            "psa_egress_deparser_input_metadata_t",
            "psa_egress_output_metadata_t",
        ],
    },
}


def attrs_top_level(hlir, p4_filename, p4_version):
    dis = hlir.decl_instances

    hlir.news = P4Node({'node_type': 'SystemInfo'})
    hlir.news.p4file = p4_filename
    hlir.news.p4v = p4_version
    hlir.news.main = dis.get(lambda main: main.arguments.map('expression')['PathExpression'].filter(lambda arg: dis.get(arg.path.name) is not None))
    if hlir.news.main is None:
        hlir.news.main = dis.get(lambda main: len(main.arguments.map('expression')['ConstructorCallExpression']) > 0)

    assert hlir.news.main is not None, 'Could not determine main entry point'

    hlir.news.model = hlir.news.main.urtype.path.name

    assert hlir.news.model is not None, 'Could not determine architecture model'
    assert hlir.news.model in model_specific_infos, f'Main belongs to unknown package {hlir.news.main}'

    infos = model_specific_infos[hlir.news.model]

    hlir.news.user_meta_var = infos['user_meta_var']
    hlir.news.meta_types = P4Node(infos['meta_types'])


def metadata_type_name_to_inst_name(mt_name):
    if mt_name == 'metadata':
        return 'meta'

    return re.sub(r'_t$', '', mt_name)


def gen_metadata_instance_node(hlir, metadata_type, name, ctl):
    new_inst_node             = P4Node({'node_type': 'StructField'})
    new_inst_node.name        = name or metadata_type_name_to_inst_name(metadata_type.name)
    if ctl:
        new_inst_node.enclosing_control = ctl
    new_inst_node.preparsed   = True
    new_inst_node.is_metadata = True
    new_inst_node.annotations = P4Node({'node_type': 'Annotations'})
    new_inst_node.annotations.annotations = P4Node([])
    new_inst_node.type = P4Node({'node_type': 'Type_Name'})
    new_inst_node.type.path = P4Node({'node_type': 'name'})
    new_inst_node.type.path.name = metadata_type.name
    new_inst_node.type.path.absolute = True
    new_inst_node.type.preparsed = False
    new_inst_node.type.type_ref = metadata_type
    metadata_type.is_metadata = True


    return new_inst_node


def mcall_to_hdr(mcall):
    return mcall.method.expr.expr.type if 'expr' in mcall.method.expr else mcall.method.expr.type

def metafld_name(hdr, fld):
    return f"{re.sub(r'_t$', '', hdr.name)}_{fld.name}"

def make_metaflds(fld_hdr_origins):
    for name in fld_hdr_origins:
        hdr, fld, origin = fld_hdr_origins[name]

        metafld = P4Node({'node_type': 'StructField'})
        metafld.name = name
        # metafld.name = fld.name or metafld_name(hdr, fld)
        metafld.type = fld
        metafld.origin_ref = origin

        metafld.type.path = P4Node({'node_type': 'Path'})
        metafld.type.path.absolute = True

        metafld.orig_hdr = hdr
        metafld.orig_fld = fld

        yield metafld


def set_header_meta_preparsed(hdr, is_meta_preparsed):
    hdr.urtype.is_metadata = is_meta_preparsed
    if 'path' not in hdr.urtype or not hdr.urtype.path.absolute:
        for fld in hdr.urtype.fields:
            fld.preparsed = is_meta_preparsed


def check_meta_fields(fldinfos):
    count = Counter(fldinfos)
    for name, typename in count:
        if count[(name, typename)] > 1:
            def fld_urtype_info(fld):
                if fld.type == fld.urtype:
                    return f'{fld.type.name}'
                return f'{fld.type.name} (aka {fld.urtype.name})'
            typeinfos = ''.join((f'    - {fld.name}: {fld_urtype_info(fld)}\n' for fldname, fldtype in fldinfos))
            addError('getting metadata', f'The name {name} appears in {count[(name, typename)]} metadata fields with different types:\n{typeinfos}')

def localvar_meta(hlir, name, hdr, hdrt, fld):
    """Creates a meta header with the given name if it does not exist.
    Adds the given field into it.
    Returns the header."""
    if name not in hlir.news.meta:
        meta_hdr = P4Node({'node_type': 'Type_Struct'})
        meta_hdr.name = name
        meta_hdr.fields = P4Node([])
        meta_hdr.preparsed = True
        hlir.news.meta.append(meta_hdr)
    else:
        meta_hdr = hlir.news.meta.get(name)

    meta_hdr.fields.append(fld)

    for fld2 in hdrt.fields:
        fld2.preparsed = True

    return meta_hdr

def make_allmetas_node(hlir):
    ctl_local_vars = hlir.controls.flatmap('controlLocals').filter('node_type', 'Declaration_Variable')

    clv_to_struct = {}

    fldinfos = unique_everseen((fld.name, fld.urtype) for fld in hlir.news.meta.flatmap('fields'))

    check_meta_fields(fldinfos)

    fldname_to_hdrfield = {fld.name: (hdr, fld, fld) for hdr in hlir.news.meta for fld in hdr.fields}

    allmeta_flds = list(make_metaflds(fldname_to_hdrfield)) + list(make_metaflds(clv_to_struct))

    hlir.allmetas = P4Node({'node_type': 'StructField'})
    hlir.allmetas.name = 'all_metadatas'
    hlir.allmetas.type = P4Node({'node_type': 'Type_Name'})
    hlir.allmetas.type.path = P4Node({'node_type': 'Path'})
    hlir.allmetas.type.path.absolute = True

    hlir.allmetas.type.type_ref = P4Node({'node_type': 'Type_Header'})
    hlir.allmetas.type.type_ref.name = 'all_metadatas_t'
    hlir.allmetas.type.type_ref.fields = P4Node(allmeta_flds)


def relink_aliases(hlir):
    for method in hlir.all_nodes.by_type('Type_Method'):
        for param in method.parameters.parameters.filter(lambda param: 'name' in param.type):
            if hlir.news.meta.get(param.type.name):
                param.type.type_ref = hlir.allmetas

    for param in hlir.all_nodes.by_type('Parameter').filter('type.node_type', 'Type_Enum'):
        if (found := hlir.enums.get(param.type.name)):
            param.type = found
        if (found := hlir.errors.get(param.type.name)):
            param.type = found

    for arg in hlir.all_nodes.by_type('Argument').filter('expression.type.node_type', 'Type_Header'):
        if (found := hlir.headers.get(arg.expression.type.name)):
            arg.expression.type = found


def create_struct_field(decl_inst):
    struct_field = P4Node({'node_type': 'StructField'})
    struct_field.name = decl_inst.name
    struct_field.type = decl_inst.type
    return struct_field


def attrs_hdr_metadata_insts(hlir):
    """Metadata instances and header instances"""

    # TODO move it to a more appropriate place
    hlir.locals = hlir.controls.flatmap('controlLocals') + hlir.parsers.flatmap('parserLocals')

    is_hdr = lambda fld: fld.urtype.node_type == 'Type_Header'
    is_named_hdr = lambda fld: fld.urtype.node_type == 'Type_Name' and resolve_type_name(hlir, fld.urtype).node_type == 'Type_Header'

    hdrs = hlir.news.data.flatmap('fields').filter(lambda fld: is_hdr(fld) or is_named_hdr(fld))
    local_hdrs = hlir.locals.filter('node_type', 'Declaration_Variable').filter('type.node_type', 'Type_Name').filter(lambda h: hlir.headers.get(h.urtype.path.name) is not None).map(create_struct_field)
    insts = hdrs + local_hdrs

    for inst in insts:
        if 'path' in inst.urtype and not inst.urtype.path.absolute:
            inst.type.type_ref = hlir.headers.get(inst.urtype.path.name)

    set_header_meta_preparsed(hlir.allmetas, True)
    for hdr in hlir.headers:
        set_header_meta_preparsed(hdr, False)

    hlir.headers.append(hlir.allmetas.urtype)

    hlir.header_instances = P4Node(insts + [hlir.allmetas])


def attrs_add_enum_sizes(hlir):
    """Types that have members do not have a proper size (bit width) as we get it.
    We need to compute them by hand."""

    for fldt in hlir.enums.map('urtype'):
        fldt.size = dlog(len(fldt.members))

    for fldt in hlir.errors.map('urtype'):
        fldt.size = dlog(len(fldt.members))


def attrs_header_types_add_attrs(hlir):
    """Collecting header types, part 2"""

    # for hdrt in hlir.header_instances.map('urtype').filter(lambda hdrt: 'name' in hdrt):
    for hdrt in hlir.headers:
        offset = 0
        for fld in hdrt.fields:
            # TODO bit_offset, byte_offset, mask
            fld.offset = offset
            fld.size = fld.urtype.size
            # 'Type_Bits' vs. 'Type_Varbits'
            fld.is_vw = (fld.urtype.node_type == 'Type_Varbits')

            offset += fld.size

        hdrt.size = sum(hdrt.fields.map('size'))
        hdrt.byte_width = (hdrt.size+7) // 8
        hdrt.is_vw = any(hdrt.fields.map('is_vw'))


table_key_match_order = ['exact', 'lpm', 'ternary']


def set_table_key_attrs(hlir, table):
    for k in table.key.keyElements:
        k.match_order = table_key_match_order.index(k.matchType.path.name)

        if 'expr' not in k.expression:
            # the key element is a local variable in a control
            k.size = table.control.controlLocals.get(k.expression.path.name).urtype.size
            continue

        expr = k.expression.expr

        k.field_name = k.expression.member

        if (fld := hlir.allmetas.urtype.fields.get(k.field_name)):
            # TODO .hdr_ref is already set in some cases, but not all
            expr.hdr_ref = hlir.allmetas

            k.header = hlir.allmetas
            k.header_name = 'all_metadatas'
            k.size = fld.size
        else:
            # supposing that k.expression is of form '<header_name>.<name>'
            if expr.node_type == 'PathExpression':
                k.header_name = expr.hdr_ref.name
            # supposing that k.expression is of form 'hdr.<header_name>.<name>'
            elif expr.node_type == 'Member':
                k.header_name = expr.member
            else:
                addWarning("Table key analysis", f"Header not found for key in table {table.name}")

            k.header = hlir.header_instances.get(k.header_name)

        if 'size' not in k:
            k.size = k.header.urtype.fields.get(k.field_name).urtype.size


def get_meta_instance(hlir, metaname):
    return hlir.allmetas, f'all_metadatas_{metaname}'


def key_length(hlir, keyelement):
    expr = keyelement.expression.get_attr('expr')
    if expr is None:
        return keyelement.expression.type.size

    if expr.type.name == 'metadata':
        keyelement.header = hlir.allmetas
        if 'size' not in keyelement:
            keyelement.size = hlir.allmetas.urtype.fields.get(metaname).urtype.size

    keyelement.header = hlir.header_instances.get(keyelement.header_name)
    return keyelement.size if keyelement.header is not None else 0


def table_key_length(hlir, table):
    return sum((key_length(hlir, keyelement) for keyelement in table.key.keyElements))


def add_attr_named_actions(table):
    named_actions = []
    for a in table.actions:
        name_parts = a.action_object.annotations.annotations('name').expr
        if not name_parts:
            continue
        a.name = name_parts[0].value.rsplit(".")[-1]
        named_actions.add(a)
    table.named_actions = P4Node(named_actions)


def set_table_match_type(table):
    counter = Counter(table.key.keyElements.map('matchType.path.name'))

    table.matchType = P4Node({'node_type': 'matchType'})

    table.matchType.ternary = counter['ternary']
    table.matchType.lpm = counter['lpm']
    table.matchType.exact = counter['exact']

    if counter['ternary']  > 1: table.matchType.name = 'ternary'
    if counter['lpm']      > 1: table.matchType.name = 'ternary'
    if counter['lpm']     == 1: table.matchType.name = 'lpm'
    if counter['lpm']     == 0: table.matchType.name = 'exact'


def make_canonical_name(node):
    annot = node.annotations.annotations.get('name')
    node.canonical_name = annot.expr[0].value if annot is not None else f'({node.name})'

def make_short_canonical_names(nodes):
    shorted = set()
    multiple = set()

    infos = [(node, node.canonical_name, node.canonical_name.split('.')[-1], 'is_hidden' in node and node.is_hidden) for node in nodes]

    for node, canname, shortname, hid in infos:
        if hid:
            continue
        shortname = canname.split('.')[-1]
        if shortname in multiple:
            continue
        if shortname in shorted:
            shorted.remove(shortname)
            multiple.add(shortname)
            continue
        shorted.add(shortname)

    for node, canname, shortname, hid in infos:
        if hid:
            node.short_name = canname
        else:
           node.short_name = shortname if shortname in shorted else canname


def attrs_controls_tables(hlir):
    for ctl in hlir.controls:
        ctl.tables = P4Node(ctl.controlLocals['P4Table'])
        for table in ctl.tables:
            table.control = ctl
        ctl.actions = P4Node(ctl.controlLocals['P4Action'])

    hlir.tables = P4Node([table for ctrl in hlir.controls for table in ctrl.tables])

    for table in hlir.tables:
        for prop in table.properties.properties:
            table.set_attr(prop.name, prop.value)
        table.remove_attr('properties')

    for table in hlir.tables:
        table.is_hidden = len(table.annotations.annotations.filter('name', 'hidden')) > 0

        make_canonical_name(table)

    make_short_canonical_names(hlir.tables)

    for ctl in hlir.controls:
        for table in ctl.tables:
            for act in table.actions.actionList:
                act.action_object = table.control.actions.get(act.expression.method.path.name)
                ao = act.action_object
                make_canonical_name(ao)

            table.actions = P4Node(table.actions.actionList)
            add_attr_named_actions(table)

    make_short_canonical_names(hlir.controls.flatmap('tables').flatmap('actions').map('action_object'))

    # keyless tables are turned into empty-key tables
    for table in hlir.tables:
        if 'key' not in table:
            table.key = P4Node({'node_type': 'Key'})
            table.key.keyElements = P4Node([])

    for table in hlir.tables:
        set_table_match_type(table)
        set_table_key_attrs(hlir, table)

    for table in hlir.tables:
        table.key_length_bits = table_key_length(hlir, table)
        table.key_length_bytes = (table.key_length_bits+7) // 8


def attrs_extract_node(hlir, node, method):
    arg0 = node.methodCall.arguments[0]

    node.call   = 'extract_header'
    node.is_tmp = arg0.node_type == 'PathExpression'
    node.header = arg0 if node.is_tmp else resolve_header_ref(arg0)
    node.is_vw  = len(method.type.parameters.parameters) == 2

    if node.is_vw:
        node.width = node.methodCall.arguments[1]


def attrs_extract_nodes(hlir):
    for mcall in hlir.all_nodes.by_type('MethodCallStatement'):
        method = mcall.methodCall.method
        if method('expr.path.name') == 'packet' and method.member == 'extract':
            attrs_extract_node(hlir, mcall, method)


def attrs_header_refs_in_exprs(hlir):
    """Header references in expressions"""

    member_nodes = hlir.all_nodes.by_type('Member')
    no_externs = member_nodes.filterfalse('expr.type.node_type', 'Type_Extern')

    hlir.node_groups = P4Node({'node_type': 'NodeGroup'})
    hlir.node_groups.members = P4Node({'node_type': 'NodeGroup'})

    members = hlir.node_groups.members
    make_node_group(members, 'headers', no_externs.filter('type.node_type', 'Type_Header'))
    make_node_group(members, 'members', no_externs.not_of(members.headers).filter('expr.node_type', 'Member'))
    make_node_group(members, 'paths', no_externs.not_of(members.headers).filter('expr.node_type', 'PathExpression'))

    rest = no_externs.not_of(members.headers)

    if len(stacks := member_nodes.filter('type.node_type', 'Type_Stack')) > 0:
        names = ', '.join(unique_everseen((f'{stack.expr.path.name}.{stack.member}' for stack in stacks)))
        raise NotImplementedError(f"Some headers ({names}) are header stacks which are currently not supported")

    for member in members.headers:
        mexpr = member.expr
        mtype = mexpr.urtype
        mname = member.member
        tname = member.type.name

        member.hdr_ref = hlir.header_instances.filter('urtype.name', tname).get(mname)
        mexpr.hdr_ref = member.hdr_ref

    for member in members.members:
        mexpr = member.expr
        mtype = mexpr.urtype
        mname = member.member

        member.hdr_ref = hlir.headers.get(mtype.name)
        member.fld_ref = member.hdr_ref.fields.get(mname)

        mexpr.hdr_ref = member.hdr_ref
        mexpr.fld_ref = member.fld_ref

        mexpr.urtype.type_ref = hlir.headers.get(mexpr.urtype.name)


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


def get_registers(hlir):
    reg_insts = hlir.decl_instances
    local_regs = hlir.controls.flatmap('controlLocals').filter('node_type', 'Declaration_Instance').filter('type.node_type', 'Type_Specialized')
    return (reg_insts + local_regs).filter('type.baseType.path.name', 'register')


# In v1model, all software memory cells are represented as 32 bit integers
def smem_repr_type(smem):
    tname = "int" if smem.is_signed else "uint"

    for w in [8,16,32,64]:
        if smem.size <= w:
            return f"register_{tname}{w}_t"

    return "NOT_SUPPORTED"


def smem_components(smem):
    make_canonical_name(smem)

    smem.size = smem.type.arguments[0].urtype.size if smem.smem_type == "register" else 32
    smem.is_signed = smem.type.arguments[0].urtype.isSigned if smem.smem_type == "register" else False
    smem.is_direct = smem.smem_type in ("direct_counter", "direct_meter")

    smem.amount = 1 if smem.is_direct else smem.arguments['Argument'][0].expression.value

    base_type = smem_repr_type(smem)

    if smem.smem_type == 'register':
        return [{"type": base_type, "name": smem.name}]

    member = [s.expression for s in smem.arguments if s.expression.node_type == 'Member'][0]

    # TODO set these in hlir_attrs
    smem.packets_or_bytes = member.member.lower()
    smem.smem_for = {
        "packets": smem.packets_or_bytes in ("packets", "packets_and_bytes"),
        "bytes":   smem.packets_or_bytes in (  "bytes", "packets_and_bytes"),
    }

    pkts_name  = f"{smem.smem_type}_{smem.name}_packets"
    bytes_name = f"{smem.smem_type}_{smem.name}_bytes"

    pbs = {
        "packets":           P4Node([{"for": "packets", "type": base_type, "name": pkts_name}]),
        "bytes":             P4Node([{"for":   "bytes", "type": base_type, "name": bytes_name}]),

        "packets_and_bytes": P4Node([{"for": "packets", "type": base_type, "name": pkts_name},
                                     {"for":   "bytes", "type": base_type, "name": bytes_name}]),
    }

    return pbs[smem.packets_or_bytes]


def attrs_stateful_memory(hlir):
    # direct counters
    for table in hlir.tables:
        table.direct_meters    = P4Node(unique_list([m for t, m in get_smems('direct_meter', [table])]))
        table.direct_counters  = P4Node(unique_list([c for t, c in get_smems('direct_counter', [table])]))

    # indirect counters
    hlir.meters    = P4Node(unique_list(get_smems('meter', hlir.tables)))
    hlir.counters  = P4Node(unique_list(get_smems('counter', hlir.tables) + get_smems('Counter', hlir.tables)))
    hlir.registers = P4Node(unique_list(get_registers(hlir)))

    hlir.all_meters   = P4Node(unique_list(hlir.meters   + [(t, m) for t in hlir.tables for m in t.direct_meters]))
    hlir.all_counters = P4Node(unique_list(hlir.counters + [(t, c) for t in hlir.tables for c in t.direct_counters]))

    for _table, smem in hlir.all_meters + hlir.all_counters:
        smem.smem_type  = smem.type._baseType.path.name
        smem.components = smem_components(smem)
    for smem in hlir.registers:
        smem.smem_type  = smem.type._baseType.path.name
        smem.components = smem_components(smem)

    make_short_canonical_names([smem for _, smem in hlir.all_meters])
    make_short_canonical_names([smem for _, smem in hlir.all_counters])
    make_short_canonical_names(hlir.registers)

def attrs_typedef(hlir):
    for typedef in hlir.all_nodes.by_type('Type_Typedef'):
        if 'size' in typedef:
            continue

        if 'type_ref' not in typedef.type:
            typedef.size = typedef.type.size
        elif 'size' in typedef.urtype:
            typedef.size = typedef.urtype.size


def attrs_reachable_parser_states(hlir):
    parser = hlir.parsers[0]

    reachable_states = set()
    reachable_states.add('start')
    reachable_states.add('accept')
    reachable_states.add('reject')

    for e in hlir.all_nodes.by_type('SelectExpression'):
        for case in e.selectCases:
            reachable_states.add(case.state.path.name)

    for s in parser.states:
        if 'selectExpression' not in s:
            continue

        b = s.selectExpression

        if b.node_type == 'PathExpression':
            reachable_states.add(b.path.name)
        else:
            for case in b.selectCases:
                reachable_states.add(case.state.path.name)

    for s in parser.states:
        s.is_reachable = s.name in reachable_states


def attrs_control_locals(hlir):
    non_ctr_locals = ('counter', 'direct_counter', 'meter')

    for ctl in hlir.controls:
        ctl.local_var_decls = ctl.controlLocals.filter('node_type', ('Declaration_Variable', 'Declaration_Instance')).filterfalse('urtype.name', non_ctr_locals)
        for local_var_decl in ctl.local_var_decls:
            vart = local_var_decl.urtype
            vart.needs_dereferencing = 'size' in vart and vart.size > 32


def default_attr_funs(p4_filename, p4_version):
    return [
        hlir16.hlirx_regroup.regroup_attrs,
        lambda hlir: attrs_top_level(hlir, p4_filename, p4_version),
        hlir16.hlirx_regroup.attrs_regroup_structs,
        hlir16.hlirx_regroup.attrs_regroup_members,
        hlir16.hlirx_regroup.attrs_regroup_path_expressions,
        hlir16.hlirx_regroup.finish_regroup,

        make_allmetas_node,
        attrs_hdr_metadata_insts,

        relink_aliases,

        attrs_type_boolean,
        attrs_annotations,
        attrs_typeargs,

        attrs_resolve_members,
        attrs_resolve_types,

        attrs_member_naming,

        attrs_add_enum_sizes,

        attrs_resolve_pathexprs,

        attrs_header_types_add_attrs,

        attrs_controls_tables,
        attrs_extract_nodes,
        attrs_header_refs_in_exprs,
        attrs_stateful_memory,
        attrs_typedef,

        attrs_reachable_parser_states,

        attrs_control_locals,

        hlir16.hlirx_annots.copy_annots,
    ]

def set_additional_attrs(hlir, p4_filename, p4_version, additional_attr_funs = None):
    for attrfun in additional_attr_funs or default_attr_funs(p4_filename, p4_version):
        attrfun(hlir)

    return hlir
