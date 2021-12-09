#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node, get_fresh_node_id
from hlir16.hlir_utils import make_node_group, align8_16_32, unique_list, shorten_locvar_names
from hlir16.hlir_model import model_specific_infos, smem_types_by_model, packets_by_model
from hlir16.hlir_attrs_extern import attrs_extern

import hlir16.hlirx_annots
import hlir16.hlirx_regroup

from compiler_log_warnings_errors import addWarning, addError
from compiler_common import unique_everseen, dlog

import re
from collections import Counter


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
    varname = type_var.name

    if (parents := type_var.parents.filter('node_type', ('Type_Method'))) != []:
        results = list(partype for parent in parents for parname, partype in zip(parent.typeParameters.parameters.map('name'), parent.parameters.parameters) if parname == varname)
        if len(results) > 0:
            return results[0]

    if (parents := type_var.parents.filter('node_type', ('Type_Extern', 'Type_Parser'))) != []:
        typeargs = parents.filter(lambda n: 'typeargs' in n and varname in n.typeargs).map('typeargs')
        if len(typeargs) > 0:
            return typeargs[0][varname]

    return None



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

    for method in hlir.methods:
        set_typeargs(method)


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

def copy_type_var_nodes(typepars):
    """Nodes with node_type Type_Var whose name are the same (e.g. T) use the exact same P4Node.
    However, they need to be separate P4Nodes, as they are resolved to different types.
    Therefore, this method creates separate P4Node copies of these nodes."""
    return P4Node([P4Node({'node_type': 'Type_Var', 'name': old.name}) for old in typepars])

def attrs_resolve_types(hlir):
    """Resolve all Type_Name nodes to real type nodes"""

    for node in hlir.all_nodes.by_type('Type_Name'):
        resolve_type(hlir, node)

    for stmt in hlir.all_nodes.by_type('BlockStatement'):
        if found := stmt.parents.filter('node_type', 'P4Control'):
            stmt.enclosing_control = found[0]

    for node in hlir.all_nodes.by_type('Parameter').filter('type.node_type', 'Type_Var'):
        nt = node.type
        if (ref := resolve_type_var(hlir, nt)):
            nt.type_ref = ref

    for spcan in hlir.groups.pathexprs.specialized_canonical:
        old_typepars = spcan.urtype.typeParameters.parameters
        spcan.type_parameters = copy_type_var_nodes(old_typepars)
        for par, arg in zip(spcan.type_parameters, spcan.type.arguments):
            par.type_ref = arg

    for ee in hlir.all_nodes.by_type('PathExpression').filter('type.node_type', 'Type_Method'):
        for node in ee.type.typeParameters.parameters.filter('node_type', 'Type_Var'):
            if (ref := resolve_type_var(hlir, node)):
                node.type_ref = ref


def attrs_add_renamed_locals(hlir):
    """Adds a .locals attribute that unifies the parserLocals/controlLocals attribute in P4Parser/P4Control nodes."""
    for parser in hlir.parsers:
        parser.locals = parser.parserLocals

    for ctl in hlir.controls:
        ctl.locals = ctl.controlLocals


def attrs_resolve_pathexprs(hlir):
    """Resolve all PathExpression nodes"""

    for pe in hlir.groups.pathexprs.action:
        pe.action_ref = hlir.map('controls').flatmap('locals').get(pe.path.name)

    for hexpr in hlir.groups.pathexprs.header + hlir.groups.pathexprs.struct + hlir.groups.member_exprs.headers + hlir.groups.member_exprs.structs:
        tname = hexpr.urtype.name
        name = hexpr._expr.path.name

        if hexpr.type.name in hlir.news.meta_types:
            hexpr.hdr_ref = hlir.allmetas
        elif (found := hlir.news.data.get(tname)):
            hexpr.hdr_ref = found
        elif (found := hlir.news.meta.get(tname)):
            hexpr.hdr_ref = hlir.allmetas
        elif (found := hexpr.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('locals').get(name)):
            hexpr.hdr_ref = found
        elif len(founds := [hdrt for hdrt in unique_everseen(hlir.header_instances.map('urtype').filter('name', hexpr.type.name))]) == 1:
            hexpr.hdr_ref = founds[0]
            hexpr.type.type_ref = founds[0].urtype

    for pe in hlir.groups.pathexprs.table:
        pe.table_ref = hlir.map('controls').flatmap('locals').get(pe.path.name)

    for mcexpr in hlir.groups.pathexprs.under_mcall:
        mname = mcexpr.path.name

        if (found := hlir.methods.get(mname)):
            mcexpr.action_ref = found
        else:
            mcexpr.action_ref = hlir.controls.flatmap('locals').get(mname)

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
        clocs = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('locals')
        pe.decl_ref = clocs.get(pe.path.name)
        if pe.decl_ref is None and len(pars := clocs.flatmap('parameters.parameters')) > 0:
            parname, parsize = unique_everseen(((par.name, par.urtype.size) for par in pars))[0]
            pe.decl_ref = pars.filter(lambda par: (par.name, par.urtype.size) == (parname, parsize))[0]

    for pe in hlir.groups.pathexprs.extern_under_member:
        locs = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('locals')
        pe.decl_ref = locs.get(pe.path.name)
        if pe.decl_ref is None:
            pe.decl_ref = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('type.applyParams.parameters').get(pe.path.name)

    for pe in hlir.groups.pathexprs.under_assign:
        locs = pe.parents.filter('node_type', ('P4Parser', 'P4Control')).flatmap('locals')
        pe.decl_ref = locs.get(pe.path.name)
        if pe.decl_ref is None:
            if len(pars := locs.flatmap('parameters.parameters')) > 0:
                parname, parsize = unique_everseen(((par.name, par.urtype.size) for par in pars))[0]
                pe.decl_ref = pars.filter(lambda par: (par.name, par.urtype.size) == (parname, parsize))[0]

    for pe in hlir.groups.pathexprs.under_unknown:
        pe.table_ref = pe.parents.filter('node_type', 'P4Control').flatmap('locals').get(pe.path.name)


def attrs_fix_enum_error_pars(hlir):
    """Fix some Parameter nodes that don't properly link to enums/errors"""

    for par in hlir.all_nodes['Parameter'].filter('type.node_type', 'Type_Error'):
        if (err := hlir.errors.get(par.type.name)):
            par.type = err

    for par in hlir.all_nodes['Parameter'].filter('type.node_type', 'Type_Enum'):
        if (enum := hlir.enums.get(par.type.name)):
            par.type = enum


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
    hlir.news.deparsers = P4Node(infos['deparsers'])


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


def attrs_pad_hdrs(hlir):
    for hdr in hlir.headers:
        for fld in hdr.fields:
            size = fld.urtype.size
            # important: as fld.urtype can coincide with urtypes of other fields,
            #            .padded_size is added to fld.type, not .urtype
            fld.type.padded_size = size if size > 32 else align8_16_32(size)


def reorder_all_metadatas(hlir):
    """Makes sure that byte aligned meta fields come first."""
    def align_ordering(k):
        psz = k.type.padded_size
        if psz >= 32:
            return -200
        if psz >= 16:
            return -100
        return -psz

    allmetas_type = hlir.allmetas.type.type_ref
    allmetas_type.fields = P4Node(sorted(allmetas_type.fields, key=align_ordering))


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


def create_hdr(hlir, hdrname, hdrtype, idx=0, stack=None):
    hdr = P4Node({'node_type': 'StructField'})
    hdr.name = hdrname
    hdr.type = hdrtype
    hdr.is_local = False

    if stack is not None:
        hdr.stack_idx = idx
        hdr.stack = stack

    for ctl in hlir.controls:
        if ctl.controlLocals.get(hdr.name, 'Declaration_Variable'):
            hdr.ctl_ref = ctl

    return hdr


def hlir_locals(hlir):
    hlir.locals = hlir.controls.flatmap('controlLocals') + hlir.parsers.flatmap('parserLocals')


def attrs_hdr_metadata_insts(hlir):
    """Metadata instances and header instances"""

    is_hdr = lambda fld: fld.urtype.node_type == 'Type_Header'
    is_named_hdr = lambda fld: fld.urtype.node_type == 'Type_Name' and (res := resolve_type_name(hlir, fld.urtype)) is not None and res.node_type == 'Type_Header'

    for stk in hlir.header_stacks:
        # note: the 'size' attribute in T4P4S refers to the bitsize of the header
        #       this renaming avoids collision
        stk.type.stk_size = stk.type.size
        stk.type.del_attr('size')

    stack_infos = hlir.header_stacks.map(lambda stack: (stack, stack.name, stack.urtype.stk_size.value, stack.urtype.elementType))

    hdrs = hlir.news.data.flatmap('fields').filter(lambda fld: is_hdr(fld) or is_named_hdr(fld))
    hdr_stacks = list(create_hdr(hlir, f'{name}_{idx}', type, idx=idx, stack=stack) for (stack, name, stk_size, type) in stack_infos for idx in range(stk_size))
    local_hdrs = hlir.locals \
        .filter('node_type', 'Declaration_Variable') \
        .filter('type.node_type', 'Type_Name') \
        .filter(lambda hdr: hlir.headers.get(hdr.urtype.path.name) is not None) \
        .map(lambda hdr: create_hdr(hlir, hdr.name, hdr.type))
    local_hdr_node_ids = set(local_hdrs.map('Node_ID'))

    insts = hdrs + hdr_stacks + local_hdrs

    for hdrinst in insts:
        hdrinst.is_local = hdrinst.Node_ID in local_hdr_node_ids

        if 'path' in hdrinst.urtype and not hdrinst.urtype.path.absolute:
            hdrinst.type.type_ref = hlir.headers.get(hdrinst.urtype.path.name)

        is_stack = 'stack' in hdrinst and hdrinst.stack is not None

        # TODO find an even more reliable way to see if the header is skipped (extracted as _)
        hdrinst.is_skipped = not is_stack and hdrinst.is_local and 'annotations' not in hdrinst and hdrinst.name.startswith('arg')

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


def compute_fld_sizes(struct):
    # perhaps turn this into a command line option
    pad_meta_fields = True

    is_meta = 'is_metadata' in struct and struct.is_metadata

    offset = 0
    for fld in struct.fields:
        if (stk := fld.type).node_type == 'Type_Stack':
            fld.size = stk.stk_size.value * stk.elementType.urtype.size
        elif not ('is_vw' in fld and fld.is_vw):
            fld.size = fld.urtype.size
        else:
            fld.size = 0

        if pad_meta_fields and is_meta:
            fld.offset = offset + (fld.type.padded_size - fld.size)
            offset += fld.type.padded_size
        else:
            fld.offset = offset
            offset += fld.size

    struct.size = offset
    struct.byte_width = (struct.size+7) // 8


def attrs_header_types_add_attrs(hlir):
    """Collecting header types, part 2"""

    for hdr in hlir.headers:
        for fld in hdr.fields:
            # 'Type_Bits' vs. 'Type_Varbits'
            fld.is_vw = (fld.urtype.node_type == 'Type_Varbits')
            if fld.is_vw:
                fld.max_vw_size = fld.urtype.size
                hdr.vw_fld = fld

        hdr.is_vw = any(hdr.fields.map('is_vw'))


    for hdr in hlir.headers:
        compute_fld_sizes(hdr)

    structs_idx = 13
    for struct in hlir.object_groups[structs_idx] + hlir.all_nodes.by_type('StructExpression').map('type'):
        compute_fld_sizes(struct)


def attrs_add_field_cnames(hlir):
    """Adds a short_len attribute that extracts fldname from generated field names like _fldname101."""
    for hdrt in hlir.headers.filter(lambda hdrt: len(hdrt.fields) > 0):
        shorten_locvar_names(hdrt.fields, last_infix='')


def replace_short_name(comp, new_name):
    if 'short_name' not in comp or comp.short_name.startswith('('):
        comp.short_name = f'[{new_name}]'


def improve_action_names(ctl, comp, actions, prefix):
    by_nodetype = {
        'IfStatement': '.if',
    }

    if (ctl2 := comp).node_type == 'P4Control':
        improve_action_names(ctl2, ctl2.body, ctl2.actions, f'{prefix}{"." if prefix != "" else ""}{ctl2.type.name}')
    elif (blk := comp).node_type in ('BlockStatement', 'SwitchCase'):
        parts = blk.components if blk.node_type == 'BlockStatement' else blk.statement
        for idx2, comp2 in enumerate(parts):
            idx_txt = '' if len(parts) == 1 else f'#{idx2+1}'
            improve_action_names(ctl, comp2, actions, f'{prefix}{by_nodetype.get(comp2.node_type, "")}{idx_txt}')
    elif (sw := comp).node_type == 'SwitchStatement':
        for idx2, comp2 in enumerate(sw.cases):
            idx_txt = '' if len(sw.cases) == 1 else f'#{idx2+1}'
            improve_action_names(ctl, comp2, actions, f'{prefix}.case{idx_txt}')
    elif comp.node_type == 'IfStatement':
        improve_action_names(ctl, comp.ifTrue, actions, f'{prefix}T')
        if 'ifFalse' in comp:
            improve_action_names(ctl, comp.ifFalse, actions, f'{prefix}F')
    elif (mcall := comp).node_type == 'MethodCallStatement':
        if 'action_ref' in mcall.methodCall.method:
            action = mcall.methodCall.method.action_ref
        else:
            method = mcall.methodCall.method
            mname = method.expr.path.name
            mprefix = 'tbl_'
            if mname.startswith(mprefix) and (action := actions.get(mname[len(mprefix):])) is not None:
                if (tbl := ctl.tables.get(f'{mprefix}{action.name}')) is not None:
                    replace_short_name(tbl, prefix)
            else:
                return

        replace_short_name(action, prefix)
    elif (mcall := comp).node_type == 'EmptyStatement':
        pass
    else:
        addWarning('Improving action names', f'Unexpected statement node type {comp.node_type}')


def attrs_improve_action_names(hlir):
    for ctl in hlir.controls:
        improve_action_names(ctl, ctl, ctl.actions, '')


def attrs_improve_localvar_names(hlir):
    for ctl in hlir.controls:
        shorten_locvar_names(ctl.controlLocals['Declaration_Variable'])

    for parser in hlir.parsers:
        shorten_locvar_names(parser.parserLocals['Declaration_Variable'])


table_key_match_order = ['exact', 'range', 'selector', 'lpm', 'ternary']


def set_table_key_attrs(hlir, table):
    for k in table.key.keyElements:
        match_name = k.matchType.path.name
        k.match_order = table_key_match_order.index(match_name)
        kx = k.expression

        if 'expr' not in kx:
            k.size = kx.urtype.size

            # TODO remove?
                # the key element is a local variable in a control
                # locs = table.control.controlLocals
                # locvar = locs.get(kx.path.name)
                # k.size = locvar.urtype.size

            continue

        kxx = kx.expr

        k.field_name = kx.member

        hdrname = None
        if kxx.node_type == 'Member':
            hdrname = kxx.member

        if hdrname is None and (fld := hlir.allmetas.urtype.fields.get(k.field_name)):
            # TODO .hdr_ref is already set in some cases, but not all
            kxx.hdr_ref = hlir.allmetas

            k.header = hlir.allmetas
            k.header_name = 'all_metadatas'
            k.size = fld.size
        else:
            # supposing that kx is of form '<header_name>.<name>'
            if kxx.node_type == 'PathExpression':
                k.header_name = kxx.hdr_ref.name
            # supposing that kx is of form 'hdr.<header_name>.<name>'
            elif kxx.node_type == 'Member':
                k.header_name = kxx.member
            elif kxx.node_type == 'ArrayIndex':
                idx = kxx.right.value
                k.header_name = f'{kxx.left.member}_{idx}'
            else:
                addWarning("Table key analysis", f"Header not found for key in table {table.name}")
                continue

            k.header = hlir.header_instances.get(k.header_name)

            fld = k.header.urtype.fields.get(k.field_name)
            k.size = fld.urtype.size


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


# note: Python 3.9 has this as a built-in
def removeprefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def make_canonical_name(node):
    annot = node.annotations.annotations.get('name')
    node.canonical_name = annot.expr[0].value if annot is not None else f'({removeprefix(node.name, "tbl_")})'


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
        table.key_bit_size = table_key_length(hlir, table)
        table.key_length_bytes = (table.key_bit_size+7) // 8


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

    meta_flds = hlir.allmetas.urtype.fields
    for member in members.paths.filterfalse('urtype.node_type', 'Type_Stack').filter('expr.urtype.node_type', 'Type_Struct'):
        hdrt_name = member.expr.urtype.name
        fldname = member.member

        member.hdr_ref = hlir.allmetas
        member.fld_ref = meta_flds.get(fldname, 'StructField')

    for member in members.headers:
        mexpr = member.expr
        mtype = mexpr.urtype
        hdrname = member.member
        hdrt_name = member.type.name

        member.hdr_ref = hlir.header_instances.filter('urtype.name', hdrt_name).get(hdrname)
        mexpr.hdr_ref = member.hdr_ref

    for member in members.members:
        mexpr = member.expr
        mtype = mexpr.urtype
        mname = member.member

        stack_ops = ('push_front', 'pop_front')

        if mtype.node_type == 'Type_Stack' and mname in stack_ops:
            continue

        if 'expr' in mexpr and mexpr.expr.type.node_type == 'Type_Stack' and mexpr.member == 'last':
            member.stk_name = mexpr.expr.member
            continue

        hdrname = mexpr.member
        hdrinst = hlir.header_instances.get(hdrname)
        member.hdr_ref = hdrinst
        mexpr.hdr_ref  = hdrinst

        fldname = mname
        if (fref := member.hdr_ref.urtype.fields.get(fldname)):
            member.fld_ref = fref
            mexpr.fld_ref  = fref

        mexpr.urtype.type_ref = hlir.headers.get(mexpr.urtype.name)


def get_ctrlloc_smem_type(loc):
    type = loc.type.baseType if loc.type.node_type == 'Type_Specialized' else loc.type
    return type.path.name


def get_direct_smems(smem_type, tables):
    """Gets counters and meters for tables."""
    return unique_list((t, loc)
        for t in tables
        for loc in t.control.controlLocals['Declaration_Instance']
        if get_ctrlloc_smem_type(loc) == smem_type)


def get_smems(smem_type, tables):
    """Gets counters and meters for tables."""
    return unique_list((None, loc)
        for t in tables
        for loc in t.control.controlLocals['Declaration_Instance']
        if get_ctrlloc_smem_type(loc) == smem_type)


def get_registers(hlir, register_name):
    reg_insts = hlir.decl_instances
    local_regs = hlir.controls.flatmap('controlLocals').filter('node_type', 'Declaration_Instance').filter('type.node_type', 'Type_Specialized')
    return (reg_insts + local_regs).filter('type.baseType.path.name', register_name)


# In v1model, all software memory cells are represented as 32 bit integers
def smem_repr_type(smem):
    tname = "int" if smem.is_signed else "uint"

    for w in [8,16,32,64]:
        if smem.size <= w:
            # note: this should look like the line below, but is used as a postfix of method name apply_direct_smem_* in dataplane.c
            # return f"REGTYPE({tname},{w})"
            return f"register_{tname}{w}_t"

    return "NOT_SUPPORTED"


def smem_components(hlir, smem, table):
    get_smem, reverse_get_smem = smem_types_by_model(hlir)

    make_canonical_name(smem)

    smem.is_direct  = smem.smem_type in ('direct_counter', 'direct_meter')

    smem.size = smem.type.arguments[0].urtype.size if smem.smem_type == 'register' else 32
    smem.is_signed = smem.type.arguments[0].urtype.isSigned if smem.smem_type == 'register' else False
    smem.is_direct = smem.smem_type in ('direct_counter', 'direct_meter')

    smem.amount = 1 if smem.is_direct else smem.arguments['Argument'][0].expression.value

    base_type = smem_repr_type(smem)

    if smem.smem_type == 'register':
        smem.name_parts = P4Node([smem.smem_type, smem.name])
        return [{"type": base_type, "name": smem.name}]


    pobs, reverse_pobs = packets_by_model(hlir)
    smem.packets_or_bytes = reverse_pobs[smem.arguments.map('expression').filter('node_type', 'Member')[0].member]

    smem.smem_for = {
        "packets": smem.packets_or_bytes in ("packets", "packets_and_bytes"),
        "bytes":   smem.packets_or_bytes in (  "bytes", "packets_and_bytes"),
    }

    if smem.is_direct:
        smem.table = table
        pkts_parts  = [smem.smem_type, smem.name, pobs['packets'], table.name]
        bytes_parts = [smem.smem_type, smem.name, pobs['bytes'], table.name]
    else:
        pkts_parts  = [smem.smem_type, smem.name, pobs['packets']]
        bytes_parts = [smem.smem_type, smem.name, pobs['bytes']]

    pkts_name  = '_'.join(pkts_parts)
    bytes_name = '_'.join(bytes_parts)

    pbs = {
        "packets":           P4Node([{"for": "packets", "type": base_type, "name": pkts_name}]),
        "bytes":             P4Node([{"for":   "bytes", "type": base_type, "name": bytes_name}]),

        "packets_and_bytes": P4Node([{"for": "packets", "type": base_type, "name": pkts_name},
                                     {"for":   "bytes", "type": base_type, "name": bytes_name}]),
    }

    flatpbs = {
        "packets":           ['packets'],
        "bytes":             ['bytes'],
        "packets_and_bytes": ['packets', 'bytes'],
    }


    smem.insts = P4Node([])
    for pb in flatpbs[smem.packets_or_bytes]:
        smem_inst = P4Node({'node_type': 'Smem_Instance'})

        smem_inst.smem = smem
        smem_inst.name = smem.name

        smem_inst.packets_or_bytes = pb

        smem_inst.is_direct  = smem.smem_type in ('direct_counter', 'direct_meter')

        smem_inst.size = smem.type.arguments[0].urtype.size if smem.smem_type == 'register' else 32
        smem_inst.is_signed = smem.type.arguments[0].urtype.isSigned if smem.smem_type == 'register' else False
        smem_inst.is_direct = smem.smem_type in ('direct_counter', 'direct_meter')

        smem_inst.amount = 1 if smem.is_direct else smem.arguments['Argument'][0].expression.value

        smem_inst.table = table if smem_inst.is_direct else None

        packet_or_byte = pobs[pb]
        if smem_inst.is_direct:
            smem.name_parts = P4Node([smem.smem_type, smem.name, table.name])
            smem_inst.name_parts = P4Node([smem.smem_type, smem.name, packet_or_byte, table.name])
        else:
            smem.name_parts = P4Node([smem.smem_type, smem.name])
            smem_inst.name_parts = P4Node([smem.smem_type, smem.name, packet_or_byte])

        hlir.smem_insts.append(smem_inst)
        smem.insts.append(smem_inst)
        smem.set_attr(f'smem_{pb}_inst', smem_inst)

    return pbs[smem.packets_or_bytes]


def attrs_stateful_memory(hlir):
    get_smem, reverse_get_smem = smem_types_by_model(hlir)

    # direct counters
    for table in hlir.tables:
        table.direct_meters    = P4Node(unique_list(m for t, m in get_direct_smems(get_smem['direct_meter'], [table])))
        table.direct_counters  = P4Node(unique_list(c for t, c in get_direct_smems(get_smem['direct_counter'], [table])))

    hlir.smem = P4Node({'node_type': 'NodeGroup'})

    # indirect counters
    hlir.smem.meters    = P4Node(unique_list(get_smems(get_smem['meter'], hlir.tables)))
    hlir.smem.counters  = P4Node(unique_list(get_smems(get_smem['counter'], hlir.tables)))
    hlir.smem.registers = P4Node(unique_list(get_registers(hlir, get_smem['register'])))

    dms = [(t, m) for t in hlir.tables for m in t.direct_meters]
    dcs = [(t, c) for t in hlir.tables for c in t.direct_counters]

    for t in hlir.tables:
        for m in t.direct_meters:
            m.table_ref = t
        for c in t.direct_counters:
            c.table_ref = t

    hlir.smem.direct_counters = P4Node(unique_list(dcs))
    hlir.smem.direct_meters = P4Node(unique_list(dms))
    hlir.smem.all_meters   = hlir.smem.meters   + hlir.smem.direct_meters
    hlir.smem.all_counters = hlir.smem.counters + hlir.smem.direct_counters
    hlir.smem.directs      = hlir.smem.direct_meters + hlir.smem.direct_counters
    hlir.smem.indirects    = hlir.smem.meters + hlir.smem.counters
    hlir.smem.all          = hlir.smem.all_meters + hlir.smem.all_counters + hlir.smem.registers.map(lambda reg: (None, reg))

    hlir.smem_insts = P4Node([])

    for table, smem in hlir.smem.all:
        simple_smem_type = smem.type._baseType.path.name

        smem.smem_type  = reverse_get_smem[simple_smem_type]
        smem.components = smem_components(hlir, smem, table)

    make_short_canonical_names([smem for _, smem in hlir.smem.all_meters])
    make_short_canonical_names([smem for _, smem in hlir.smem.all_counters])
    make_short_canonical_names(hlir.smem.registers)


def attrs_ref_stateful_memory(hlir):
    get_smem, reverse_get_smem = smem_types_by_model(hlir)

    for extern in hlir.all_nodes.by_type('Type_Extern'):
        if extern.name in reverse_get_smem:
            extern.extern_type = 'smem'
            extern.smem_type = reverse_get_smem[extern.name]


def attrs_typedef(hlir):
    for typedef in hlir.all_nodes.by_type('Type_Typedef'):
        if 'size' in typedef:
            continue

        if 'type_ref' not in typedef.type:
            typedef.size = typedef.type.size
        elif 'size' in typedef.urtype:
            typedef.size = typedef.urtype.size


def attrs_reachable_parser_states(hlir):
    reachable_states = set()
    reachable_states.add('start')
    reachable_states.add('accept')
    reachable_states.add('reject')

    for e in hlir.all_nodes.by_type('SelectExpression'):
        for case in e.selectCases:
            reachable_states.add(case.state.path.name)

    for parser in hlir.parsers:
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


def attrs_hdr_stacks(hlir):
    hdrstks_idx = 13
    hlir.header_stacks = hlir.object_groups[hdrstks_idx].flatmap('fields').filter('type.node_type', 'Type_Stack')


def default_attr_funs(p4_filename, p4_version):
    return [
        hlir16.hlirx_regroup.regroup_attrs,
        lambda hlir: attrs_top_level(hlir, p4_filename, p4_version),
        hlir16.hlirx_regroup.attrs_regroup_structs,
        hlir16.hlirx_regroup.attrs_regroup_members,
        hlir16.hlirx_regroup.attrs_regroup_path_expressions,
        hlir16.hlirx_regroup.finish_regroup,

        attrs_hdr_stacks,

        hlir_locals,

        make_allmetas_node,
        attrs_hdr_metadata_insts,

        relink_aliases,

        attrs_type_boolean,
        attrs_annotations,
        attrs_typeargs,

        attrs_resolve_members,
        attrs_resolve_types,

        attrs_fix_enum_error_pars,
        attrs_member_naming,

        attrs_add_enum_sizes,

        attrs_add_renamed_locals,

        attrs_resolve_pathexprs,

        attrs_pad_hdrs,
        reorder_all_metadatas,

        attrs_header_types_add_attrs,

        attrs_add_field_cnames,

        attrs_controls_tables,
        attrs_extract_nodes,
        attrs_header_refs_in_exprs,
        attrs_stateful_memory,
        attrs_typedef,
        attrs_extern,

        attrs_ref_stateful_memory,

        attrs_reachable_parser_states,

        attrs_control_locals,

        attrs_improve_action_names,
        attrs_improve_localvar_names,

        hlir16.hlirx_annots.copy_annots,
    ]

def set_additional_attrs(hlir, p4_filename, p4_version, additional_attr_funs = None):
    for attrfun in additional_attr_funs or default_attr_funs(p4_filename, p4_version):
        attrfun(hlir)

    return hlir
