#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node, get_fresh_node_id
from utils.misc import addWarning, addError
from compiler_common import unique_everseen

import re
from collections import Counter


simple_binary_ops = {'Div':'/', 'Mod':'%',                                 #Binary arithmetic operators
                     'Grt':'>', 'Geq':'>=', 'Lss':'<', 'Leq':'<=',         #Binary comparison operators
                     'BAnd':'&', 'BOr':'|', 'BXor':'^',                    #Bitwise operators
                     'LAnd':'&&', 'LOr':'||',                              #Boolean operators
                     'Equ':'==', 'Neq':'!='}                               #Equality operators

# TODO currently, AddSat and SubSat are handled exactly as Add and Sub
complex_binary_ops = {'AddSat':'+', 'SubSat':'-', 'Add':'+', 'Sub':'-', 'Mul':'*', 'Shl':'<<', 'Shr':'>>'}


def get_table_match_type(table):
    counter = Counter(table.key.keyElements.map('matchType.path.name'))

    table.ternary_count = counter['ternary']
    table.lpm_count = counter['lpm']
    table.exact_count = counter['exact']

    if counter['ternary']  > 1: return 'ternary'
    if counter['lpm']      > 1: return 'ternary'
    if counter['lpm']     == 1: return 'lpm'
    if counter['lpm']     == 0: return 'exact'


def attrs_resolve_members(hlir):
    # for m in hlir.groups.member_exprs.members:
    #     breakpoint()

    for can in hlir.groups.member_exprs.specialized_canonical:
        can.expr.ref = hlir.decl_instances.get(can.expr.path.name)
        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", can])
        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", can.expr])



# def resolve_path_expression_node(hlir, path_node, parent):
#     name = path_node.path.name
#     resolve_lists = []
#     current = parent
#     while True:
#         if current.node_type == 'P4Program':
#             return [retval for grp in hlir.object_groups if (retval := grp.get(name))][0]
#         if 'name' in path_node.type and hlir.news.meta.get(path_node.type.name):
#             return hlir.allmetas
#         if current.node_type == 'KeyElement' and current.matchType == path_node:
#             return [mk for mks in hlir.decl_matchkinds
#                     for mk in mks.members if mk.name == path_node.path.name][0]

#         if current.node_type == 'P4Parser':
#             resolve_lists.extend([current.type.applyParams.parameters, current.parserLocals, current.states])
#         elif current.node_type == 'P4Control':
#             resolve_lists.extend([current.type.applyParams.parameters, current.controlLocals])
#         elif current.node_type == 'P4Action':
#             resolve_lists.append(current.parameters.parameters)
#         elif current.node_type == 'Type_Header':
#             resolve_lists.append(current.fields)

#         for resolve_list in resolve_lists:
#             tmp_resolved = resolve_list.get(name)
#             if tmp_resolved is not None:
#                 return tmp_resolved

#         current = current.parent()


def resolve_header_ref(member_expr):
    if 'expression' in member_expr:
        return member_expr.expression.type

    return member_expr.expr.ref.urtype.fields.get(member_expr.member)


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
    if len(typeargs) > 1:
        breakpoint()
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

    # for extern in hlir.groups.member_exprs.externs:
    for extern in hlir.all_nodes.by_type('Type_Extern'):
        set_typeargs(extern)
        for method in extern.map('methods'):
            set_typeargs(method)

    for parser in hlir.all_nodes.by_type('Type_Parser'):
        set_typeargs(parser)


def resolve_type_name(hlir, typename_node):
    retval = resolve_type_name2(hlir, typename_node)
    if retval is None:
        # breakpoint()
        return None
    import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", retval])
    if retval.node_type == 'Type_Typedef':
        return retval
    # if 'type' in retval or 'type_ref' in retval:
    if retval.urtype.node_type == 'Type_Name':
        breakpoint()
    return retval

def resolve_type_name2(hlir, typename_node):
    # if 'name' not in typename_node.path:
    if typename_node.path.absolute:
        if (fld := typename_node.parent()).node_type == 'StructField':
            if fld.name == 'parser_error':
                return hlir.errors[0]
            else:
                # this is a metadata header
                results = hlir.news.meta.flatmap('fields').filter('name', fld.name)
                import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno} R1", results])
                if len(results) == 1:
                    import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno} single-isabs", results[0].type.path.absolute])
                    return results[0]

                results = results.filterfalse('type.path.absolute')
                typenames = unique_everseen(results.map('type.type_ref.name'))
                import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno} R2", results])
                import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno} R3", typenames])
                # if any(( (results[0].name, results[0].type.type_ref.name) != (r.name, r.type.type_ref.name) for r in results[1:] )):
                if len(typenames) > 1:
                    hdrname = typename_node.parents.filter(lambda n: n.node_type == 'Type_Struct')[0].name
                    typenames = ', '.join(typenames)
                    assert False, f'Metadata field {hdrname}.{fld.name} has conflicting types ({typenames})'
                return results[0]

    name = typename_node.path.name
    parents = typename_node.parents

    if (found := parents.filter('ConstructorCallExpression').filter(lambda n: n.constructedType == typename_node)):
        return found[0].type

    if (found := parents.filter('TypeNameExpression').filter(lambda n: n.typeName == typename_node)):
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


def attrs_resolve_types(hlir):
    """Resolve all Type_Name nodes to real type nodes"""

    for node in hlir.all_nodes.by_type('Type_Name'):
        resolved_type = resolve_type_name(hlir, node)
        assert resolved_type != node

        if resolved_type is None:
            if 'name' in node:
                addWarning('resolving type', f'Type name {node.name} could not be resolved')
            else:
                addWarning('resolving type', f'Type name {node} could not be resolved')
            continue

        if resolved_type.node_type == 'Type_Var':
            resolved_type = resolve_type_var(hlir, resolved_type)
            if resolved_type is None:
                # here, we have to suppose that the type name is unused
                # such as in T lookahead<T>() if the function is not called
                continue

        node.type_ref = resolved_type

    # TODO do it

def check_no_leftovers(base_node, leftover_nodes, node_description):
    if len(leftover_nodes) != 0:
        addError(f'visiting {node_description}s', f'{len(leftover_nodes)} {node_description}s of unexpected type found')
        import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:142 ERROR", f'{len(leftover_nodes)} {node_description}s of unexpected type found'])


def attrs_resolve_pathexprs(hlir):
    """Resolve all PathExpression nodes"""

    # TODO ez atkerult a masik helyre...

    # for pe in hlir.groups.pathexprs.action:
    #     import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:145 pe.hlir.action", pe])
    #     # breakpoint()

    # for pe in hlir.groups.pathexprs.io:
    #     import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:148 pe.hlir.io", pe])
    #     # breakpoint()

    for hexpr in hlir.groups.pathexprs.header:
        if hexpr.type.name in hlir.news.meta_types:
            hexpr.ref = hlir.allmetas
        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", hexpr])

    # for pe in hlir.groups.pathexprs.state:
    #     import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:154 pe.hlir.state", pe])
    #     # breakpoint()

    # for pe in hlir.groups.pathexprs.method:
    #     import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:157 pe.hlir.method", pe])
    #     # breakpoint()

    # for pe in hlir.groups.pathexprs.matchkind:
    #     import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:160 pe.hlir.matchkind", pe])
    #     # breakpoint()

    # for pe in hlir.groups.pathexprs.table:
    #     import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:163 pe.hlir.table", pe])
    #     # breakpoint()

    for mcexpr in hlir.groups.pathexprs.under_mcall:
        mname = mcexpr.path.name
        mcexpr.action_ref = hlir.controls.flatmap('controlLocals').get(mname)
        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", mcexpr])

    # for pe in hlir.groups.pathexprs.assign:
    #     import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:169 pe.hlir.assign", pe])
    #     breakpoint()

    pass


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
        "egress_meta_fld": "egress_spec",
        # from v1model.p4: "an implementation-specific special value that ... causes the packet to be dropped"
        "egress_drop_value": 100,
        "user_meta_var": "meta",
        "meta_types": ["standard_metadata_t"],
    },
    "PSA_Switch": {
        "egress_meta_fld": "egress_port",
        "egress_drop_value": "true",
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


def attrs_top_level(hlir, p4_version):
    dis = hlir.decl_instances

    hlir.news = P4Node({'node_type': 'SystemInfo'})
    hlir.news.p4v = p4_version
    hlir.news.main = dis.get(lambda main: main.arguments.map('expression')['PathExpression'].filter(lambda arg: dis.get(arg.path.name) is not None))
    if hlir.news.main is None:
        hlir.news.main = dis.get(lambda main: len(main.arguments.map('expression')['ConstructorCallExpression']) > 0)

    assert hlir.news.main is not None, 'Could not determine main entry point'

    hlir.news.model = hlir.news.main.urtype.path.name

    assert hlir.news.model is not None, 'Could not determine architecture model'
    assert hlir.news.model in model_specific_infos, f'Main belongs to unknown package {hlir.news.main}'

    infos = model_specific_infos[hlir.news.model]

    hlir.news.egress_meta_fld = infos['egress_meta_fld']
    hlir.news.egress_drop_value = infos['egress_drop_value']
    hlir.news.user_meta_var = infos['user_meta_var']
    hlir.news.meta_types = P4Node(infos['meta_types'])


def attrs_regroup_structs(hlir):
    structs = hlir.objects['Type_Struct']

    meta_type_names = hlir.news.meta_types
    hlir.news.meta = remove_nodes(structs.filter(lambda s: s.name in meta_type_names), hlir.objects)

    # TODO digest etc., amibol structot kell gyartani
    hlir.news.data = remove_nodes(hlir.objects['Type_Struct'], hlir.objects)
    hlir.news.misc = P4Node([]) # TODO ezek mire valok? kellenek ilyenek egyaltalan?

    assert (remaining := len(hlir.objects['Type_Struct'])) == 0, f'{remaining} structs are not identified'


def attrs_regroup_members(hlir):
    mes = hlir.all_nodes.by_type('Member')
    # TODO metadata refs
    # TODO fld refs

    hlir.groups.member_exprs = P4Node({'node_type': 'grouped'})
    mem_exprs = hlir.groups.member_exprs

    mem_methods = mes.filter('type.node_type', 'Type_Method')

    mem_path_members = mem_methods.filter(lambda m: 'member' in m)
    mem_path_methods = mem_methods.filter(lambda m: 'path' in m.expr)
    mem_path_pathexpressions = mes.filter('expr.node_type', 'PathExpression')

    hlir.groups.member_exprs.enums = remove_nodes(mes.filter('type.node_type', 'Type_Enum'), mes)
    hlir.groups.member_exprs.booleans = remove_nodes(mes.filter('type.node_type', 'Type_Boolean'), mes)
    hlir.groups.member_exprs.specialized_canonical = remove_nodes(mes.filter('expr.type.node_type', 'Type_SpecializedCanonical'), mes)

    hlir.groups.member_exprs.tables = remove_nodes(mem_path_methods.filter('expr.type.node_type', 'Type_Table'), mes)
    hlir.groups.member_exprs.externs = remove_nodes(mem_path_methods.filter('expr.type.node_type', 'Type_Extern'), mes)

    hlir.groups.member_exprs.headers = remove_nodes(mem_path_pathexpressions.filter('type.node_type', 'Type_Header'), mes)
    hlir.groups.member_exprs.bits = remove_nodes(mem_path_pathexpressions.filter('type.node_type', 'Type_Bits'), mes)
    # hlir.groups.member_exprs.methods = remove_nodes(mem_path_pathexpressions.filter('type.node_type', 'Type_Method'), mes)

    hlir.groups.member_exprs.members = remove_nodes(mem_methods.filter(lambda m: 'member' in m.expr), mes)
    hlir.groups.member_exprs.exprs = remove_nodes(mes.filter(lambda m: 'expr' in m.expr), mes)
    hlir.groups.member_exprs.under_mcall = remove_nodes(mes.filter(lambda m: m.parent().node_type == 'MethodCallExpression'), mes)

    check_no_leftovers(hlir.groups.member_exprs, mes, "member expression")

    # # ctl_param_structs = hlir.controls \
    # #     .flatmap('controlLocals') \
    # #     .filter('node_type', 'P4Action') \
    # #     .flatmap('body.components') \
    # #     .filter('node_type', 'MethodCallStatement') \
    # #     .flatmap('methodCall.arguments') \
    # #     .filter('expression.type.node_type', 'Type_Struct') \
    # #     .map('expression.type.name') \
    # #     .map(lambda ctl_param_name: structs.get(ctl_param_name))

    # is_miscs = [all(('name' in fld.urtype and hlir.headers.get(fld.urtype.name) for fld in hdr.fields)) for hdr in structs]
    # # is_miscs = [all((fldname:=fld.urtype('name')) and hlir.headers.get(fldname) for fld in hdr.fields) for hdr in structs]
    # miscs = [hdr for hdr, is_misc in zip(structs, is_miscs) if is_misc]
    # datas = [hdr for hdr, is_misc in zip(structs, is_miscs) if not is_misc if hdr in ctl_param_structs]
    # metas = [hdr for hdr, is_misc in zip(structs, is_miscs) if not is_misc if hdr not in ctl_param_structs]
    # # breakpoint()


    # make_node_group(hlir.news, 'misc', miscs, hlir.objects)
    # make_node_group(hlir.news, 'data', datas, hlir.objects)
    # make_node_group(hlir.news, 'meta', metas, hlir.objects)

    # TODO remove this
    hlir.object_groups = P4Node([
        hlir.control_types,
        hlir.controls,
        hlir.decl_instances,
        hlir.decl_matchkinds,
        hlir.enums,
        hlir.errors,
        hlir.externs,
        hlir.headers,
        hlir.methods,
        hlir.packages,
        hlir.parsers,
        hlir.typedefs,
        hlir.type_parsers,

        # hlir.news.misc,
        # hlir.news.data,
        hlir.news.meta,
    ])




def make_node_group(target, new_group_name, nodes, origin = None):
    """Move the selected nodes from a vector node into a new attribute of the target node.
    The grouped nodes are removed from the origin node if it is given."""
    new_node = P4Node(nodes)
    target.set_attr(new_group_name, new_node)
    if origin is not None:
        for node in nodes:
            origin.vec.remove(node)


def clear_hlir_objects(hlir):
    """At this point, all nodes have been moved from hlir.objects.vec
    into separate attributes of hlir.
    Remove the unnecessary node."""
    if len(hlir.objects) != 0:
        addError('cleaning up', f'{len(hlir.objects)} unexpected nodes found in hlir.objects')

    hlir.remove_attr('objects')


def remove_nodes(nodes, parent):
    for node in nodes:
        assert node in parent, f'Node {node} could not be removed from {parent}'

        parent.vec.remove(node)
    return nodes


def attrs_regroup_path_expressions(hlir):
    """Makes hlir attributes for distinct kinds of structs."""

    # TODO remove?
    # ops1 = ' '.split(list(simple_binary_ops.keys()))
    # arithmetic_types = unique_everseen(list(' '.split(simple_binary_ops.keys())) + list(' '.split(complex_binary_ops.keys())))

    pes = hlir.all_nodes.by_type('PathExpression')

    hlir.groups.pathexprs = P4Node({'node_type': 'grouped'})

    hlir.groups.pathexprs.action = remove_nodes(pes.filter('type.node_type', 'Type_Action'), pes)
    hlir.groups.pathexprs.io = remove_nodes(pes.filter('type.node_type', 'Type_Extern'), pes)
    hlir.groups.pathexprs.header = remove_nodes(pes.filter('type.node_type', 'Type_Struct'), pes)
    hlir.groups.pathexprs.state = remove_nodes(pes.filter('type.node_type', 'Type_State'), pes)
    hlir.groups.pathexprs.method = remove_nodes(pes.filter('type.node_type', 'Type_Method'), pes)
    hlir.groups.pathexprs.matchkind = remove_nodes(pes.filter('type.node_type', 'Type_MatchKind'), pes)
    hlir.groups.pathexprs.table = remove_nodes(pes.filter('type.node_type', 'Type_Table'), pes)
    hlir.groups.pathexprs.boolean = remove_nodes(pes.filter('type.node_type', 'Type_Boolean'), pes)
    hlir.groups.pathexprs.specialized_canonical = remove_nodes(pes.filter('type.node_type', 'Type_SpecializedCanonical'), pes)
    hlir.groups.pathexprs.package = remove_nodes(pes.filter('type.node_type', 'Type_Package'), pes)
    hlir.groups.pathexprs.bits = remove_nodes(pes.filter('type.node_type', 'Type_Bits'), pes)
    hlir.groups.pathexprs.arithmetic = remove_nodes(pes.filter(lambda m: (op := m.parent().node_type) in simple_binary_ops or op in complex_binary_ops), pes)

    hlir.groups.pathexprs.under_mcall = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'MethodCallExpression'), pes)
    breakpoint()
    hlir.groups.pathexprs.under_assign = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'AssignmentStatement'), pes)
    hlir.groups.pathexprs.under_keyelement = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'KeyElement'), pes)
    hlir.groups.pathexprs.under_member = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'Member'), pes)

    check_no_leftovers(hlir.groups.pathexprs, pes, "path expression")



def attrs_regroup_attrs(hlir):
    """Groups hlir objects by their types into hlir attributes."""

    hlir.groups = P4Node({'node_type': 'groups'})

    groups = [
        ('control_types', 'Type_Control'),
        ('controls', 'P4Control'),
        ('decl_instances', 'Declaration_Instance'),
        ('decl_matchkinds', 'Declaration_MatchKind'),
        ('enums', 'Type_Enum'),
        ('errors', 'Type_Error'),
        ('externs', 'Type_Extern'),
        ('headers', 'Type_Header'),
        ('methods', 'Method'),
        ('packages', 'Type_Package'),
        ('parsers', 'P4Parser'),
        # note: structs are separated using group_structs()
        # ('structs', 'Type_Struct'),
        ('typedefs', 'Type_Typedef'),
        ('type_parsers', 'Type_Parser'),
        ]

    for new_group_name, node_type_name in groups:
        make_node_group(hlir, new_group_name, hlir.objects[node_type_name], hlir.objects)



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

def parser_or_control_parent(node):
    return [parent for parent in node.node_parents[0] if parent.node_type in ('P4Control', 'P4Parser')][0]

def metafld_name(hdr, fldname, ctr):
    return f'{ctr.name}_{hdr.name}_{fldname}' if ctr else f"{hdr.name}_{re.sub(r'_t$', '', hdr.name)}"

def make_metafld(hdr, fld, fldname, ctr):
    metafld = P4Node({'node_type': 'StructField'})
    metafld.name = fldname or metafld_name(hdr, fldname, ctr)
    metafld.type = fld.type

    metafld.type.path = P4Node({'node_type': 'Path'})
    metafld.type.path.absolute = True

    metafld.orig_hdr = hdr
    metafld.orig_fld = fld
    if ctr:
        metafld.orig_ctr = ctr

    return metafld


def attrs_header_refs_in_parser_locals(hlir):
    """Temporary header references in parser locals"""

    def is_tmp_header_inst(local):
        return local.name.startswith('tmp_')

    return P4Node([local for parser in hlir.parsers for local in parser.parserLocals if is_tmp_header_inst(local)])


def set_header_meta_preparsed(hdr, is_meta_preparsed):
    hdr.urtype.is_metadata = is_meta_preparsed
    import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", hdr])
    import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", hdr.urtype])
    if 'path' not in hdr.urtype or not hdr.urtype.path.absolute:
        for fld in hdr.urtype.fields:
            fld.preparsed = is_meta_preparsed


def check_meta_fields(fldinfos):
    # TODO the same name/type combo can appear in several controls, currently treating them as one unified unit
    # allmeta_flds = [make_metafld(hdr, fld, fldname, ctr) for hdr, fldname, ctr in metadata_infos for fld in hdr.fields]

    count = Counter(fldinfos)
    for name, typename in count:
        if count[(name, typename)] > 1:
            def fld_urtype_info(fld):
                if fld.type == fld.urtype:
                    return f'{fld.type.name}'
                return f'{fld.type.name} (aka {fld.urtype.name})'
            typeinfos = ''.join((f'    - {fld.name}: {fld_urtype_info(fld)}\n' for fldname, fldtype in fldinfos))
            addError('getting metadata', f'The name {name} appears in {count[(name, typename)]} metadata fields with different types:\n{typeinfos}')

def make_allmetas_node(hlir):
    fldinfos = unique_everseen([(fld.name, fld.urtype) for hdr in hlir.news.meta for fld in hdr.fields])

    check_meta_fields(fldinfos)

    fldname_to_hdrfield = {fld.name: (hdr, fld) for hdr in hlir.news.meta for fld in hdr.fields}
    allmeta_flds = [make_metafld(hdr, fld, fld.name, None) for fldname in fldname_to_hdrfield for hdr, fld in [fldname_to_hdrfield[fldname]]]

    allmetas = P4Node({'node_type': 'StructField'})
    allmetas.name = 'all_metadatas'
    allmetas.type = P4Node({'node_type': 'Type_Name'})
    allmetas.type.path = P4Node({'node_type': 'Path'})
    allmetas.type.path.absolute = True

    allmetas_t = P4Node({'node_type': 'Type_Header'})
    allmetas_t.name = 'all_metadatas_t'
    allmetas_t.fields = P4Node(allmeta_flds)

    allmetas.type.type_ref = allmetas_t


    return allmetas


def attrs_hdr_metadata_insts(hlir):
    """Metadata instances and header instances"""

    hlir.allmetas = make_allmetas_node(hlir)
    insts = hlir.news.data.flatmap('fields') + attrs_header_refs_in_parser_locals(hlir)

    for inst in insts:
        if not inst.type.path.absolute:
            inst.type.type_ref = hlir.headers.get(inst.type.path.name)

    set_header_meta_preparsed(hlir.allmetas, True)
    for hdr in insts:
        set_header_meta_preparsed(hdr, False)

    hlir.headers.append(hlir.allmetas.urtype)

    hlir.header_instances = P4Node(insts + [hlir.allmetas])


def dlog(num, base=2):
    """Returns the discrete logarithm of num.
    For the standard base 2, this is the number of bits required to store the range 0..num."""
    return [n for n in range(32) if num < base**n][0]


def attrs_add_enum_sizes(hlir):
    """Types that have members do not have a proper size (bit width) as we get it.
    We need to compute them by hand."""

    breakpoint()
    # for fld in hlir.header_instances.map('urtype').filter('node_type', 'Type_Header').flatmap('fields'):
    # for fld in hlir.header_instances.map('urtype').filter('node_type', ('Type_Error', 'Type_Enum')).flatmap('fields'):
    for fldt in hlir.enums.map('urtype'):
        fldt.size = dlog(len(fldt.members))
        # TODO is this not needed?
        # fldt.preparsed = True
        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", fldt.urtype])

    for fldt in hlir.errors.map('urtype'):
        fldt.size = dlog(len(fldt.members))


def attrs_header_types_add_attrs(hlir):
    """Collecting header types, part 2"""

    for hdrt in hlir.header_instances.map('urtype').filter(lambda hdrt: 'name' in hdrt):
        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", hdrt])
        hdrt.id = f'HDR({hdrt.name})'
        offset = 0

        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", hdrt])
        for idx, (ff,tt) in enumerate(zip(hdrt.fields, hdrt.fields.map('urtype'))):
            import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", idx, ff, tt, 'size' not in tt])
        if hdrt.name == 'all_metadatas_t':
            breakpoint()
        hdrt.size = sum((fld.urtype.size for fld in hdrt.fields))
        hdrt.byte_width = (hdrt.size+7) // 8

        for f in hdrt.fields:
            tref = f.urtype

            if 'name' in f:
                f.id = f'FLD({hdrt.name},{f.name})'
            # TODO bit_offset, byte_offset, mask
            f.offset = offset
            f.size = tref.size
            f.is_vw = (tref.node_type == 'Type_Varbits') # 'Type_Bits' vs. 'Type_Varbits'

            offset += f.size

        hdrt.is_vw = any(hdrt.fields.map('is_vw'))

    for hdr in hlir.header_instances:
        hdr.id = re.sub(r'\[([0-9]+)\]', r'_\1', f"HDR({hdr.name})")


table_key_match_order = ['exact', 'lpm', 'ternary']


def set_table_key_attrs(hlir, table):
    # TODO remove debug info
    for k in table.key.keyElements:
        expr = k.expression.expr
        for gname in ["action", "bits", "header", "io", "matchkind", "method", "specialized_canonical", "state", "table", "under_mcall", "under_member"]:
            if expr in hlir.groups.pathexprs.get_attr(gname):
                import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno} --> hlir.groups.pathexprs.{gname}", expr])
                break

    for k in table.key.keyElements:
        expr = k.expression.expr
        if not expr:
            # the key element is a local variable in a control
            k.size = table.control.controlLocals.get(k.expression.path.name).urtype.size
            import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", k.size])
            continue

        k.match_order = table_key_match_order.index(k.matchType.path.name)

        import inspect; import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint([f"hlir_attrs.py@{inspect.getframeinfo(inspect.currentframe()).lineno}", expr])

        # supposing that k.expression is of form '<header_name>.<name>'
        if expr.node_type == 'PathExpression':
            k.header_name = expr.ref.name
            k.field_name = k.expression.member
        # supposing that k.expression is of form 'hdr.<header_name>.<name>'
        elif expr.node_type == 'Member':
            k.header_name = expr.member
            k.field_name = k.expression.member
        else:
            addWarning("Table key analysis", "Key not found")

        k.id = f'FLD({k.header_name},{k.field_name})'
        k.header = hlir.header_instances.get(k.header_name)
        if k.header is None and (fld := hlir.allmetas.urtype.fields.get(k.field_name)):
            k.header = hlir.allmetas
            k.size = fld.size

        if 'size' not in k:
            breakpoint()
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


def attrs_controls_tables(hlir):
    for c in hlir.controls:
        c.tables = P4Node(c.controlLocals['P4Table'])
        for t in c.tables:
            t.control = c
        c.actions = P4Node(c.controlLocals['P4Action'])

    main = hlir.news.main
    pipeline_elements = main.arguments

    hlir.tables = P4Node([table for ctrl in hlir.controls for table in ctrl.tables])

    for table in hlir.tables:
        for prop in table.properties.properties:
            table.set_attr(prop.name, prop.value)
        table.remove_attr('properties')

    package_name = hlir.news.model

    for ctl in hlir.controls:
        for table in ctl.tables:
            for act in table.actions.actionList:
                act.action_object = table.control.actions.get(act.expression.method.path.name)

            table.actions = P4Node(table.actions.actionList)
            add_attr_named_actions(table)

    # keyless tables are turned into empty-key tables
    for table in hlir.tables:
        if 'key' not in table:
            table.key = P4Node({'node_type': 'Key'})
            table.key.keyElements = P4Node([])

    for table in hlir.tables:
        table.matchType = get_table_match_type(table)

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
        breakpoint()
        raise NotImplementedError(f"Some headers ({', '.join(stacks.map('name'))}) are header stacks which are currently not supported")

    for member in members.headers:
        mexpr = member.expr
        mtype = mexpr.urtype
        mname = member.member
        tname = member.type.name

        member.header_ref = hlir.header_instances.filter('urtype.name', tname).get(mname)
        mexpr.header_ref = member.header_ref

    for member in members.members:
        mexpr = member.expr
        mtype = mexpr.urtype
        mname = member.member
        breakpoint()


        # hdr, fld = [(hdr, fld) for hdr in hlir.news.meta for fld in hdr.fields if fld.name == member.expr.member if 'name' in fld.urtype and (name := fld.urtype.name) == mtype.name][0]

        member.header_ref = hlir.headers.get(mtype.name)
        member.field_ref = member.header_ref.fields.get(mname)

        mexpr.header_ref = member.header_ref
        mexpr.field_ref = member.field_ref


# def attrs_add_metadata_refs(hlir):
#     for expr in hlir.all_nodes.by_type('PathExpression'):
#         if expr.path.name == 'standard_metadata':
#             expr.header_ref = hlir.allmetas
#             expr.type = hlir.allmetas
#         else:
#             import pprint; pprint.PrettyPrinter(indent=4,width=999,compact=True).pprint(["hlir_attrs.py:621 expr", expr])
#     breakpoint()

#     for expr in hlir.all_nodes.by_type('Member'):
#         if expr('header_ref.name') == 'metadata':
#             _, metaname = get_meta_instance(hlir, expr.member)
#             expr.header_ref = hlir.allmetas
#             expr.field_name = metaname

#     for ke in hlir.all_nodes.by_type('KeyElement'):
#         if ke('header_name') == 'meta':
#             _, metaname = get_meta_instance(hlir, ke.field_name)
#             ke.header_ref = hlir.allmetas
#             ke.field_name = metaname


# def attrs_field_refs_in_exprs(hlir):
#     """Field references in expressions"""

#     for member in hlir.all_nodes.by_type('Member'):
#         if 'path' in member.expr and member.expr.path.name == 'standard_metadata':
#             member.field_ref = hlir.news.meta.get('standard_metadata_t').fields.get('egress_port', 'StructField')
#             continue

#         if 'header_ref' not in member.expr:
#             continue
#         if member.expr.header_ref is None:
#             continue

#         ref = member.expr.header_ref.urtype.fields.get(member.member, 'StructField')

#         if ref is not None:
#             member.field_ref = ref


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
    return [r for r in hlir.decl_instances if r.type.baseType.path.name == 'register']


# In v1model, all software memory cells are represented as 32 bit integers
def smem_repr_type(smem):
    tname = "int" if smem.is_signed else "uint"

    for w in [8,16,32,64]:
        if smem.size <= w:
            return f"register_{tname}{w}_t"

    return "NOT_SUPPORTED"


def smem_components(smem):
    smem.size = smem.type.arguments[0].size if smem.smem_type == "register" else 32
    smem.is_signed = smem.type.arguments[0].isSigned if smem.smem_type == "register" else False
    if smem.smem_type not in ["direct_counter", "direct_meter"]:
        smem.amount = smem.arguments['Argument'][0].expression.value

    base_type = smem_repr_type(smem)

    if smem.smem_type == 'register':
        return [{"type": base_type, "name": smem.name}]

    member = [s.expression for s in smem.arguments if s.expression.node_type == 'Member'][0]

    # TODO set these in hlir_attrs
    smem.packets_or_bytes = member.member
    smem.smem_for = {
        "packets": smem.packets_or_bytes in ("packets", "packets_and_bytes"),
        "bytes":   smem.packets_or_bytes in (  "bytes", "packets_and_bytes"),
    }

    pkts_name  = f"{smem.smem_type}_{smem.name}_packets"
    bytes_name = f"{smem.smem_type}_{smem.name}_bytes"

    pbs = {
        "packets":           [{"for": "packets", "type": base_type, "name": pkts_name}],
        "bytes":             [{"for":   "bytes", "type": base_type, "name": bytes_name}],

        "packets_and_bytes": [{"for": "packets", "type": base_type, "name": pkts_name},
                              {"for":   "bytes", "type": base_type, "name": bytes_name}],
    }

    return pbs[smem.packets_or_bytes]


def attrs_stateful_memory(hlir):
    # direct counters
    for table in hlir.tables:
        table.direct_meters    = P4Node(unique_list([m for t, m in get_smems('direct_meter', [table])]))
        table.direct_counters  = P4Node(unique_list([c for t, c in get_smems('direct_counter', [table])]))

    # indirect counters
    hlir.meters    = P4Node(unique_list(get_smems('meter', hlir.tables)))
    hlir.counters  = P4Node(unique_list(get_smems('counter', hlir.tables)))
    hlir.registers = P4Node(unique_list(get_registers(hlir)))

    hlir.all_meters   = P4Node(unique_list(hlir.meters   + [(t, m) for t in hlir.tables for m in t.direct_meters]))
    hlir.all_counters = P4Node(unique_list(hlir.counters + [(t, c) for t in hlir.tables for c in t.direct_counters]))

    for _table, smem in hlir.all_meters + hlir.all_counters:
        smem.smem_type  = smem.type._baseType.path.name
        smem.components = smem_components(smem)
    for smem in hlir.registers:
        smem.smem_type  = smem.type._baseType.path.name
        smem.components = smem_components(smem)


def attrs_typedef(hlir):
    for typedef in hlir.all_nodes.by_type('Type_Typedef'):
        if 'size' in typedef:
            continue

        if 'type_ref' not in typedef.type:
            typedef.size = typedef.type.size
        elif 'size' in typedef.urtype:
            typedef.size = typedef.urtype.size


# def attrs_add_meta_field(hlir, metainst_type, name, size):
#     """P4 documentation suggests using magic numbers as egress ports:
#     const PortId DROP_PORT = 0xF;
#     As these constants do not show up in the JSON representation,
#     they cannot be present in HLIR.
#     This function is used to add the 'drop' field to the standard_metadata header as a temporary fix.
#     Other required, but not necessarily present fields can be added as well."""

#     if metainst_type.fields.get(name) is not None:
#         return

#     new_field           = P4Node({'node_type': 'StructField'})
#     new_field.name      = name
#     new_field.annotations = P4Node({'node_type': 'Annotations'})
#     new_field.annotations.annotations = P4Node([])
#     new_field.type      = P4Node({'node_type': 'Type_Bits'})
#     new_field.type.isSigned  = False
#     new_field.type.size      = size

#     metainst_type.fields.append(new_field)



def default_attr_funs(p4_version):
    return [
        attrs_regroup_attrs,
        lambda hlir: attrs_top_level(hlir, p4_version),
        attrs_regroup_structs,
        attrs_regroup_members,
        attrs_regroup_path_expressions,
        clear_hlir_objects,

        attrs_hdr_metadata_insts,

        attrs_type_boolean,
        attrs_annotations,
        attrs_typeargs,

        attrs_resolve_members,
        attrs_resolve_types,

        attrs_member_naming,
        # lambda hlir: attrs_add_meta_field(hlir, hlir.news.meta.get('standard_metadata_t'), "drop", 1),
        # lambda hlir: attrs_add_meta_field(hlir, hlir.news.meta.get('standard_metadata_t'), "egress_spec", 32),

        attrs_add_enum_sizes,
        attrs_header_types_add_attrs,

        attrs_resolve_pathexprs,

        attrs_controls_tables,
        attrs_extract_nodes,
        attrs_header_refs_in_exprs,
        # attrs_field_refs_in_exprs,
        attrs_stateful_memory,
        attrs_typedef,
        # attrs_add_metadata_refs,
    ]

def set_additional_attrs(hlir, p4_version, additional_attr_funs = None):
    for attrfun in additional_attr_funs or default_attr_funs(p4_version):
        attrfun(hlir)

    breakpoint()

    return hlir
