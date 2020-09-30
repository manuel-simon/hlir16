# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node
from hlir16.hlir_utils import make_node_group
from compiler_common import unique_everseen


def remove_nodes(nodes, parent):
    for node in nodes:
        assert node in parent, f'Node {node} could not be removed from {parent}'

        parent.vec.remove(node)
    return nodes


def check_no_leftovers(base_node, leftover_nodes, node_description):
    if len(leftover_nodes) != 0:
        addError(f'visiting {node_description}s', f'{len(leftover_nodes)} {node_description}s of unexpected type found')


def regroup_attrs(hlir):
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
        # note: structs are separated using attrs_regroup_structs()
        # ('structs', 'Type_Struct'),
        ('typedefs', 'Type_Typedef'),
        ('type_parsers', 'Type_Parser'),
        ]

    for new_group_name, node_type_name in groups:
        make_node_group(hlir, new_group_name, hlir.objects[node_type_name], hlir.objects)


def attrs_regroup_structs(hlir):
    structs = hlir.objects['Type_Struct']

    act_param_types = hlir.all_nodes.by_type('P4Control').flatmap('controlLocals').filter('node_type', 'P4Action').flatmap('parameters.parameters').filter('type.node_type', 'Type_Name').map('type.type_ref')

    metas_by_varname = hlir.all_nodes.by_type('PathExpression').filter('type.node_type', 'Type_Struct').filter('path.name', hlir.news.user_meta_var).map('type.name')
    param_metas = hlir.all_nodes.by_type('Parameter').filter('name', hlir.news.user_meta_var).map('urtype').filter('node_type', 'Type_Struct').map('name')

    meta_type_names = unique_everseen(hlir.news.meta_types + metas_by_varname + param_metas)

    hlir.news.meta = remove_nodes(structs.filter(lambda s: s.name in meta_type_names), hlir.objects)
    hlir.news.data = remove_nodes(hlir.objects['Type_Struct'], hlir.objects)

    assert (remaining := len(hlir.objects['Type_Struct'])) == 0, f'{remaining} structs are not identified'


def attrs_regroup_members(hlir):
    mes = hlir.all_nodes.by_type('Member')

    hlir.groups.member_exprs = P4Node({'node_type': 'grouped'})
    mem_exprs = hlir.groups.member_exprs

    mem_methods = mes.filter('type.node_type', 'Type_Method')

    mem_path_members = mem_methods.filter(lambda m: 'member' in m)
    mem_path_methods = mem_methods.filter(lambda m: 'path' in m.expr)
    mem_path_pathexpressions = mes.filter('expr.node_type', 'PathExpression')

    hlir.groups.member_exprs.enums = remove_nodes(mes.filter('type.node_type', 'Type_Enum'), mes)
    hlir.groups.member_exprs.booleans = remove_nodes(mes.filter('type.node_type', 'Type_Boolean'), mes)
    hlir.groups.member_exprs.errors = remove_nodes(mes.filter('type.node_type', 'Type_Error'), mes)
    hlir.groups.member_exprs.action_enums = remove_nodes(mes.filter('type.node_type', 'Type_ActionEnum'), mes)
    hlir.groups.member_exprs.header_stacks = remove_nodes(mes.filter('type.node_type', 'Type_Stack'), mes)

    hlir.groups.member_exprs.indexed_header_stack = remove_nodes(mes.filter('expr.node_type', 'ArrayIndex'), mes)

    hlir.groups.member_exprs.specialized_canonical = remove_nodes(mes.filter('expr.type.node_type', 'Type_SpecializedCanonical'), mes)
    hlir.groups.member_exprs.tables = remove_nodes(mem_path_methods.filter('expr.type.node_type', 'Type_Table'), mes)
    hlir.groups.member_exprs.externs = remove_nodes(mem_path_methods.filter('expr.type.node_type', 'Type_Extern'), mes)

    hlir.groups.member_exprs.headers = remove_nodes(mem_path_pathexpressions.filter('type.node_type', 'Type_Header'), mes)
    hlir.groups.member_exprs.structs = remove_nodes(mem_path_pathexpressions.filter('type.node_type', 'Type_Struct'), mes)
    hlir.groups.member_exprs.bits = remove_nodes(mem_path_pathexpressions.filter('type.node_type', 'Type_Bits'), mes)
    hlir.groups.member_exprs.varbits = remove_nodes(mem_path_pathexpressions.filter('type.node_type', 'Type_Varbits'), mes)

    hlir.groups.member_exprs.members = remove_nodes(mem_methods.filter(lambda m: 'member' in m.expr), mes)
    hlir.groups.member_exprs.exprs = remove_nodes(mes.filter(lambda m: 'expr' in m.expr), mes)
    hlir.groups.member_exprs.under_mcall = remove_nodes(mes.filter(lambda m: m.parent().node_type == 'MethodCallExpression'), mes)

    check_no_leftovers(hlir.groups.member_exprs, mes, "member expression")

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

        hlir.news.data,
        hlir.news.meta,
    ])


def attrs_regroup_path_expressions(hlir):
    """Makes hlir attributes for distinct kinds of structs."""

    pes = hlir.all_nodes.by_type('PathExpression')

    hlir.groups.pathexprs = P4Node({'node_type': 'grouped'})

    hlir.groups.pathexprs.under_mcall = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'MethodCallExpression'), pes)
    hlir.groups.pathexprs.under_assign = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'AssignmentStatement'), pes)
    hlir.groups.pathexprs.under_keyelement = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'KeyElement'), pes)

    hlir.groups.pathexprs.extern_under_member = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'Member' and m.type.node_type == 'Type_Extern'), pes)

    hlir.groups.pathexprs.under_header = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'Member' and m.parent().type.node_type == 'Type_Header'), pes)
    hlir.groups.pathexprs.under_unknown = remove_nodes(pes.filter(lambda m: m.parent().node_type == 'Member' and m.parent().type.node_type == 'Type_Unknown'), pes)

    hlir.groups.pathexprs.action = remove_nodes(pes.filter('type.node_type', 'Type_Action'), pes)
    hlir.groups.pathexprs.io = remove_nodes(pes.filter('type.node_type', 'Type_Extern'), pes)
    hlir.groups.pathexprs.header = remove_nodes(pes.filter('type.node_type', 'Type_Header'), pes)
    hlir.groups.pathexprs.struct = remove_nodes(pes.filter('type.node_type', 'Type_Struct'), pes)
    hlir.groups.pathexprs.state = remove_nodes(pes.filter('type.node_type', 'Type_State'), pes)
    hlir.groups.pathexprs.method = remove_nodes(pes.filter('type.node_type', 'Type_Method'), pes)
    hlir.groups.pathexprs.matchkind = remove_nodes(pes.filter('type.node_type', 'Type_MatchKind'), pes)
    hlir.groups.pathexprs.table = remove_nodes(pes.filter('type.node_type', 'Type_Table'), pes)
    hlir.groups.pathexprs.boolean = remove_nodes(pes.filter('type.node_type', 'Type_Boolean'), pes)
    hlir.groups.pathexprs.specialized_canonical = remove_nodes(pes.filter('type.node_type', 'Type_SpecializedCanonical'), pes)
    hlir.groups.pathexprs.package = remove_nodes(pes.filter('type.node_type', 'Type_Package'), pes)
    hlir.groups.pathexprs.bits = remove_nodes(pes.filter('type.node_type', 'Type_Bits'), pes)
    hlir.groups.pathexprs.varbits = remove_nodes(pes.filter('type.node_type', 'Type_Varbits'), pes)

    hlir.groups.pathexprs.arithmetic = remove_nodes(pes.filter(lambda m: (op := m.parent().node_type) in simple_binary_ops or op in complex_binary_ops), pes)

    check_no_leftovers(hlir.groups.pathexprs, pes, "path expression")


def finish_regroup(hlir):
    """At this point, all nodes have been moved from hlir.objects.vec
    into separate attributes of hlir.
    Remove the unnecessary node."""
    if len(hlir.objects) != 0:
        addError('cleaning up', f'{len(hlir.objects)} unexpected nodes found in hlir.objects')

    hlir.remove_attr('objects')
