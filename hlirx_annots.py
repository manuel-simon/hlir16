# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2020 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node, deep_copy

def copy_arg(arg):
    if arg.is_vec():
        return P4Node(arg.vec)

    node = P4Node({'node_type': 'Parameter'})
    node.type        = arg.type
    node.name        = f"{postfix}_extra_param"
    node.direction   = 'in'
    node.annotations = []
    return node

def apply_annots(postfix, annots, expr):
    extra_args = annots.map('expr')

    mcall = expr.methodCall
    method = mcall.method

    method.decl_ref = deep_copy(method.action_ref, on_error=lambda node_id: addError('transforming hlir', f'Recursion found during deep-copy on node {node_id}'))
    method.decl_ref.name += f"_{postfix}"
    method.decl_ref.type.parameters.parameters.vec += extra_args.map(copy_arg)
    del method.decl_ref.type.parameters.parameters.vec[:2]

    method.path.name += f"_{postfix}"
    mcall.arguments.vec += extra_args
    del expr.methodCall.arguments.vec[:2]


def search_for_annotations(stmt):
    optimization_annots = ('offload', 'atomic')

    annots = stmt.annotations.annotations.filter('name', optimization_annots)
    if annots == []:
        return

    name = '_'.join(annots.map('name'))
    for expr in stmt.components.filter('methodCall.method.node_type', "PathExpression"):
        apply_annots(name, annots, expr)


def copy_annots(hlir):
    pipeline_elements = hlir.news.main.arguments

    for pe in pipeline_elements:
        if (ctl := hlir.controls.get(pe.expression.type.name)) is not None:
            for comp in ctl.body.components.filter('node_type', "BlockStatement"):
                search_for_annotations(comp)
