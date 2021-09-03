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
    """Copies the method call"""
    copy_error = lambda node_id: addError('transforming hlir', f'Recursion found during deep-copy on node {node_id}')

    mcall = expr.methodCall
    method = mcall.method

    method.action_ref = deep_copy(method.action_ref, on_error=copy_error)
    method.type       = deep_copy(method.type, on_error=copy_error)

    method.action_ref.name += f"_{postfix}"
    method.path.name       += f"_{postfix}"
    method.type.name       += f"_{postfix}"


    mapars = method.action_ref.type.parameters.parameters
    mtpars = method.type.parameters.parameters
    mcargs = mcall.arguments

    extra_args = annots.flatmap('expr')
    mapars.vec += extra_args.map(copy_arg)
    # TODO is using deep_copy OK in all cases, or is a separate method like copy_arg needed?
    mtpars.vec += extra_args.map('type').map(deep_copy)
    mcargs.vec += extra_args

    # remove "checksum"
    del mapars.vec[2]
    del mtpars.vec[2]
    del mcargs.vec[2]

    # remove "condition"
    del mapars.vec[0]
    del mtpars.vec[0]
    del mcargs.vec[0]

    # kept params: data, algo


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
