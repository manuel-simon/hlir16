# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node


def make_node_group(target, new_group_name, nodes, origin = None):
    """Move the selected nodes from a vector node into a new attribute of the target node.
    The grouped nodes are removed from the origin node if it is given."""
    new_node = P4Node(nodes)
    target.set_attr(new_group_name, new_node)
    if origin is not None:
        for node in nodes:
            origin.vec.remove(node)


def align8_16_32(size):
    return 8 if size <= 8 else 16 if size <= 16 else 32


def unique_list(l):
    return list(set(l))


def shorten_locvar_names(locvars, last_infix='_'):
    # locs = locvars.filter(lambda loc: 'type_ref' not in loc.type)
    locs = locvars

    locvars_in_order = all(loc.name.endswith(f'{last_infix}{idx}') for idx, loc in enumerate(locs))
    no_dups = len(set(loc.name[:-len(f'{last_infix}{idx}')] for idx, loc in enumerate(locs))) == len(locs)

    can_shorten = locvars_in_order and no_dups

    for idx, loc in enumerate(locs):
        no_postfix = loc.name[:-len(f'{last_infix}{idx}')]
        if not can_shorten:
            loc.short_name = loc.name
        elif no_postfix.startswith('_'):
            loc.short_name = '.'.join(no_postfix.split('_')[1:]) if can_shorten else loc.name
        else:
            loc.short_name = no_postfix if can_shorten else loc.name
