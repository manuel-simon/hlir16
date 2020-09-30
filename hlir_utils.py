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
