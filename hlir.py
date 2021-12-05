#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2017-2020 Eotvos Lorand University, Budapest, Hungary


import json
import subprocess
import os
import os.path
import tempfile

from hlir16.p4node import P4Node
from hlir16.hlir_attrs import set_additional_attrs


def has_method(obj, method_name):
    return hasattr(obj, method_name) and callable(getattr(obj, method_name))


def walk_json(node, fun, nodes, skip_elems=['Node_Type', 'Node_ID', 'Source_Info'], node_parent_chain=[]):
    rets = []
    if type(node) is dict or type(node) is list:
        node_id = node['Node_ID']
        if node_id not in nodes:
            nodes[node_id] = P4Node({
                'Node_ID': node_id,
                'node_type': '(incomplete_json_data)',
                'node_parents': [node_parent_chain],
            })

        if 'vec' in node.keys():
            elems = [(None, elem) for elem in node['vec']]
        else:
            elems = [(key, node[key]) for key in node.keys() if key not in skip_elems]
        rets = [(key, walk_json(elem, fun, nodes, skip_elems, node_parent_chain + [nodes[node_id]])) for (key, elem) in elems if elem != {}]

    return fun(node, rets, nodes, skip_elems, node_parent_chain)


def p4node_creator(node, elems, nodes, skip_elems, node_parent_chain):
    if not isinstance(node, (dict, list)):
        # note: types: string, bool, int
        return node

    node_id = node['Node_ID']
    p4node = nodes[node_id]

    p4node.id = node_id
    p4node.json_data = node

    if node_parent_chain not in p4node.node_parents:
        p4node.node_parents += [node_parent_chain]

    if 'Node_Type' in node.keys():
        p4node.node_type = node['Node_Type']
        # p4node.remove_attr('incomplete_json_data')

    if 'vec' in node.keys():
        no_key_elems = [elem for key, elem in elems]
        nodes[node_id].set_vec(no_key_elems)
    else:
        for key, subnode in elems:
            nodes[node_id].set_attr(key, subnode)

    return nodes[node_id]


def walk_json_from_top(node, fun=p4node_creator):
    nodes = {}
    hlir = walk_json(node, fun, nodes)
    hlir.all_nodes = P4Node({'node_type': 'all_nodes'}, [nodes[idx] for idx in nodes.keys()])
    return hlir


def p4_to_json(p4_filename, json_filename=None, p4_version=16, p4c_path=None, opts=[]):
    filename, ext = os.path.splitext(p4_filename)

    if json_filename is None:
        json_filename = f'{filename}.json'

    if p4c_path is None:
        p4c_path = os.environ['P4C']

    if p4_version is None:
        ext_to_vsn = {
            'p4': 16,
            'p4_14': 14,
        }

        p4_version = ext_to_vsn[ext] if ext in ext_to_vsn else 16

    p4test = os.path.join(p4c_path, "build", "p4test")
    p4include = os.path.join(p4c_path, "p4include")

    version_opts = ['--p4v', f'{p4_version}'] if p4_version is not None else []
    for opt in opts:
        version_opts += ['-D', opt]

    base_cmd = f'{p4test} {p4_filename} --toJSON {json_filename} --Wdisable=unused'.split(' ')
    errcode = subprocess.call(base_cmd + version_opts)

    return json_filename if errcode == 0 else None
