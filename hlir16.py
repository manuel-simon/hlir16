#!/usr/bin/env python

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

import json
import subprocess
import os
import tempfile
from p4node import P4Node


def has_method(obj, method_name):
    return hasattr(obj, method_name) and callable(getattr(obj, method_name))


def walk_json(node, fun, nodes, skip_elems=['Node_Type', 'Node_ID']):
    rets = []
    if type(node) is dict or type(node) is list:
        if 'vec' in node.keys():
            elems = [(None, elem) for elem in node['vec']]
        else:
            elems = [(key, node[key]) for key in node.keys() if key not in skip_elems]
        rets = [(key, walk_json(elem, fun, nodes)) for (key, elem) in elems if elem != {}]

    return fun(node, rets, nodes, skip_elems)


def p4node_creator(node, elems, nodes, skip_elems):
    if type(node) is not dict and type(node) is not list:
        # note: types: string, bool, int
        return node

    node_id = node['Node_ID']

    if node_id in nodes:
        p4node = nodes[node_id]
    else:
        p4node = P4Node({
            'incomplete_json_data': True,
        })
        nodes[node_id] = p4node

    if not hasattr(p4node, 'incomplete_json_data'):
        return

    p4node.set_attrs({
        "id": node_id,
        "json_data": node,
    })

    # TODO u'annotations': {u'Node_ID': 4}
    if 'Node_Type' in node.keys():
        p4node.set_attrs({"node_type": node['Node_Type']})
        p4node.remove_attr('incomplete_json_data')

    if 'vec' in node.keys():
        no_key_elems = [elem for key, elem in elems]
        nodes[node_id].set_vec(no_key_elems)
    else:
        for key, subnode in elems:
            nodes[node_id].set_attrs({key: subnode})

    return nodes[node_id]


def load_p4(p4c_path, p4c_file):
    p4test = os.path.join(p4c_path, "build", "p4test")
    p4include = os.path.join(p4c_path, "p4include")
    json_file = tempfile.NamedTemporaryFile(prefix="p4_out_", suffix=".json")
    json_file.close()

    errcode = subprocess.call(
        [p4test, p4c_file, "-I", p4include, "--toJSON", json_file.name])

    if errcode != 0:
        return (errcode, None, None)

    with open(json_file.name, 'r') as f:
        json_root = json.load(f)

    # Note: this can happen if the loaded file does not contain "main".
    if json_root['Node_ID'] is None:
        return (errcode, None, None)

    nodes = {}
    walk_json(json_root, p4node_creator, nodes)

    program = nodes[json_root['Node_ID']]
    return (errcode, program, nodes)
