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

from utils_hlir16 import *

from hlir16_attrs import set_additional_attrs


def has_method(obj, method_name):
    return hasattr(obj, method_name) and callable(getattr(obj, method_name))


def walk_json_from_top(node, fun):
    nodes = {}
    hlir = walk_json(node, fun, nodes)
    hlir.all_nodes = P4Node({}, nodes)
    return hlir


def walk_json(node, fun, nodes, skip_elems=['Node_Type', 'Node_ID', 'Source_Info'], node_parent_chain=[]):
    rets = []
    if type(node) is dict or type(node) is list:
        node_id = node['Node_ID']
        if node_id not in nodes:
            nodes[node_id] = P4Node({
                'incomplete_json_data': True,
                'node_parents': [node_parent_chain],
            })

        if 'vec' in node.keys():
            elems = [(None, elem) for elem in node['vec']]
        else:
            elems = [(key, node[key]) for key in node.keys() if key not in skip_elems]
        rets = [(key, walk_json(elem, fun, nodes, skip_elems, node_parent_chain + [nodes[node_id]])) for (key, elem) in elems if elem != {}]

    return fun(node, rets, nodes, skip_elems, node_parent_chain)


def p4node_creator(node, elems, nodes, skip_elems, node_parent_chain):
    if type(node) is not dict and type(node) is not list:
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
        p4node.remove_attr('incomplete_json_data')

    if 'vec' in node.keys():
        no_key_elems = [elem for key, elem in elems]
        nodes[node_id].set_vec(no_key_elems)
    else:
        for key, subnode in elems:
            nodes[node_id].set_attr(key, subnode)

    return nodes[node_id]


def create_p4_json_file(p4c_filename, p4_version=None, p4c_path=None, json_cache_dir=None, json_filename=None):
    """Translates the P4 file into a JSON file.
    If no filename is given, a temporary one is created."""
    if p4c_path is None:
        p4c_path = os.environ['P4C']

    p4compiler = os.path.join(p4c_path, "build", "p4test")
    p4include = os.path.join(p4c_path, "p4include")

    remove_json_after_use = False

    if json_cache_dir:
        json_filename = os.path.join(json_cache_dir, os.path.basename(p4c_filename) + ".json")
    else:
        if json_filename is None:
            json_file = tempfile.NamedTemporaryFile(prefix="p4_out_", suffix=".p4.json")
            json_file.close()
            json_filename = json_file.name
            remove_json_after_use = True

    version_opts = ['--p4v', str(p4_version)] if p4_version is not None else []

    opts = [p4compiler, "-I", p4include, p4c_filename] + version_opts + ["--toJSON", json_filename]

    errcode = subprocess.call(
        [p4compiler, p4c_filename, "-I", p4include, "--toJSON", json_filename] + version_opts)

    return (errcode, remove_json_after_use, json_filename)


ERR_CODE_NO_PROGRAM = -1000
def load_p4_json_file(json_filename, p4_version):
    """Returns either ERR_CODE_NO_PROGRAM (an int), or a P4Node object."""
    with open(json_filename, 'r') as f:
        import pkgutil
        if pkgutil.find_loader('ujson') is not None:
            import ujson
            json_root = ujson.load(f)
        else:
            json_root = json.load(f)

    # Note: this can happen if the loaded file does not contain "main".
    if json_root['Node_ID'] is None:
        return ERR_CODE_NO_PROGRAM

    nodes = {}
    walk_json(json_root, p4node_creator, nodes)
    hlir16 = nodes[json_root['Node_ID']]

    success = set_additional_attrs(hlir16, nodes, p4_version)
    if not success:
        return ERR_CODE_NO_PROGRAM

    return hlir16


def load_p4(filename, p4_version=None, p4c_path=None, json_cache_dir=None):
    """Returns either an error code (an int), or a P4Node object."""
    if p4c_path is None:
        p4c_path = os.environ['P4C']

    MOST_RECENT_P4_VERSION = 16
    p4_version = p4_version or MOST_RECENT_P4_VERSION

    if filename.endswith(".json"):
        json_filename = filename
        remove_json_after_use = False
    else:
        errcode, remove_json_after_use, json_filename = create_p4_json_file(filename, p4_version, p4c_path, json_cache_dir)

        if errcode != 0:
            return errcode

    retval = load_p4_json_file(json_filename, p4_version or MOST_RECENT_P4_VERSION)
    if remove_json_after_use:
        os.remove(json_filename)

    return retval
