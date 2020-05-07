#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


import pkgutil
import types

extra_node_id = -1000

clr_attrname = 'green'
clr_attrmul = 'red'
clr_nodeid = 'magenta'
clr_nodetype = 'cyan'
clr_value = 'yellow'
clr_extrapath = 'magenta'
clr_off = 'grey'
clr_function = 'magenta'

is_using_colours = pkgutil.find_loader('termcolor')
if pkgutil.find_loader('termcolor'):
    from termcolor import colored


def _c(txt, colour, show_colours=True):
    if not is_using_colours or not show_colours:
        return txt
    return colored(txt, colour)


def get_fresh_node_id():
    global extra_node_id
    extra_node_id -= 1
    return extra_node_id


class P4Node(object):
    """These objects represent nodes in the HLIR.
    Related nodes are accessed via attributes,
    with some shortcuts for vectors."""

    common_attrs = {
        "_data",
        "Node_Type",
        "Node_ID",
        "node_parents",
        "vec",
        "add_attr",
        "is_vec",
        "set_vec",
        "json_data",
        "node_type",
        "xdir",
        "remove_attr",
        "get_attr",
        "set_attr",
        "define_common_attrs",
        "set_vec",
        "is_vec",
        "common_attrs",
        "get",
        "str",
        "id",
        "append",

        # displayed by default
        "name",

        # not really useful most of the time
        "declid",

        # common tools
        "all_nodes_by_type",
        "paths_to",
        "by_type",
        "json_repr",
        "canonical_type",
    }

    def __init__(self, dict={}, vec=None):
        self.__dict__ = dict
        if 'Node_ID' not in dict:
            self.Node_ID = get_fresh_node_id()
        self._data = {}
        self.vec = vec

    def __str__(self, show_name=True, show_type=True, show_funs=True, details=True, show_colours=True, depth=0):
        """A textual representation of a P4 HLIR node."""
        if self.vec is not None and details:
            if len(self.vec) > 0 and type(self.vec[0]) is P4Node:
                fmt   = '{{0:>{}}} {{1}}'.format(len(str(len(self.vec))))
                if type(self.vec) is dict:
                    return '\n'.join([fmt.format(key, self.vec[key]) for key in sorted(self.vec.keys())])
                else:
                    return '\n'.join([fmt.format(idx, elem) for idx, elem in enumerate(self.vec)])
            return str(self.vec)

        name = self.name if hasattr(self, 'name') else ""

        part1 = name if show_name else ""
        part2 = "#" + str(self.get_attr('Node_ID'))
        part3 = "#{}".format(self.node_type) if show_type and hasattr(self, 'node_type') else ""
        part4 = "[{}]".format(', '.join(self.xdir(details, depth=depth))) if show_funs else ""

        indent = " " * (8*depth)
        return "{}{}{}{}{}".format(indent, part1, _c(part2, clr_nodeid, show_colours), _c(part3, clr_nodetype, show_colours), part4)

    def __repr__(self):
        return self.__str__()

    def __getitem__(self, key):
        """If the node has the given key as an attribute, retrieves it.
        Otherwise, the node has to be a vector,
        which can be indexed numerically or, for convenience by node type."""
        if key in self._data:
            return self._data[key]
        if self.vec is None:
            return None

        if type(key) == int:
            return self.vec[key]
        return P4Node({}, [node for node in self.vec if node.node_type == key])

    def __len__(self):
        if self.vec is None:
            return 0
        return len(self.vec)

    def __iter__(self):
        if self.vec is not None:
            for x in self.vec:
                yield x

    def __mod__(self, other):
        return self.paths_to(other)

    def __lt__(self, depth):
        """This is not a proper comparison operator.
        Rather, it pretty prints the node to the standard output.
        You can use it as the postfix "love operator" on a node: `node<3` """
        import json
        from ruamel import yaml
        import re

        depth = max(1, depth)

        dumped = yaml.dump(yaml.safe_load(json.dumps(self.json_repr(depth))), default_flow_style=False).decode('string_escape')
        ascii_escape = '\033'
        print(re.sub(r'\\e[ ]*', ascii_escape, re.sub(r'\"\\e', '\\e', re.sub(r'\\e\[0m\"', '\\e[0m', dumped))))

        return None

    def __nonzero__(self):
        return 'node_type' in self.__dict__ and self.__dict__['node_type'] != "INVALID"

    # TODO this would be better if it was set in set_common_attrs in hlir16_attrs
    def canonical_type(self):
        node = self
        # Note: for enums, node.type == node, which would result in an infinite loop
        while hasattr(node, "type") and node != node.type._type_ref:
            node = node.type._type_ref
        return node

    def json_repr(self, depth=3, max_vector_len=lambda depth: 2 if depth > 2 or depth <= 0 else [8, 4][depth - 1], is_top_level = True):
        if depth <= 0:
            return "..."

        if self.is_vec():
            maxlen = max_vector_len(depth)
            selflen = len(self.vec)
            repr = [e.json_repr(depth, is_top_level = True) if type(e) is P4Node else e for e in list(self.vec)[:maxlen]]
            if selflen > maxlen:
                repr += ["({} more elements, {} in total)".format(selflen - maxlen, selflen)]
        else:
            repr = {}
            for d in self.xdir(details=False, show_colours=False):
                reprattrname = _c("." + d, clr_attrname)
                reprtype = _c("#" + str(self.node_type) if 'node_type' in self.__dict__ else "#", clr_nodetype)
                reprfld = "{}{}".format(reprattrname, reprtype)
                if type(self.get_attr(d)) is P4Node:
                    repr[reprfld] = self.get_attr(d).json_repr(depth-1, is_top_level = False)
                else:
                    repr[reprfld] = str(self.get_attr(d))

        nodename = "{}{}".format(_c(self.name  if 'name' in self.__dict__ else "", clr_value), _c("#" + str(self.node_type) if 'node_type' in self.__dict__ else "#", clr_nodetype))

        return { nodename: repr } if is_top_level else repr

    def remove_attr(self, key):
        del self.__dict__[key]

    def set_attr(self, key, value):
        """Sets an attribute of the object."""
        self.__dict__[key] = value

    @staticmethod
    def define_common_attrs(attr_names):
        """The attribute names in the list will not be listed
        by the str and xdir operations."""
        P4Node.common_attrs.update(attr_names)

    def get_attr(self, key):
        return self.__dict__[key] if key in self.__dict__ else None

    def append(self, elem):
        """Adds an element to the vector of the object."""
        self.vec.append(elem)

    def __add__(self, other):
        """Returns a P4Node that contains the elements from the node's vector and the other list/P4Node."""
        if type(other) is list:
            return P4Node({}, self.vec + other)
        return P4Node({}, self.vec + other.vec)

    def __getattr__(self, key):
        if key.startswith('__') or key == 'vec':
            return object.__getattr__(self, key)

        if key.startswith('_'):
            realkey = key[1:]
            return self.__dict__[realkey] if realkey in self.__dict__ else self

        if self.__dict__['node_type'] == "INVALID":
            return self

        return self.__dict__[key]


    def __call__(self, key, continuation = None, default = None):
        """The key is a dot separated sequence of attributes such as 'type.type_ref.name'.
        If the attributes can be traversed, the node that is reached is returned.
        If the attribute sequence is broken, a P4 node describing the failure
        (or the default parameter, if it is set) is returned."""
        if self.node_type == "INVALID":
            return self

        original_node = self

        current_node = self
        for idx, k in enumerate(key.split(".")):
            if k not in current_node.__dict__:
                retval = P4Node()
                retval.name = "INVALID"
                retval.node_type = "INVALID"
                retval.original_node = original_node
                retval.original_path = key
                retval.last_good_node = current_node
                retval.remaining_path = ".".join(key.split(".")[idx:])
                return retval

            current_node = current_node.__dict__[k]

        if current_node:
            return continuation(current_node) if callable(continuation) else current_node

        return default() if callable(default) else default or current_node

    def set_vec(self, vec):
        """Sets the vector of the object."""
        self.vec = vec

    def is_vec(self):
        return self.vec is not None

    def xdir(self, details=False, show_colours=True, depth=0):
        """Lists the noncommon attributes of the node."""
        def follow_path(node, path):
            for pathelem in path:
                node = node.get_attr(pathelem)
                if node is None:
                    return None

            return (".".join(path), str(node)) if type(node) is not P4Node else None


        def follow_paths(attrname, node):
            paths = [
                'header_ref.name',
                'type_ref.path.name',
                'type_ref.name',
                'type.type_ref.path.name',
                'type.type_ref.name',
                'type.path.node_type',
                'type.path.name',
                'type.name',
                'type.node_type',
                'baseType.path.name',
                'field_ref.name',
                'expr.path.name',
                'method.path.name',
                'expr.ref.name',
                'expr.expr.ref.name',
                'expr.member.member',
                'expr.member',
                'path.name',
                'ref.name',
                'member.member',
            ]
            for path in [p.split('.')[1:] for p in paths if p.split('.')[0] == attrname]:
                result = follow_path(node, path)
                if result is not None:
                    return result
            return None

        def show_details(d):
            if not details or type(d) not in [str, unicode]:
                return (True, "")

            attr = self.get_attr(d)

            if type(attr) is types.FunctionType:
                return (True, "=" + _c("fun", clr_function))

            if type(attr) is not P4Node:
                return (True, "=" + _c(str(attr) or '""', clr_value))

            result = follow_paths(d, attr)
            if result is not None:
                return (True, _c("." + result[0], clr_extrapath) + "=" + _c(result[1], clr_value))

            if type(attr.get_attr(d)) is P4Node and attr.get_attr(d).vec is not None:
                attrlen = len(attr.get_attr(d).vec)
                return (attrlen > 0, "**" + _c(str(attrlen), clr_attrmul if attrlen > 0 else clr_off, show_colours))

            listables = ['NameMap', 'ParameterList', 'Annotations', 'Vector']
            is_listable = False if not hasattr(attr, 'node_type') else True in [attr.node_type.startswith(t) for t in listables]
            if attr.vec is None and not is_listable:
                return (True, "")

            attrlen = len(attr.vec or [])
            return (attrlen > 0, "*" + _c(str(attrlen), clr_attrmul if attrlen > 0 else clr_off, show_colours))

        return [_c(d, clr_attrname if is_clr_on else clr_off, show_colours) + attr_details
                    for d in dir(self)
                    if not d.startswith("__")
                    if d not in P4Node.common_attrs
                    for (is_clr_on, attr_details) in [show_details(d)] ]

    def str(self, show_name=True, show_type=True, show_funs=True, details=True, show_colours=True, depth=0):
        return P4Node.__str__(self, show_name, show_type, show_funs, details, show_colours, depth)

    def get(self, name, type_names=[], cond=lambda elem: True):
        """A convenient way to get the element with the given name (and types, if given) in a vector.
        You can impose further limitations on the returned elements with the condition argument.
        """
        if type(type_names) is str:
            type_names = [type_names]
        potentials = [elem for elem in self.vec if elem.get_attr('name') == name and (type_names == [] or elem.node_type in type_names) if cond(elem)]
        return potentials[0] if len(potentials) == 1 else None


def deep_copy(node, seen_ids = [], on_error = lambda x: None):
    new_p4node = P4Node({})

    if node.id in seen_ids:
        on_error(node.id)

    for c in node.__dict__:
        if c not in node.xdir(details=False) and not c.startswith("__"):
            new_p4node.set_attr(c, node.get_attr(c))

    if node.is_vec():
        new_p4node.set_vec([deep_copy(elem, seen_ids + [node.id]) for elem in node.vec])

    for d in node.xdir(details=False):
        if type(node.get_attr(d)) == P4Node and d not in ['ref', 'type_ref', 'header_ref', 'field_ref', 'control']:
            new_p4node.set_attr(d, deep_copy(node.get_attr(d), seen_ids + [node.id]))
        else:
            new_p4node.set_attr(d, node.get_attr(d))

    return new_p4node
