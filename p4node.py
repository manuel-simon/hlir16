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
        "paths_to",
        "by_type",
    }

    def __init__(self, dict={}, vec=None):
        self.__dict__ = dict
        if 'Node_ID' not in dict:
            self.Node_ID = get_fresh_node_id()
        self._data = {}
        self.vec = vec

    def __str__(self, show_name=True, show_type=True, show_funs=True, details=True, show_colours=True):
        """A textual representation of a P4 HLIR node."""
        if self.vec is not None:
            if len(self.vec) > 0 and type(self.vec[0]) is P4Node:
                fmt   = '{{0:>{}}} {{1}}'.format(len(str(len(self.vec))))
                return '\n'.join([fmt.format(idx, elem) for idx, elem in enumerate(self.vec)])
            return str(self.vec)

        name = self.name if hasattr(self, 'name') else ""

        part1 = name if show_name else ""
        part2 = "#" + str(self.get_attr('Node_ID'))
        part3 = "#{}".format(self.node_type) if show_type else ""
        part4 = "[{}]".format(', '.join(self.xdir(details))) if show_funs else ""

        return "{}{}{}{}".format(part1, _c(part2, clr_nodeid, show_colours), _c(part3, clr_nodetype, show_colours), part4)

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
        if not self.vec:
            return 0
        return len(self.vec)

    def __iter__(self):
        if self.vec is not None:
            for x in self.vec:
                yield x

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
        """Adds elements to the vector of the object."""
        if type(other) is list:
            return P4Node({}, self.vec + other)
        return P4Node({}, self.vec + other.vec)

    def __call__(self, key):
        return self.__dict__[key] if key in self.__dict__ else self

    def set_vec(self, vec):
        """Sets the vector of the object."""
        self.vec = vec

    def is_vec(self):
        return self.vec is not None

    def xdir(self, details=False, show_colours=True):
        """Lists the noncommon attributes of the node."""
        def follow_path(node, path):
            for pathelem in path:
                node = node.get_attr(pathelem)
                if node is None:
                    return None

            return (".".join(path), str(node)) if type(node) is not P4Node else None


        def follow_paths(attrname, node):
            paths = [
                ('expr', ['path', 'name']),
                ('expr', ['ref', 'name']),
                ('expr', ['expr', 'ref', 'name']),
                ('expr', ['member', 'member']),
                ('expr', ['member']),
                ('path', ['name']),
                ('ref',  ['name']),
                ('member',  ['member']),
            ]
            for path in [p for (a, p) in paths if a == attrname]:
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
                return (True, "=" + _c(str(attr), clr_value))

            result = follow_paths(d, attr)
            if result is not None:
                return (True, _c("." + result[0], clr_extrapath) + "=" + _c(result[1], clr_value))

            if type(attr.get_attr(d)) is P4Node and attr.get_attr(d).vec is not None:
                attrlen = len(attr.get_attr(d).vec)
                return (attrlen > 0, "**" + _c(str(attrlen), clr_attrmul if attrlen > 0 else clr_off, show_colours))
            if attr.vec is None:
                return (True, "")

            attrlen = len(attr.vec)
            return (attrlen > 0, "*" + _c(str(attrlen), clr_attrmul if attrlen > 0 else clr_off, show_colours))

        return [_c(d, clr_attrname if is_clr_on else clr_off, show_colours) + attr_details
                    for d in dir(self)
                    if not d.startswith("__")
                    if d not in P4Node.common_attrs
                    for (is_clr_on, attr_details) in [show_details(d)] ]

    def str(self, show_name=True, show_type=True, show_funs=True):
        return P4Node.__str__(self, show_name, show_type, show_funs)

    def get(self, name, type_name=None, cond=lambda elem: True):
        """A convenient way to get the element with the given name (and type, if given) in a vector.
        A predicate that takes the element as a parameter can also be specified."""
        potentials = [elem for elem in self.vec if elem.get_attr('name') == name and (type_name == None or elem.node_type == type_name) if cond(elem)]
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
