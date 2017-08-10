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


extra_node_id = -1000

p4node_last_failure      = None
p4node_last_failure_path = []

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
    }

    def __init__(self, dict, vec=None):
        self.__dict__ = dict
        if 'Node_ID' not in dict:
            global extra_node_id
            self.Node_ID = extra_node_id
            extra_node_id -= 1
        self._data = {}
        self.vec = vec

    def __str__(self, show_name=True, show_type=True, show_funs=True):
        """A textual representation of a P4 HLIR node."""
        if self.is_vec():
            if len(self.vec) > 0 and type(self.vec[0]) is P4Node:
                return '\n'.join([str(elem) for elem in self.vec])
            return str(self.vec)

        name = self.name if hasattr(self, 'name') else ""

        part1 = name if show_name else ""
        part2 = "<{}>".format(self.node_type) if show_type else ""
        part3 = "[{}]".format(', '.join(self.xdir())) if show_funs else ""

        return "{}{}[#{}]{}".format(part1, part2, str(self.get_attr('Node_ID')), part3)

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
        return [node for node in self.vec if node.node_type == key]

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

    def define_common_attrs(self, attr_names):
        """The attribute names in the list will not be listed
        by the str and xdir operations."""
        for attr_name in attr_names:
            P4Node.common_attrs.add(attr_name)

    def get_attr(self, key):
        global p4node_last_failure
        global p4node_last_failure_path

        if key not in self.__dict__:
            if p4node_last_failure is None:
                p4node_last_failure = self
            p4node_last_failure_path.append(key)
            return None
        return self.__dict__[key]

    def set_vec(self, vec):
        """Sets the vector of the object."""
        self.vec = vec

    def is_vec(self):
        return self.vec is not None

    def xdir(self):
        """Lists the noncommon attributes of the node."""
        return [d for d in dir(self) if not d.startswith("__") and d not in P4Node.common_attrs]

    def str(self, show_name=True, show_type=True, show_funs=True):
        return P4Node.__str__(self, show_name, show_type, show_funs)

    def get(self, name, type_name=None):
        """A convenient way to get the element with the given name (and type, if given) in a vector."""
        potentials = [elem for elem in self.vec if elem.get_attr('name') == name and (type_name == None or elem.node_type == type_name)]
        return potentials[0] if len(potentials) == 1 else None
