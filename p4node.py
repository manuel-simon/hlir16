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

class P4Node(object):
    """These objects represent nodes in the HLIR.
    Related nodes are accessed via attributes,
    with some shortcuts for vectors."""

    def __init__(self, dict):
        self.__dict__ = dict
        self.data = {}
        self.vec = None
        self.common_attrs = [
            "Node_Type",
            "Node_ID",
            "vec",
            "add_attr",
            "is_vec",
            "set_vec",
            "json_data",
            "node_type",
        ]

    def __str__(self):
        """A textual representation of a P4 HLIR node."""
        name = self.name if hasattr(self, 'name') else ""
        funs = [k for k in self.json_data.keys() if k not in self.common_attrs]
        return "{}<{}>[{}]".format(name, self.node_type, ', '.join(funs))

    def __repr__(self):
        return self.__str__()

    def __getitem__(self, key):
        """If the node has the given key as an attribute, retrieves it.
        Otherwise, the node has to be a vector,
        which can be indexed numerically or, for convenience by node type."""
        if key in self.data:
            return self.data[key]
        if self.vec is None:
            return None

        if type(key) == int:
            return self.vec[key]
        return [node for node in self.vec if node.node_type == key]

    def __len__(self):
        return len(self.vec)

    def remove_attr(self, key):
        del self.__dict__[key]

    def set_attrs(self, dict):
        """Changes attributes of the object."""
        for key, value in dict.items():
            self.__dict__[key] = value

    def set_vec(self, vec):
        """Sets the vector of the object."""
        self.vec = vec

    def is_vec(self):
        return self.vec is not None

    def xdir(self):
        """Lists the noncommon attributes of the node."""
        return [d for d in dir(self) if not d.startswith("__") and d not in self.common_attrs]
