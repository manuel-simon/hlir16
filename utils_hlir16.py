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


# Utility functions for analyzing HLIR

# TODO turn all content in here into attributes of P4Nodes?


def get_bit_width(hlir16, node):
    return type_bit_width(hlir16, get_type(hlir16, node))


def type_bit_width(hlir16, p4type):
    return sum([get_type(hlir16, hf).size for hf in p4type.fields])


def get_type(hlir16, node):
    if node.type.node_type == "Type_Bits":
        return node.type

    if node.type.node_type == "Type_Varbits":
        return node.type

    if node.type.node_type == "Type_Name":
        htype_name = node.type.path.name

        hdr = hlir16.declarations.get(htype_name, "Type_Header")
        if hdr is not None:
            return hdr

        return hlir16.declarations.get(htype_name, "Type_Typedef").type

    raise ValueError("Expected node that describes a type, got " + str(node))


def bits_to_bytes(bit_size):
    return (bit_size + 7) / 8
