#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node, get_fresh_node_id
from hlir16.hlir_utils import make_node_group, align8_16_32, unique_list, shorten_locvar_names
from hlir16.hlir_model import model_specific_infos, smem_types_by_model, packets_by_model

import hlir16.hlirx_annots
import hlir16.hlirx_regroup

from compiler_log_warnings_errors import addWarning, addError
from compiler_common import unique_everseen, dlog

import re
from collections import Counter


def is_extern_unused(extern, repr):
    return repr is None or repr.node_type in ('Type_Name')


def get_extern_repr(extern):
    if len(extern.constructors) == 0:
        return None

    ctor_params = extern.constructors[0].urtype.parameters.parameters
    if len(ctor_params) == 0:
        return None
    repr = ctor_params[0].urtype

    if is_extern_unused(extern, repr):
        return None

    return repr


def attrs_extern(hlir):
    infos = model_specific_infos[hlir.news.model]

    for extern in hlir.all_nodes.by_type('Type_Extern'):
        if 'smem_type' in extern:
            continue

        extern.constructors      = P4Node([ctor for ctor in extern.methods if ctor.name == extern.name])
        extern.interface_methods = P4Node([ctor for ctor in extern.methods if ctor.name != extern.name])
        extern.is_repr_model_specific = extern.name in infos['extern_reprs']

        if extern.is_repr_model_specific:
            extern.repr = infos['extern_reprs'][extern.name]
            extern.is_unused = False
        else:
            extern.repr = get_extern_repr(extern)
            extern.is_unused = is_extern_unused(extern, extern.repr)
