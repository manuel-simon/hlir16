#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Eotvos Lorand University, Budapest, Hungary

from hlir16.p4node import P4Node

# These have to be specified here, as the model description file gives ZERO HINTS about them
model_specific_infos = {
    "V1Switch": {
        "user_meta_var": "meta",
        "meta_types": [
            "standard_metadata_t",
        ],
        "extern_reprs": {},
    },
    "PSA_Switch": {
        "user_meta_var": "user_meta",
        "meta_types": [
            "psa_ingress_parser_input_metadata_t",
            "psa_egress_parser_input_metadata_t",
            "psa_ingress_input_metadata_t",
            "psa_ingress_output_metadata_t",
            "psa_egress_input_metadata_t",
            "psa_egress_deparser_input_metadata_t",
            "psa_egress_output_metadata_t",
        ],
        "extern_reprs": {
            'InternetChecksum': P4Node({'node_type': 'Type_Bits', 'isSigned': False, 'size': 16, 'padded_size': 16}),
            'Digest':           P4Node({'node_type': 'Type_Bits', 'isSigned': False, 'size': 32, 'padded_size': 32}),
        },
    },
}

def get_infos(hlir, names, model_to_names, description):
    if (model := hlir.news.model) not in model_to_names:
        addError(f'Getting {description}', f'Unknown model "{model}"')
        return None, None

    result_names = model_to_names[model]
    return {info: minfo for info, minfo in zip(names, result_names)}, {minfo: info for info, minfo in zip(names, result_names)}


def smem_types_by_model(hlir):
    smems = ['counter', 'direct_counter', 'meter', 'direct_meter', 'register']
    model_to_smems = {
        'V1Switch': smems,
        'PSA_Switch': ['Counter', 'DirectCounter', 'Meter', 'DirectMeter', 'Register'],
    }
    return get_infos(hlir, smems, model_to_smems, 'software memories')



def packets_by_model(hlir):
    pobs = ['packets', 'bytes', 'packets_and_bytes']
    model_to_pobs = {
        'V1Switch': pobs,
        'PSA_Switch': ['PACKETS', 'BYTES', 'PACKETS_AND_BYTES'],
    }
    return get_infos(hlir, pobs, model_to_pobs, 'packet-or-bytes infos')
