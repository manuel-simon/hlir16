#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Eotvos Lorand University, Budapest, Hungary

elementwise_binary_ops = {
    #Bitwise operators
    'BAnd':'&', 'BOr':'|', 'BXor':'^',
    #Equality operators
    'Equ':'==', 'Neq':'!='
}

simple_binary_ops = {
    #Binary arithmetic operators
    'Div':'/', 'Mod':'%',
    #Binary comparison operators
    'Grt':'>', 'Geq':'>=', 'Lss':'<', 'Leq':'<=',
    #Bitwise operators
    'BAnd':'&', 'BOr':'|', 'BXor':'^',
    #Boolean operators
    'LAnd':'&&', 'LOr':'||',
    #Equality operators
    'Equ':'==', 'Neq':'!='
}

# TODO currently, AddSat and SubSat are handled exactly as Add and Sub
complex_binary_ops = {'AddSat':'+', 'SubSat':'-', 'Add':'+', 'Sub':'-', 'Mul':'*', 'Shl':'<<', 'Shr':'>>'}
