#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Eotvos Lorand University, Budapest, Hungary

import pkgutil
import types
import collections
from itertools import dropwhile, chain, groupby

extra_node_id = -1

is_using_colours = pkgutil.find_loader('colored')
if pkgutil.find_loader('colored'):
    from colored import fg, bg, attr

    clr_attrname = fg('green')
    clr_count = fg('red')
    clr_nodeid = fg('magenta')
    clr_nodetype = fg('cyan')
    clr_value = fg('yellow')
    clr_extrapath = fg('magenta_2a')
    clr_off = fg('light_gray') + bg('dark_blue')
    clr_function = fg('magenta')
else:
    # note: these variables are accessed later on, they need to be defined
    clr_attrname = None
    clr_count = None
    clr_nodeid = None
    clr_nodetype = None
    clr_value = None
    clr_extrapath = None
    clr_off = None
    clr_function = None


def _c(txt, colour, show_colours=True):
    if not is_using_colours or not show_colours:
        return f'{txt}'
    return f'{colour}{txt}{attr("reset")}'


def get_fresh_node_id():
    global extra_node_id
    extra_node_id -= 1
    return extra_node_id


def path_parts(root, path):
    current_node = root
    for elem in path:
        if type(elem) is not int:
            current_node = current_node.get_attr(elem)
            yield f".{elem}"
        else:
            if type(current_node) is list:
                subnode = current_node[elem]
                next_node = current_node[elem]
            else:
                subnode = current_node.vec[elem]
                next_node = current_node.vec[elem]

            if type(current_node) is P4Node and type(subnode) is P4Node:
                if not all(type(vecnode) is P4Node and type(vecnode) == type(subnode) for vecnode in current_node[subnode.node_type].vec):
                    idx = current_node[subnode.node_type].vec.index(subnode)
                    yield f"['{subnode.node_type}'][{idx}]"
                else:
                    yield f"[{elem}]"
            else:
                yield f"[{elem}]"
            current_node = next_node

def print_path(pathinfo, root, max_length=70, max_width=30):
    path, matchtype, nodetxt, _node = pathinfo
    path_txt = ''.join(path_parts(root, path)) or "(the node itself)"
    nodetxt = nodetxt or ""
    print(f'{nodetxt:{max_width}} {matchtype} {path_txt}')


def first_n(g, max_count):
    """Runs a generator for at most max_count steps."""
    count = 1
    for item in g:
        if count == max_count:
            return
        yield item
        count += 1


def paths_to(root, node_or_value, max_depth=20, sort_by_path_length=False, max_length=70):
    """Sorts using path text by default."""
    found_paths = _paths_to_recurse(root, node_or_value, max_depth=max_depth)

    first100 = list(first_n(found_paths, 256))
    max_width = max(1, max((len(nodetxt or "") for _, _, nodetxt, _ in first100), default=30))

    chained = chain(first100, found_paths)
    paths = list(sorted(chained, key=lambda pathinfo: len(pathinfo[0])) if sort_by_path_length else chained)

    count = 0
    for path in paths:
        print_path(path, root, max_length=max_length, max_width=max_width)
        count += 1

    print(f'{count} results found, search started at {root.str(details=False)}')

    return paths


def _paths_new_nodes(node, founds):
    if type(node) is list:
        return ((idx, subnode) for idx, subnode in enumerate(node) if subnode not in founds)
    elif type(node) is dict:
        return ((key, subnode) for key in node if (subnode := node[key]) not in founds)
    elif type(node) is not P4Node:
        return ()
    if node.node_type == 'all_nodes':
        return ()
    elif node.is_vec():
        if type(node.vec) is dict:
            return ((key, node.vec[key]) for key in sorted(node.vec.keys()))
        else:
            return ((idx, node[idx]) for idx, elem in enumerate(node.vec))

    return ((attr, getattr(node, attr)) for attr in node.xdir(show_colours=False))

def _paths_matchtype(nodetxt, valuetxt):
    if nodetxt == valuetxt:
        return '='
    if nodetxt.startswith(valuetxt):
        return '<'
    if nodetxt.endswith(valuetxt):
        return '>'
    return '∊'

def _paths_to_recurse(node, node_or_value, max_depth=20, path=[], found_nodes=set()):
    """Finds the paths under node through which the value is accessible."""
    if max_depth < 1:
        return

    if type(node_or_value) is P4Node and node == node_or_value:
        p4_node_txt = node.name if 'name' in node else None
        yield (path, '=', p4_node_txt, node)
        return

    nodetxt = f'{node}' if type(node) is not P4Node else node.name if 'name' in node else None

    if nodetxt is not None and type(node_or_value) is not P4Node and (valuetxt := f'{node_or_value}') in nodetxt:
        matchtype = _paths_matchtype(nodetxt, valuetxt)
        yield (path, matchtype, nodetxt, node)
        return

    founds = found_nodes.copy()
    founds.add(node)

    for key, new_node in _paths_new_nodes(node, founds):
        if type(new_node) is P4Node and new_node not in founds:
            yield from _paths_to_recurse(new_node, node_or_value, max_depth - 1, path + [key], founds)


class P4Node(object):
    """These objects represent nodes in the HLIR.
    Related nodes are accessed via attributes,
    with some shortcuts for vectors."""

    followable_paths = [
        'action_ref.name',
        'env_node.name',
        'header_ref.name',

        'constructedType.path.name',
        'type_ref.path.name',
        'type_ref.name',
        'type.type_ref.path.name',
        'type.type_ref.name',
        'type.path.name',
        'type.name',
        'type.size',
        'type.node_type',
        'baseType.path.name',
        'field_ref.name',

        'method.member',
        'method.path.name',

        'expression.method.member',
        'expression.method.path.name',

        'expr.path.name',
        'expr.ref.name',
        'expr.ref.name',
        'expr.expr.ref.name',
        'expr.member.member',
        'expr.member',

        'path.name',
        'path.absolute',
        'ref.name',
        'member.member',
        'size.expression.value',
        'control.name',
        'default_action.expression.method.path.name',
    ]

    common_attrs = set((
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
        "listable_types",

        # displayed by default
        "name",

        # not really useful most of the time
        "declid",

        # common tools
        "all_nodes_by_type",
        "by_type",
        "default_keys",
        "filter",
        "_filter",
        "filterfalse",
        "followable_paths",
        "flatmap",
        "_get_filter_fun",
        "json_repr",
        "map",
        "node_by_id",
        "not_of",
        "of",
        "parent",
        "_parent",
        "parents",
        "_parents",
        "paths_to",
        "sorted",
        "urtype",
        "_urtype",
    ))

    default_keys = ('Node_ID', 'vec', 'node_type')

    def __init__(self, init=None, vec=None):
        if isinstance(init, P4Node):
            if not init.is_vec():
                raise AssertionError(f"Non-vector P4Node {init} used in P4Node creation")
            vec = list(init.vec)
            dct = {}
        elif isinstance(init, list):
            vec = init
            dct = {}
        else:
            dct = init or {}

        self.__dict__ = dct
        if 'Node_ID' not in dct:
            self.Node_ID = get_fresh_node_id()
        self.vec = vec

        if vec is not None and 'node_type' not in self:
            self.node_type = '<vec>'

        assert 'node_type' in self, f'P4Node created without node_type'
        if self.vec is not None and len(self.__dict__) != len(P4Node.default_keys):
            keys = ', '.join(key for key in self.__dict__.keys() if key not in P4Node.default_keys)
            assert False, f'P4Node has attributes ({keys}) but is also a vector ({len(self.vec)} elements)'

    def __str__(self, show_name=True, show_type=True, show_funs=True, details=True, show_colours=True, depth=0):
        """A textual representation of a P4 HLIR node."""
        if self.is_vec() and details:
            def elem_print(node):
                if type(node) is P4Node and node.is_vec() and len(node.vec) > 0 and type(node.vec[0]) is P4Node:
                    counts = sorted(collections.Counter(node.map('node_type')).items())
                    vecname = node.node_type[: node.node_type.find('<')]
                    return ', '.join(f'{_c(vecname, clr_nodetype)}<{_c(ntype, clr_nodetype)}*{_c(count, clr_count)}>' for ntype, count in counts)
                return f'{node}'

            if len(self.vec) > 0 and type(self.vec[0]) is P4Node:
                veclen = len(f'{len(self.vec)}')
                fmt    = f'{{0:>{veclen}}} {{1}}'
                return '\n'.join((f'{idx:>{veclen}} {elem_print(elem)}' for idx, elem in enumerate(self.vec)))
            return f'{self.vec}'

        name = self.name if 'name' in self.__dict__ else ""

        part1 = name or "" if show_name else ""
        part2 = f"#{self.Node_ID}"
        clr2 = _c(part2, clr_nodeid, show_colours)
        part3 = f"#{self.node_type}" if show_type else ""
        clr3 = _c(part3, clr_nodetype, show_colours)
        part4 = "[{}]".format(', '.join(self.xdir(details, depth=depth))) if show_funs else ""

        indent = " " * (8*depth)
        return f"{indent}{part1}{clr2}{clr3}{part4}"

    def __repr__(self):
        return self.__str__()

    def __getitem__(self, key):
        """If the node has the given key as an attribute, retrieves it.
        Otherwise, the node has to be a vector,
        which can be indexed numerically or, for convenience by node type."""
        if self.vec is None:
            return None

        if type(key) == int or type(key) == slice:
            return self.vec[key]
        return P4Node({'node_type': '<vec>'}, [node for node in self.vec if type(node) is P4Node if node.node_type == key])

    def __len__(self):
        if self.vec is None:
            return 0
        return len(self.vec)

    def __iter__(self):
        if self.vec is not None:
            for x in self.vec:
                yield x

    def __truediv__(self, node_or_value, max_depth=20):
        if type(node := node_or_value) is P4Node:
            paths_to(self, node, max_depth=max_depth, sort_by_path_length=False)
        else:
            paths_to(self, f'{node_or_value}', max_depth=max_depth, sort_by_path_length=False)

    def __floordiv__(self, node_or_value, max_depth=20):
        if type(node := node_or_value) is P4Node:
            paths_to(self, node, max_depth=max_depth, sort_by_path_length=True)
        else:
            paths_to(self, f'{node_or_value}', max_depth=max_depth, sort_by_path_length=True)

    def by_type(self, typename, strict=False):
        def is_right_type(t):
            return t == typename or (not strict and t == f'Type_{typename}')
        return P4Node([f for f in self.vec if is_right_type(f.node_type)])

    def parent(self):
        return self.node_parents[0][-1] if self.node_parents != [] else None

    def __lt__(self, depth):
        """This is not a proper comparison operator.
        Rather, it pretty prints the node to the standard output.
        You can use it as the postfix "love operator" on a node: `node<3` """
        import json
        from ruamel import yaml
        import re

        depth = max(1, depth+1)

        dumped = yaml.dump(yaml.safe_load(json.dumps(self.json_repr(depth))), default_flow_style=False)
        ascii_escape = '\033'
        dumped = re.sub(r'\\e\[0m\"', '\\\\e[0m', dumped)
        dumped = re.sub(r'\"\\e',     '\\\\e', dumped)
        dumped = re.sub(r'\\e[ ]*',    ascii_escape, dumped)
        print(dumped)

        return None

    def __bool__(self):
        if 'node_type' not in self.__dict__:
            return False
        if self.__dict__['node_type'] == "INVALID":
            return False
        if self.is_vec() and len(self.vec) == 0:
            return False
        return True

    __nonzero__=__bool__

    def _urtype(self):
        """Follows the attributes type, type_ref and baseType as long as possible."""
        node = self

        prevs = set()
        while type(node) is P4Node and node not in prevs:
            prevs.add(node)
            if "type" in node:
                node = node.type
                continue
            if "type_ref" in node:
                node = node.type_ref
                continue
            if "baseType" in node:
                node = node.baseType
                continue
        return node

    def _parents(self):
        """Returns a path from the root HLIR node to self.
        Usually it is the only such path."""

        return P4Node(self.node_parents[0])

    def _parent(self):
        return self.node_parents[0][-1]

    @staticmethod
    def _get_filter_fun(fun_or_path, value):
        if type(path := fun_or_path) is str:
            getval_fun = lambda node: node(path)
        else:
            getval_fun = fun_or_path

        if value is None:
            return getval_fun
        elif type(values := value) in (types.GeneratorType, tuple):
            return lambda node: getval_fun(node) in values
        else:
            return lambda node: getval_fun(node) == value

    def filter(self, fun_or_path, value=None):
        """Returns a P4Node vector that contains the filtered elements of the node's vector, or an invalid P4Node if it is not a vector."""
        return self._filter(P4Node._get_filter_fun(fun_or_path, value))

    def filterfalse(self, fun_or_path, value=None):
        """Returns a P4Node vector that contains the filtered elements of the node's vector, or an invalid P4Node if it is not a vector."""
        filterfun = P4Node._get_filter_fun(fun_or_path, value)
        return self._filter(lambda node: not filterfun(node))

    def sorted(self, fun_or_path, value=None):
        """Returns a P4Node vector that contains the filtered elements of the node's vector, or an invalid P4Node if it is not a vector."""
        if type(path := fun_or_path) is str:
            fun = lambda node: node(path)
        else:
            fun = fun_or_path

        if not self.is_vec():
            retval = P4Node({'name': 'INVALID', 'node_type': 'INVALID'})
            retval.original_node = self
            retval.original_path = '(filter)'
            retval.last_good_node = self
            retval.remaining_path = fun
            return retval

        return P4Node(list(sorted((node for node in self.vec), key=fun)))

    def _filter(self, fun):
        if self.is_vec():
            return P4Node([node for node in self.vec if fun(node)])

        retval = P4Node({'name': 'INVALID', 'node_type': 'INVALID'})
        retval.original_node = self
        retval.original_path = '(filter)'
        retval.last_good_node = self
        retval.remaining_path = fun
        return retval

    def of(self, nodes):
        return self._filter(lambda n: n in nodes)

    def not_of(self, nodes):
        return self._filter(lambda n: n not in nodes)


    def map(self, str_or_fun):
        """Maps the function to the node's vector (if it has one) or the node itself (if it doesn't)."""
        if type(path := str_or_fun) is str:
            fun = lambda n: n(path)
        else:
            fun = str_or_fun

        if self.is_vec():
            return P4Node({'node_type': 'Vector'}, [fun(node) for node in self.vec])
        return fun(self)

    def flatmap(self, str_or_fun):
        """Maps the function to the node's vector (if it has one) or the node itself (if it doesn't)."""
        if type(str_or_fun) is str:
            fun = lambda n: n(str_or_fun)
        else:
            fun = str_or_fun

        if self.is_vec():
            return P4Node(list((node2 for node in self.vec for node2 in fun(node))))
        else:
            invalid = P4Node({'name': 'INVALID', 'node_type': 'INVALID'})
            invalid.original_node = original_node
            invalid.original_path = key
            invalid.last_good_node = current_node
            invalid.remaining_path = ".".join(key.split(".")[idx:])
            return invalid

    def sorted(self, key, reverse=False):
        """Sorts the vector of the node (if it has one)."""
        if self.is_vec():
            return P4Node(sorted(self.vec, key=key, reverse=reverse))
        return None

    def json_repr(self, depth=3, max_vector_len=lambda depth: 2 if depth > 2 or depth <= 0 else [8, 4][depth - 1], is_top_level = True):
        if depth <= 0:
            return "..."

        def fld_repr(fldname, prefix=""):
            reprtxt = f'{self.__dict__[fldname]}' if fldname in self.__dict__ else ""
            return f'{prefix}{reprtxt}'

        if self.is_vec():
            maxlen = max_vector_len(depth)
            selflen = len(self.vec)
            repr = [e.json_repr(depth, is_top_level = True) if type(e) is P4Node else e for e in self.vec[:maxlen]]
            if selflen > maxlen:
                repr += [f"({selflen - maxlen} more elements, {selflen} in total)"]
        else:
            repr = {}
            for d in self.xdir(details=False, show_colours=False):
                reprattrname = _c(f".{d}", clr_attrname)
                reprtype = _c(fld_repr('node_type', "#"), clr_nodetype)
                vecpart = _c(f'*{len(subnode)}', clr_count) if (subnode := self.get_attr(d)) and type(subnode) is P4Node and subnode.is_vec() else ''
                reprfld = f"{reprattrname}{reprtype}{vecpart}"

                if type(attr := self.get_attr(d)) is P4Node:
                    repr[reprfld] = attr.json_repr(depth-1, is_top_level = False)
                else:
                    repr[reprfld] = f'{attr}'

        nodename = f"{_c(fld_repr('name'), clr_value)}{_c(fld_repr('node_type', '#'), clr_nodetype)}"

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
            return P4Node({'node_type': '<vec>'}, self.vec + other)
        return P4Node({'node_type': '<vec>'}, self.vec + other.vec)

    def __contains__(self, key):
        """Returns if the node has an attribute for the given key."""
        return (type(key) == str and key in self.__dict__) or (self.vec and key in self.vec)

    def __getattr__(self, key):
        if key == 'urtype':
            return self._urtype()
        if key == 'parent':
            return self._parent()()
        if key == 'parents':
            return self._parents()

        if key.startswith('__') or key == 'vec':
            return object.__getattr__(self, key)

        if key == 'node_type' and 'node_type' not in self.__dict__:
            raise AttributeError(f"Key '{key}' not found in #{self.Node_ID}")

        if key.startswith('_'):
            realkey = key[1:]
            return self.__dict__[realkey] if realkey in self.__dict__ else self

        if 'node_type' in self.__dict__ and self.__dict__['node_type'] == "INVALID":
            return self

        if key not in self.__dict__:
            if 'Node_ID' in self.__dict__:
                raise AttributeError(f"Key '{key}' not found in #{self.Node_ID}@{self.node_type}")
            raise AttributeError(f"Key '{key}' not found in #{self.Node_ID}")

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
            try:
                current_node = getattr(current_node, k)
            except AttributeError:
                invalid = P4Node({'name': 'INVALID', 'node_type': 'INVALID'})
                invalid.original_node = original_node
                invalid.original_path = key
                invalid.last_good_node = current_node
                invalid.remaining_path = ".".join(key.split(".")[idx:])
                return invalid

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
            prev_node = node
            for idx, pathelem in enumerate(path):
                if not isinstance(node, P4Node):
                    retval = P4Node({'name': 'INVALID', 'node_type': 'INVALID'})
                    retval.original_node = node
                    retval.original_path = path
                    retval.last_good_node = prev_node
                    retval.remaining_path = path[idx:]
                    return retval

                prev_node = node
                node = node.get_attr(pathelem)
                if node is None:
                    return None

            return (".".join(path), f'{node}') if type(node) is not P4Node else None


        def follow_paths(attrname, node):
            for path in (split[1:] for p in P4Node.followable_paths if (split := p.split('.'))[0] == attrname):
                if result := follow_path(node, path):
                    return result
            return None

        def short_attrs():
            return (d for d in dir(self) if not d.startswith("__") if d not in P4Node.common_attrs)

        def get_details(d):
            if not details or type(d) not in [str, bytes]:
                return ("", "", clr_value)

            attr = self.get_attr(d)

            if type(attr) is types.FunctionType:
                return ("=", "fun", clr_function)

            if type(attr) is bool:
                return ("=", "✘✓"[attr], clr_value)

            if type(attr) is dict:
                attrlen = len(attr)
                return ("#", attrlen, clr_count if attrlen > 0 else clr_off)

            if type(attr) is not P4Node:
                return ("=", f'{attr}' or '""', clr_value)

            result = follow_paths(d, attr)
            if result is not None:
                return (_c(f".{result[0]}", clr_extrapath) + "=", result[1], clr_value)

            if type(attr.get_attr(d)) is P4Node and attr.get_attr(d).vec is not None:
                attrlen = len(attr.get_attr(d).vec)
                return ("**", attrlen, clr_count if attrlen > 0 else clr_off)

            if attr.vec is None:
                attr_count = sum(1 for ad in attr.__dict__ if ad not in P4Node.common_attrs)
                return (".", attr_count, clr_count if attr_count != 0 else clr_off)

            attrlen = len(attr.vec)
            return ("*", attrlen, clr_count if attrlen > 0 else clr_off)

        def condfun(data):
            """Returns the index of the first condition that holds."""
            _, det = data
            parts = "# ** * .".split(' ')
            conds = [det[0:2] == (part, 0) for part in parts] + [det[0] == part for part in parts] + [True]
            return -list(dropwhile(lambda x: not x[1], enumerate(conds)))[0][0]

        return [_c(d, clr_attrname if attr_details[2] != clr_off else clr_off, show_colours) + attr_details[0] + _c(attr_details[1], attr_details[2], show_colours)
                    for d, attr_details in sorted(((d, get_details(d)) for d in short_attrs()),
                                                  key = condfun)]

    def str(self, show_name=True, show_type=True, show_funs=True, details=True, show_colours=True, depth=0):
        return P4Node.__str__(self, show_name, show_type, show_funs, details, show_colours, depth)

    def get(self, name_or_cond, type_names=[], cond2=lambda node: True):
        """A convenient way to get the element with the given name/condition (and types, if given) in a vector.
        You can impose further limitations on the returned elements with the condition argument.
        """
        if not self.is_vec():
            return None
        if type(type_names) is str:
            type_names = [type_names]
        cond1 = (lambda node: node.get_attr('name') == name_or_cond) if type(name_or_cond) is str else name_or_cond
        potentials = [node for node in self.vec if cond1(node) and (type_names == [] or node.node_type in type_names) if cond2(node)]
        return potentials[0] if len(potentials) == 1 else None


def deep_copy(node, seen_ids = [], on_error = lambda x: None):
    new_p4node = P4Node({'node_type': 'DEEP_COPIED_NODE'})
    new_p4node.is_copied = True

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
