
# HLIR for P4-16

This program uses [`p4c`](https://github.com/p4lang/p4c) to generate a temporary JSON file
from a `.p4` source file, loads it,
and creates a convenient Python representation out of it.

Supposing that the environment variable `P4C` contains the path to `p4c`
and/or `T4P4S` to the [T4P4S compiler](https://github.com/P4ELTE/t4p4s)
(either the P4-14 based version, or the experimental P4-16 based one,
which uses this library),
you can run the example the following way.
It requires Python 3.

~~~.bash
python test_hlir.py "$P4C/testdata/p4_16_samples/vss-example.p4" 16

python test_hlir.py "$T4P4S/examples/l2_switch_test.p4" 14
~~~

Note that the program accesses some arbitrary elements of the representation.
If you load different files, their structure will be different as well,
and you might get an exception because you're trying to access non-existing constructs.


# Gathering data

The following parts presume that you are using `ipdb` for debugging.
You can manually add a debug trigger the following way.

~~~
import ipdb; ipdb.set_trace()
~~~

A convenient place to start an investigation is at the end of `set_additional_attrs` in `hlir_attrs.py`.

## Search by content

Let us assume that the root node of the representation is loaded into a variable called `hlir`.

Starting at this node (or any other one), you can search for all occurrences of a string/integer/etc. using the `/` operator. It can also take a node as the second argument, but beware that many nodes are automatically generated (their `Node_ID`s are negative), and even if a node has the same content, it won't be found this way.

Also consider using the potentially more useful `//` operator, which lists the results by length of path.

Note: if you start the search from `hlir`, it might take awhile to finish. Starting from 

~~~
hlir / 'ethernet'
hlir / 1234567
hlir / some_node

hlir // 'ethernet'
hlir // 1234567
hlir // some_node
~~~

These operators are abbreviations of the function `paths_to`.

~~~
hl[TAB]
hlir.p[TAB]
hlir.paths_to('ethernet')
hlir.paths_to(1234567)
hlir.paths_to(some_node)

hlir.paths_to('ethernet', sort_by_path_length=True)
hlir.paths_to(1234567, sort_by_path_length=True)
hlir.paths_to(some_node, sort_by_path_length=True)
~~~

The result will look something like this.

~~~
  = .objects['Type_Header'][0]
  < .objects['Type_Struct'][4].fields
  ∈ .objects['P4Parser'][0].states['ParserState'][0].components['MethodCallStatement'][0].methodCall.arguments['Member'][0].expr.type.fields
  < .objects['P4Parser'][0].states['ParserState'][0].components['MethodCallStatement'][0].methodCall.arguments['Member'][0].member
  < .objects['P4Parser'][0].states['ParserState'][0].components['MethodCallStatement'][0].methodCall.arguments['Member'][0].type
  < .objects['P4Parser'][0].states['ParserState'][0].components['MethodCallStatement'][0].methodCall.typeArguments['Type_Name'][0].path
  < .objects['P4Parser'][0].states['ParserState'][0].selectExpression.select.components['Member'][0].expr.expr.type.fields
  < .objects['P4Parser'][0].states['ParserState'][0].selectExpression.select.components['Member'][0].expr.member
...........
~~~

The first character indicates if the searched content is (textually) a perfect match (`=`), a prefix (`<`) or an infix (`∈`) of the result of the path.

You can copy-paste a line of the result, and inspect the element there.

~~~
ipdb> hlir.objects['P4Parser'][0].states['ParserState'][0].components['MethodCallStatement'][0].methodCall.arguments['Member'][0].type
ethernet_t<Type_Header>[annotations, declid, fields, name]
~~~


## Pretty printing nodes

To pretty print a node, you may use the "postfix heart operator".

~~~
hlir <3
~~~

This, in fact, is a call to the "less than" operator.
This operator uses the `json_repr` function internally, and turns it into a nice, YAML based output.

~~~
hlir < 3
hlir < 4
~~~


# Attributes

The nodes get their attributes in the following ways.

1. At creation, see `p4node.py`.
    - In the debugger, enter `hlir.common_attrs` to see them.
1. Most attributes are directly loaded from the JSON file.
    - See `load_p4` in `hlir.py`.
    - The `.json` file is produced using the `--toJSON` option of the P4 frontend `p4test`.
      By default, this is a temporary file that is deleted upon exit.
1. Many attributes are set in `set_additional_attrs` in `hlir.py`.
   While the compiler is in the experimental stage,
   they may be subject to change, but once it crystallizes,
   they will be considered standard.
1. You can manually add attributes using `add_attrs`, but those will be considered non-standard,
   and will not be portable in general.

The representation contains internal nodes (of type `P4Node`)
and leaves (primitives like ints and strings).
Internal nodes will sometimes be (ordered) vectors.

Some of the more important attributes are the following.

~~~
hl[TAB].d[TAB]        # expands to...
hlir.objects   # these are the top-level objects in the program

ds = hlir.objects
ds.is_vec()           # True
ds[0]                 # indexes the vector; the first declaration in the program
ds.b[TAB]             # expands to...
ds.by_type('Type_Struct')   # gives you all 'Type_Struct' objects
ds.by_type('Struct')        # shortcut; many things are called 'Type_...'
ds.get('name')        # all elems in the vector with the name 'name'
ds.get('ipv4_t', 'Type_Header')   # the same, limited to the given type

any_node.name         # most nodes (but not all) have names
any_node.xdir()       # names of the node's non-common attributes
~~~

# Special attributes

The following attributes are added by `hlir_attrs`.

- `urtype`: the "base type" of a node; instead of having to use long chains of `.type.baseType.type_ref...` attributes, it takes you up there directly
- `parent()`: the parent node on the attribute chain from the root node; in case the node can be reached in many ways from the root, the parent found first is returned
- `parents`: the (first) parent chain from the root to the node

# Reorganised attributes 

When loaded initially, `hlir` contains `hlir.objects`. These nodes are separated by `hlir_attrs` into groups under `hlir.object_groups`.

# Special attribute operators

When traversing several attributes like `node.type.type_ref.size`, sometimes a part of the chain is optional; in certain cases, `node.type.size` will contain the appropriate value, that is, `type_ref` is not present at `node.type` and should not be in the chain.

- Writing `node.type._type_ref.size` will get the proper attribute value.
    - Note the underscore prefix in `_type_ref`.
    - This attribute chain will first get `node.type`. Let's call this node `node2`.
    - Starting from `node2`, `type_ref` is traversed if it is present. If `node2` doesn't have the `type_ref` attribute, `node.type._type_ref` evaluates to `node2` itself.
    - Going on from the reached node, the `size` attribute is traversed.
- For this to work, we assume that no attribute begins with an underscore.

In some cases, an attribute chain cannot be continued if an attribute is missing. For example, `e.expr.header_ref.type.type_ref.is_metadata` may only be meaningful if `header_ref` is present under `e.expr`.

- Writing `e.expr('header_ref.type.type_ref.is_metadata')` will get the proper attribute value.
    - The call operator will return an invalid `P4Node` object if the chain in its string argument cannot be fully traversed.
    - The invalid node is falsy. For example, you may use it as `if not e.expr('header_ref.type.type_ref.is_metadata'):`.
    - The invalid node contains some attributes about where the chain was broken, the last valid node reached in the chain etc.
- It is also possible to write `e.expr('header_ref.type.type_ref.is_metadata', lambda ismeta: not ismeta)`.
    - Here, the expression evaluates to the value returned by the lambda, which is invoked on the node reached at the end of the chain.
    - If the chain is broken, the invalid `P4Node` object is returned as before.
