"""Sample node tree served by server.py, derived from demo_data.json.

demo_data.json is plain, ordinary JSON -- it has no notion of "Node",
"key", "value" or "children" of its own. The tree is derived entirely
from its structure and attribute names:

  - an object's properties each become a node, keyed by the property
    name; the property's value becomes that node's value (if a scalar)
    or its children (if a nested object/array)
  - an array is transparent: it introduces no node of its own. Each
    element becomes node(s) using the SAME enclosing key. So an array
    of objects becomes one sibling node per element -- each keyed by
    the array's own property name, with that element's own properties
    as its children -- not one node holding all the elements' data.

For example, `{"users": [{"user": "alice", "group": "admin"}, ...]}`
produces one "users" node per array element (each with "user"/"group"
children), not a single "users" node listing the users directly.
"""
import json
from pathlib import Path

DATA_PATH = Path(__file__).parent / "demo_data.json"


def _scalar_to_bytes(value):
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    return text.encode("utf-8")


def _nodes_for(key, value):
    """The list of Node dicts representing `value`, reached under the
    enclosing property name `key` (None only at the very top of the
    document, where there is no enclosing name)."""
    if isinstance(value, list):
        nodes = []
        for item in value:
            nodes.extend(_nodes_for(key, item))
        return nodes

    if isinstance(value, dict):
        children = []
        for child_key, child_value in value.items():
            children.extend(_nodes_for(child_key, child_value))
        if key is None:
            # No enclosing name (the document root): nothing to key a
            # wrapper node with, so these properties become the tree
            # root's children directly.
            return children
        return [{"key": key, "value": b"", "children": children}]

    # A scalar (or null) needs a key, which a bare top-level scalar
    # wouldn't have -- not a shape our demo data uses.
    if key is None:
        raise ValueError("a top-level scalar has no attribute name to use as its key")
    return [{"key": key, "value": _scalar_to_bytes(value), "children": []}]


def _load_tree(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {"key": "/", "value": b"", "children": _nodes_for(None, raw)}


DEMO_TREE = _load_tree(DATA_PATH)
