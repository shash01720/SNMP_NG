"""Sample node tree served by server.py, loaded from demo_data.json.

JSON has no byte-string type, so each node's "value" is stored as a
plain JSON string and UTF-8 encoded here into the `bytes` that the rest
of the code treats as the Node's OCTET STRING value.
"""
import json
from pathlib import Path

DATA_PATH = Path(__file__).parent / "demo_data.json"


def _convert(raw_node):
    return {
        "key": raw_node["key"],
        "value": raw_node.get("value", "").encode("utf-8"),
        "children": [_convert(child) for child in raw_node.get("children", [])],
    }


def _load_tree(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return _convert(raw)


DEMO_TREE = _load_tree(DATA_PATH)
