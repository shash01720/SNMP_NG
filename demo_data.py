"""Sample node tree served by server.py."""

DEMO_TREE = {
    "key": "root",
    "value": b"",
    "children": [
        {
            "key": "users",
            "value": b"",
            "children": [
                {"key": "alice", "value": b"admin", "children": []},
                {"key": "bob", "value": b"user", "children": []},
                {"key": "carol", "value": b"user", "children": []},
            ],
        },
        {
            "key": "config",
            "value": b"",
            "children": [
                {"key": "timeout", "value": b"30", "children": []},
                {"key": "retries", "value": b"3", "children": []},
            ],
        },
    ],
}
