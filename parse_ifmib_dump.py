#!/usr/bin/env python3
"""Parses a real `snmpbulkwalk` capture of IF-MIB's ifTable (OID
1.3.6.1.2.1.2.2, RFC 2863) into ifmib_dump.json.

The capture this was originally run against (ifmib_raw.txt) was genuine:
taken by actually running snmpbulkwalk against a real, locally-started
snmpd (Homebrew's net-snmp 5.9.5.2, configured with a read-only community
and listening on an unprivileged local port -- no root/sudo needed):

    brew install net-snmp
    cat > /tmp/snmpd.conf <<'CONF'
    rocommunity public 127.0.0.1
    agentaddress 127.0.0.1:1161
    CONF
    /opt/homebrew/opt/net-snmp/sbin/snmpd -f -c /tmp/snmpd.conf \
        --persistentDir=/tmp/snmp-persist &
    /opt/homebrew/opt/net-snmp/bin/snmpbulkwalk -v2c -c public -O n \
        127.0.0.1:1161 1.3.6.1.2.1.2 > ifmib_raw.txt

ifmib_raw.txt itself is deliberately NOT committed to this repo: it
contains this machine's real hardware MAC addresses in plaintext, which
only get anonymized by this script, one step later. Regenerate your own
local copy with the commands above if you want to re-run this script
end to end; ifmib_dump.json (this script's output) is the artifact
that's actually committed and used as demo data.

Two columns are deliberately not carried through verbatim:

  - ifPhysAddress (MAC addresses): real MACs identify real hardware, so
    each one is replaced with a deterministic, clearly-synthetic address
    using the locally-administered range (02:00:00:xx:xx:xx) -- everything
    else about the row (name, type, MTU, speed, counters, status) is the
    genuine captured value.
  - ifSpecific: deprecated by RFC 2863, and empty (".0.0") on every row
    here; dropped rather than force it into a type this schema doesn't
    have (it's an OBJECT IDENTIFIER, which isn't one of NodeValue's
    arms -- see node.asn).

Run from the repo root, once ifmib_raw.txt exists there:

    python3 parse_ifmib_dump.py
"""
import json
import re
from pathlib import Path

RAW_PATH = Path(__file__).parent / "ifmib_raw.txt"
OUT_PATH = Path(__file__).parent / "ifmib_dump.json"

LINE_RE = re.compile(
    r"^\.1\.3\.6\.1\.2\.1\.2\.2\.1\.(?P<column>\d+)\.(?P<index>\d+)\s*=\s*"
    r"(?:(?P<type>[A-Za-z0-9]+):\s*)?(?P<value>.*)$"
)

# ifEntry column -> field name (RFC 2863). Column 6 (ifPhysAddress) and 22
# (ifSpecific) are handled specially (see module docstring); 21
# (ifOutQLen) is deprecated/always 0 and dropped for the same reason as
# ifSpecific -- it carries no real information.
COLUMNS = {
    1: "ifIndex",
    2: "ifDescr",
    3: "ifType",
    4: "ifMtu",
    5: "ifSpeed",
    7: "ifAdminStatus",
    8: "ifOperStatus",
    9: "ifLastChangeTicks",
    10: "ifInOctets",
    11: "ifInUcastPkts",
    12: "ifInNUcastPkts",
    13: "ifInDiscards",
    14: "ifInErrors",
    15: "ifInUnknownProtos",
    16: "ifOutOctets",
    17: "ifOutUcastPkts",
    18: "ifOutNUcastPkts",
    19: "ifOutDiscards",
    20: "ifOutErrors",
}

# INTEGER enum columns net-snmp renders as "up(1)" -- strip to the bare
# integer, which is the real value on the wire (the "(1)" is just
# net-snmp's display annotation for the enum label).
ENUM_RE = re.compile(r"^\w+\((-?\d+)\)$")


def parse_value(type_name, raw_value):
    raw_value = raw_value.strip()
    m = ENUM_RE.match(raw_value)
    if m:
        return int(m.group(1))
    if type_name in ("INTEGER", "Counter32", "Counter64", "Gauge32"):
        return int(raw_value)
    if type_name == "Timeticks":
        # "(12345) 0:02:03.45" -> the leading integer (hundredths of a
        # second), which is ifLastChangeTicks's real wire value.
        m2 = re.match(r"^\((\d+)\)", raw_value)
        return int(m2.group(1)) if m2 else 0
    return raw_value  # STRING and anything else: keep as text


def synthetic_mac(if_index):
    # Locally-administered range (the "02" first octet's low bit pattern
    # marks it as administratively assigned, never a real vendor OUI), so
    # it's unambiguous that this isn't a genuine hardware address.
    return "02:00:00:%02x:%02x:%02x" % ((if_index >> 16) & 0xFF, (if_index >> 8) & 0xFF, if_index & 0xFF)


def main():
    rows = {}  # ifIndex -> {field: value}
    with open(RAW_PATH) as f:
        for line in f:
            line = line.rstrip("\n")
            m = LINE_RE.match(line)
            if not m:
                continue
            column = int(m.group("column"))
            index = int(m.group("index"))
            type_name = m.group("type")
            raw_value = m.group("value")

            if column == 22:  # ifSpecific: deprecated, always empty here
                continue
            if column == 21:  # ifOutQLen: deprecated, always 0
                continue

            row = rows.setdefault(index, {})
            if column == 6:  # ifPhysAddress: anonymize
                row["ifPhysAddress"] = synthetic_mac(index)
                continue
            field = COLUMNS.get(column)
            if field is None:
                continue
            row[field] = parse_value(type_name, raw_value)

    interfaces = [rows[i] for i in sorted(rows)]

    with open(OUT_PATH, "w") as f:
        json.dump({"interfaces": interfaces}, f, indent=2)
        f.write("\n")

    print(f"wrote {len(interfaces)} interfaces to {OUT_PATH}")


if __name__ == "__main__":
    main()
