package main

import (
	_ "embed"
	"encoding/json"
	"log"

	"github.com/shash01720/SNMP_NG/goimpl/internal/server"
	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

// ifmib_dump.json is a real snmpbulkwalk capture of IF-MIB's ifTable (RFC
// 2863), taken against a real, locally-run snmpd -- not fabricated or
// scraped. See ../../../parse_ifmib_dump.py for how it was produced from
// the raw walk, and its docstring for the one thing deliberately not
// carried through verbatim: real MAC addresses (ifPhysAddress) are
// replaced with deterministic, clearly-synthetic ones in the
// locally-administered range. This is a copy of the repo root's
// ifmib_dump.json, embedded here rather than read at runtime so the
// server doesn't depend on its working directory.
//
//go:embed ifmib_dump.json
var ifmibDumpJSON []byte

type ifmibRow struct {
	IfIndex           int    `json:"ifIndex"`
	IfDescr           string `json:"ifDescr"`
	IfType            int    `json:"ifType"`
	IfMtu             int    `json:"ifMtu"`
	IfSpeed           int64  `json:"ifSpeed"`
	IfPhysAddress     string `json:"ifPhysAddress"`
	IfAdminStatus     int    `json:"ifAdminStatus"`
	IfOperStatus      int    `json:"ifOperStatus"`
	IfLastChangeTicks int64  `json:"ifLastChangeTicks"`
	IfInOctets        int64  `json:"ifInOctets"`
	IfInUcastPkts     int64  `json:"ifInUcastPkts"`
	IfInNUcastPkts    int64  `json:"ifInNUcastPkts"`
	IfInDiscards      int64  `json:"ifInDiscards"`
	IfInErrors        int64  `json:"ifInErrors"`
	IfInUnknownProtos int64  `json:"ifInUnknownProtos"`
	IfOutOctets       int64  `json:"ifOutOctets"`
	IfOutUcastPkts    int64  `json:"ifOutUcastPkts"`
	IfOutNUcastPkts   int64  `json:"ifOutNUcastPkts"`
	IfOutDiscards     int64  `json:"ifOutDiscards"`
	IfOutErrors       int64  `json:"ifOutErrors"`
}

// seedIfMib adds one "interfaces" node per captured row under t.Root, each
// with its own children typed per real IF-MIB column semantics (RFC
// 2863) -- Integer32 for ifIndex/ifType/ifMtu/ifAdminStatus/ifOperStatus,
// Unsigned32 for ifSpeed (Gauge32 in the real MIB; see node.asn's
// NodeValue docs on why this schema maps Gauge32 to unsigned32),
// TimeTicks for ifLastChangeTicks, Counter32 for every packet/octet/error
// counter, and OctetString for the two text fields (ifDescr,
// ifPhysAddress). This is a deliberately richer, more realistic dataset
// than the toy users/config demo (kept alongside it, not replacing it),
// and a good showcase for the typed NodeValue system.
func seedIfMib(srv *server.Server) {
	var doc struct {
		Interfaces []ifmibRow `json:"interfaces"`
	}
	if err := json.Unmarshal(ifmibDumpJSON, &doc); err != nil {
		log.Fatalf("parsing embedded ifmib_dump.json: %v", err)
	}

	t := srv.Tree
	for _, row := range doc.Interfaces {
		n := t.AppendUnder(t.Root, "interfaces", wire.NoValue())
		t.AppendUnder(n, "ifIndex", wire.Integer32Value(int32(row.IfIndex)))
		t.AppendUnder(n, "ifDescr", wire.StringValue(row.IfDescr))
		t.AppendUnder(n, "ifType", wire.Integer32Value(int32(row.IfType)))
		t.AppendUnder(n, "ifMtu", wire.Integer32Value(int32(row.IfMtu)))
		t.AppendUnder(n, "ifSpeed", wire.Unsigned32Value(uint32(row.IfSpeed)))
		t.AppendUnder(n, "ifPhysAddress", wire.StringValue(row.IfPhysAddress))
		t.AppendUnder(n, "ifAdminStatus", wire.Integer32Value(int32(row.IfAdminStatus)))
		t.AppendUnder(n, "ifOperStatus", wire.Integer32Value(int32(row.IfOperStatus)))
		t.AppendUnder(n, "ifLastChangeTicks", wire.TimeTicksValue(uint32(row.IfLastChangeTicks)))
		t.AppendUnder(n, "ifInOctets", wire.Counter32Value(uint32(row.IfInOctets)))
		t.AppendUnder(n, "ifInUcastPkts", wire.Counter32Value(uint32(row.IfInUcastPkts)))
		t.AppendUnder(n, "ifInNUcastPkts", wire.Counter32Value(uint32(row.IfInNUcastPkts)))
		t.AppendUnder(n, "ifInDiscards", wire.Counter32Value(uint32(row.IfInDiscards)))
		t.AppendUnder(n, "ifInErrors", wire.Counter32Value(uint32(row.IfInErrors)))
		t.AppendUnder(n, "ifInUnknownProtos", wire.Counter32Value(uint32(row.IfInUnknownProtos)))
		t.AppendUnder(n, "ifOutOctets", wire.Counter32Value(uint32(row.IfOutOctets)))
		t.AppendUnder(n, "ifOutUcastPkts", wire.Counter32Value(uint32(row.IfOutUcastPkts)))
		t.AppendUnder(n, "ifOutNUcastPkts", wire.Counter32Value(uint32(row.IfOutNUcastPkts)))
		t.AppendUnder(n, "ifOutDiscards", wire.Counter32Value(uint32(row.IfOutDiscards)))
		t.AppendUnder(n, "ifOutErrors", wire.Counter32Value(uint32(row.IfOutErrors)))
	}
	log.Printf("[server] seeded %d IF-MIB interface(s) from a real snmpbulkwalk capture", len(doc.Interfaces))
}
