// Command server runs the NodeTree QUIC server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/quic-go/quic-go"

	"github.com/shashi/snmp-ng/goimpl/internal/certs"
	"github.com/shashi/snmp-ng/goimpl/internal/server"
	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

func overrideSuffix(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(", max-datagram-size override=%d", n)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8515", "UDP address to listen on")
	maxDatagramSize := flag.Int("max-datagram-size", 0,
		"override the auto-discovered per-datagram payload budget (bytes); "+
			"mainly for testing/demoing truncation, since a real path's limit "+
			"is far larger than this demo's small tree would ever exceed")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tlsConf, err := certs.GenerateSelfSigned()
	if err != nil {
		log.Fatalf("generating TLS cert: %v", err)
	}

	ln, err := quic.ListenAddr(*addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := server.New()
	srv.MaxDatagramSizeOverride = *maxDatagramSize
	seedDemoData(srv)

	log.Printf("[server] listening on %s (QUIC)%s", *addr, overrideSuffix(*maxDatagramSize))
	if err := srv.Run(ctx, ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
	log.Printf("[server] shut down")
}

// seedDemoData populates the same demo tree shape used by the Python
// reference implementation's demo_data.json, so the two implementations'
// demos are easy to compare -- translated by hand here, since this Go tree
// uses typed wire.NodeValue rather than the Python side's plain bytes.
func seedDemoData(srv *server.Server) {
	t := srv.Tree
	for _, u := range []struct{ user, group string }{
		{"alice", "admin"}, {"bob", "user"}, {"carol", "user"},
	} {
		usersNode := t.AppendUnder(t.Root, "users", wire.NoValue())
		t.AppendUnder(usersNode, "user", wire.StringValue(u.user))
		t.AppendUnder(usersNode, "group", wire.StringValue(u.group))
	}
	config := t.AppendUnder(t.Root, "config", wire.NoValue())
	t.AppendUnder(config, "timeout", wire.Integer32Value(30))
	t.AppendUnder(config, "retries", wire.Integer32Value(3))
}
