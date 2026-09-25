// Command server runs the NodeTree QUIC server.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/shashi/snmp-ng/goimpl/internal/authz"
	"github.com/shashi/snmp-ng/goimpl/internal/certs"
	"github.com/shashi/snmp-ng/goimpl/internal/server"
	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

// maxIdleTimeout/keepAlivePeriod: quic-go's own default (30s idle timeout,
// no keep-alive) is enough to silently drop a long-lived, low-traffic
// connection -- exactly what an onChange Query sitting quietly between
// rare events needs to survive. Set explicitly here (rather than relying
// on the implicit default) so the relationship between the two is
// intentional: quic-go clamps any keep-alive period to at most half of
// MaxIdleTimeout, so 10s against a 30s idle timeout leaves real margin for
// a lost keep-alive packet or scheduling jitter before the connection
// would actually be at risk.
const (
	maxIdleTimeout  = 30 * time.Second
	keepAlivePeriod = 10 * time.Second
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
	tlsCert := flag.String("tls-cert", "", "server certificate (PEM); with -tls-key. Omit for a throwaway self-signed demo certificate")
	tlsKey := flag.String("tls-key", "", "server private key (PEM)")
	clientCA := flag.String("client-ca", "", "CA certificate (PEM) that client certificates must chain to; enables mutual TLS, and each client's certificate CommonName becomes its identity")
	policyFile := flag.String("policy", "", "access-control policy (JSON, see internal/authz); omit for open mode")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var tlsConf *tls.Config
	var err error
	switch {
	case *tlsCert != "" || *tlsKey != "":
		tlsConf, err = certs.ServerTLSConfig(*tlsCert, *tlsKey, *clientCA)
		if err != nil {
			log.Fatalf("loading TLS config: %v", err)
		}
	case *clientCA != "":
		log.Fatalf("-client-ca needs -tls-cert and -tls-key: a demo certificate can't be verified by clients")
	default:
		tlsConf, err = certs.GenerateSelfSigned()
		if err != nil {
			log.Fatalf("generating TLS cert: %v", err)
		}
		log.Printf("[server] WARNING: throwaway self-signed certificate and no client authentication; every client is %q", "anonymous")
	}
	if *tlsCert != "" && *clientCA == "" {
		log.Printf("[server] WARNING: -client-ca not set, so clients are not authenticated; every client is %q", "anonymous")
	}

	ln, err := quic.ListenAddr(*addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  maxIdleTimeout,
		KeepAlivePeriod: keepAlivePeriod,
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := server.New()
	if *policyFile != "" {
		if srv.Policy, err = authz.Load(*policyFile); err != nil {
			log.Fatalf("loading policy: %v", err)
		}
		log.Printf("[server] access-control policy loaded from %s", *policyFile)
	} else {
		log.Printf("[server] no -policy: open mode (session isolation still enforced)")
	}
	srv.MaxDatagramSizeOverride = *maxDatagramSize
	seedDemoData(srv)
	seedIfMib(srv)

	log.Printf("[server] listening on %s (QUIC)%s", *addr, overrideSuffix(*maxDatagramSize))
	if err := srv.Run(ctx, ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
	log.Printf("[server] shut down")
}

// seedDemoData populates a small demo tree of users and config values,
// using typed wire.NodeValue.
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
