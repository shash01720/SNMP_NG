package certs

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type pkiDir struct{ dir string }

func (p pkiDir) f(name string) string { return filepath.Join(p.dir, name) }

func mkCA(t *testing.T, dir, name string) {
	t.Helper()
	c, k, err := NewCA(name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, name+".pem"), c, 0o644)
	os.WriteFile(filepath.Join(dir, name+"-key.pem"), k, 0o600)
}

func issue(t *testing.T, dir, ca, cn string, server bool) {
	t.Helper()
	cc, _ := os.ReadFile(filepath.Join(dir, ca+".pem"))
	ck, _ := os.ReadFile(filepath.Join(dir, ca+"-key.pem"))
	c, k, err := IssueCert(cc, ck, cn, server, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, cn+".pem"), c, 0o644)
	os.WriteFile(filepath.Join(dir, cn+"-key.pem"), k, 0o600)
}

// tcpPair returns the two ends of a loopback TCP connection. (net.Pipe is
// unbuffered, so a TLS alert write blocks until the peer reads, which
// deadlocks the rejection cases.)
func tcpPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() { c, err := ln.Accept(); ch <- acc{c, err} }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	if a.err != nil {
		t.Fatal(a.err)
	}
	deadline := time.Now().Add(5 * time.Second)
	a.c.SetDeadline(deadline)
	client.SetDeadline(deadline)
	t.Cleanup(func() { a.c.Close(); client.Close() })
	return a.c, client
}

// handshake runs a TLS 1.3 handshake and returns the identity the server
// saw, or the server's error if it rejected the client.
func handshake(t *testing.T, srv, cli *tls.Config) (string, error) {
	t.Helper()
	a, b := tcpPair(t)
	type res struct {
		id  string
		err error
	}
	sc := make(chan res, 1)
	go func() {
		s := tls.Server(a, srv)
		err := s.Handshake()
		sc <- res{PeerIdentity(s.ConnectionState()), err}
		a.Close()
	}()
	c := tls.Client(b, cli)
	if c.Handshake() == nil {
		// TLS 1.3: the client can finish before the server has validated its
		// certificate; a rejection surfaces on the server side.
		c.Write([]byte("x"))
		c.Read(make([]byte, 1))
	}
	r := <-sc
	return r.id, r.err
}

func TestMutualTLSIdentity(t *testing.T) {
	dir := t.TempDir()
	p := pkiDir{dir}
	mkCA(t, dir, "ca")
	mkCA(t, dir, "rogue")
	issue(t, dir, "ca", "server", true)
	issue(t, dir, "ca", "alice", false)
	issue(t, dir, "rogue", "mallory", false)

	srv, err := ServerTLSConfig(p.f("server.pem"), p.f("server-key.pem"), p.f("ca.pem"))
	if err != nil {
		t.Fatal(err)
	}

	alice, err := ClientTLSConfig(p.f("alice.pem"), p.f("alice-key.pem"), p.f("ca.pem"), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	id, err := handshake(t, srv, alice)
	if err != nil || id != "alice" {
		t.Fatalf("identity = %q, err = %v; want alice", id, err)
	}

	anon, _ := ClientTLSConfig("", "", p.f("ca.pem"), "localhost")
	if id, err := handshake(t, srv, anon); err == nil {
		t.Fatalf("a client with no certificate was accepted as %q", id)
	}

	mallory, _ := ClientTLSConfig(p.f("mallory.pem"), p.f("mallory-key.pem"), p.f("ca.pem"), "localhost")
	if id, err := handshake(t, srv, mallory); err == nil {
		t.Fatalf("a client certificate from another CA was accepted as %q", id)
	}
}

func TestClientRejectsServerFromWrongCA(t *testing.T) {
	dir := t.TempDir()
	p := pkiDir{dir}
	mkCA(t, dir, "ca")
	mkCA(t, dir, "rogue")
	issue(t, dir, "rogue", "server", true)
	srv, _ := ServerTLSConfig(p.f("server.pem"), p.f("server-key.pem"), "")
	cli, _ := ClientTLSConfig("", "", p.f("ca.pem"), "localhost")
	a, b := tcpPair(t)
	go func() { tls.Server(a, srv).Handshake(); a.Close() }()
	if err := tls.Client(b, cli).Handshake(); err == nil {
		t.Fatal("client accepted a server certificate not signed by its CA")
	}
}
