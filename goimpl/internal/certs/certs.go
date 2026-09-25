// Package certs supplies the TLS configuration for NodeTree's QUIC
// connections (QUIC mandates TLS 1.3, RFC 9001). pki.go is the real path:
// a small CA and leaf-certificate toolkit plus mutual-TLS server and client
// configs, where a client certificate's CommonName is its identity. This
// file is the demo fallback used when no certificates are configured: a
// throwaway self-signed server certificate and a client that skips
// verification. It authenticates nothing.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// GenerateSelfSigned returns a tls.Config presenting a fresh, in-memory
// self-signed certificate for "localhost" / 127.0.0.1, suitable for the
// server side of a demo QUIC connection.
func GenerateSelfSigned() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nodetree-demo"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"nodetree-quic/1"},
	}, nil
}

// ClientConfig returns a tls.Config for the demo client. InsecureSkipVerify
// is deliberate here -- this is a throwaway self-signed cert with no CA a
// client could otherwise verify against. Use ClientTLSConfig (pki.go) to
// verify the server against a real CA.
func ClientConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"nodetree-quic/1"},
	}
}
