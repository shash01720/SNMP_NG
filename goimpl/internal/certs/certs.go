// Package certs generates a throwaway self-signed TLS certificate for the
// demo server. QUIC mandates TLS 1.3 (RFC 9001); this is not a production
// certificate story (no CA, no client verification) -- see the mTLS design
// discussion referenced in the project's README for what a real deployment
// would need instead.
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
// client could otherwise verify against; a real deployment needs real
// certificate (or raw-public-key, per the mTLS design discussion)
// verification instead.
func ClientConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"nodetree-quic/1"},
	}
}
