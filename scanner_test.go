package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func generateCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}

	return tlsCert, pool
}

func TestScanTLS_FeasibleServer(t *testing.T) {
	origPort := port
	origTimeout := timeout
	defer func() {
		port = origPort
		timeout = origTimeout
	}()
	timeout = 5

	tlsCert, _ := generateCert(t)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := li.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates:     []tls.Certificate{tlsCert},
				MinVersion:       tls.VersionTLS13,
				NextProtos:       []string{"h2"},
				CurvePreferences: []tls.CurveID{tls.X25519},
			})
			_ = tlsConn.Handshake()
			_ = tlsConn.Close()
		}
	}()
	defer li.Close()

	port = li.Addr().(*net.TCPAddr).Port

	outCh := make(chan string, 10)
	geo := NewGeo()

	host := Host{
		IP:     net.ParseIP("127.0.0.1"),
		Origin: "127.0.0.1",
		Type:   HostTypeIP,
	}

	ScanTLS(host, outCh, geo)

	select {
	case result := <-outCh:
		if !strings.Contains(result, "127.0.0.1") {
			t.Errorf("output should contain IP, got %q", result)
		}
		if !strings.Contains(result, "test.example.com") {
			t.Errorf("output should contain cert domain, got %q", result)
		}
		if !strings.Contains(result, "Test Org") {
			t.Errorf("output should contain cert issuer, got %q", result)
		}
	default:
		t.Error("expected output on outCh but got none (server may not be feasible)")
	}
}

func TestScanTLS_UnreachableHost(t *testing.T) {
	origPort := port
	origTimeout := timeout
	defer func() {
		port = origPort
		timeout = origTimeout
	}()
	timeout = 1
	port = 1

	outCh := make(chan string, 10)
	geo := NewGeo()

	host := Host{
		IP:     net.ParseIP("192.0.2.1"),
		Origin: "192.0.2.1",
		Type:   HostTypeIP,
	}

	ScanTLS(host, outCh, geo)

	select {
	case <-outCh:
		t.Error("should not produce output for unreachable host")
	default:
	}
}

func TestScanTLS_DomainHost(t *testing.T) {
	origPort := port
	origTimeout := timeout
	defer func() {
		port = origPort
		timeout = origTimeout
	}()
	timeout = 5

	tlsCert, _ := generateCert(t)

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := li.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates:     []tls.Certificate{tlsCert},
				MinVersion:       tls.VersionTLS13,
				NextProtos:       []string{"h2"},
				CurvePreferences: []tls.CurveID{tls.X25519},
			})
			_ = tlsConn.Handshake()
			_ = tlsConn.Close()
		}
	}()
	defer li.Close()

	port = li.Addr().(*net.TCPAddr).Port

	outCh := make(chan string, 10)
	geo := NewGeo()

	host := Host{
		IP:     nil,
		Origin: "127.0.0.1",
		Type:   HostTypeDomain,
	}

	ScanTLS(host, outCh, geo)

	select {
	case result := <-outCh:
		if !strings.Contains(result, "127.0.0.1") {
			t.Errorf("output should contain resolved IP, got %q", result)
		}
		if !strings.Contains(result, "test.example.com") {
			t.Errorf("output should contain cert domain, got %q", result)
		}
	default:
		t.Error("expected output on outCh for domain host")
	}
}

func TestScanTLS_NonFeasibleALPN(t *testing.T) {
	origPort := port
	origTimeout := timeout
	defer func() {
		port = origPort
		timeout = origTimeout
	}()
	timeout = 5

	tlsCert, _ := generateCert(t)

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := li.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates:     []tls.Certificate{tlsCert},
				MinVersion:       tls.VersionTLS13,
				NextProtos:       []string{"http/1.1"},
				CurvePreferences: []tls.CurveID{tls.X25519},
			})
			_ = tlsConn.Handshake()
			_ = tlsConn.Close()
		}
	}()
	defer li.Close()

	port = li.Addr().(*net.TCPAddr).Port

	outCh := make(chan string, 1)
	geo := NewGeo()

	host := Host{
		IP:     net.ParseIP("127.0.0.1"),
		Origin: "127.0.0.1",
		Type:   HostTypeIP,
	}

	ScanTLS(host, outCh, geo)

	select {
	case result := <-outCh:
		t.Fatalf("unexpected output for non-feasible host: %q", result)
	default:
	}
}
