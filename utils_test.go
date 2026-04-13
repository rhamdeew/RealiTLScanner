package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestExistOnlyOne(t *testing.T) {
	tests := []struct {
		name string
		arr  []string
		want bool
	}{
		{"single non-empty", []string{"a", "", ""}, true},
		{"single non-empty middle", []string{"", "b", ""}, true},
		{"single non-empty last", []string{"", "", "c"}, true},
		{"all empty", []string{"", "", ""}, false},
		{"two non-empty", []string{"a", "b", ""}, false},
		{"all non-empty", []string{"a", "b", "c"}, false},
		{"empty slice", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExistOnlyOne(tt.arr); got != tt.want {
				t.Errorf("ExistOnlyOne(%v) = %v, want %v", tt.arr, got, tt.want)
			}
		})
	}
}

func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"valid domain", "example.com", true},
		{"valid subdomain", "sub.example.com", true},
		{"valid with hyphen", "my-domain.example.com", true},
		{"valid with numbers", "example123.com", true},
		{"empty string", "", false},
		{"with spaces", "example .com", false},
		{"with underscore", "example_domain.com", false},
		{"single label", "localhost", true},
		{"with port", "example.com:443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateDomainName(tt.domain); got != tt.want {
				t.Errorf("ValidateDomainName(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestRemoveDuplicateStr(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"empty slice", []string{}, nil},
		{"all same", []string{"x", "x", "x"}, []string{"x"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RemoveDuplicateStr(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("RemoveDuplicateStr(%v) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("RemoveDuplicateStr(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNextIP(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		increment bool
		want      string
	}{
		{"increment IPv4", "192.168.1.1", true, "192.168.1.2"},
		{"decrement IPv4", "192.168.1.2", false, "192.168.1.1"},
		{"increment boundary", "192.168.1.255", true, "192.168.2.0"},
		{"decrement boundary", "192.168.2.0", false, "192.168.1.255"},
		{"increment from zero", "0.0.0.0", true, "0.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := NextIP(ip, tt.increment)
			if got.String() != tt.want {
				t.Errorf("NextIP(%v, %v) = %v, want %v", tt.ip, tt.increment, got, tt.want)
			}
		})
	}
}

func TestNextIP_IPv6(t *testing.T) {
	ip := net.ParseIP("::1")
	next := NextIP(ip, true)
	if !next.Equal(net.ParseIP("::2")) {
		t.Errorf("NextIP(::1, true) = %v, want ::2", next)
	}
	prev := NextIP(ip, false)
	if !prev.Equal(net.ParseIP("::")) {
		t.Errorf("NextIP(::1, false) = %v, want ::", prev)
	}
}

func TestIterate_IPv4(t *testing.T) {
	enableIPv6 = false
	input := "1.2.3.4\n5.6.7.8\n"
	hosts := collectHosts(t, strings.NewReader(input))

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0].IP.String() != "1.2.3.4" {
		t.Errorf("hosts[0].IP = %v, want 1.2.3.4", hosts[0].IP)
	}
	if hosts[0].Type != HostTypeIP {
		t.Errorf("hosts[0].Type = %v, want HostTypeIP", hosts[0].Type)
	}
	if hosts[1].IP.String() != "5.6.7.8" {
		t.Errorf("hosts[1].IP = %v, want 5.6.7.8", hosts[1].IP)
	}
}

func TestIterate_CIDR(t *testing.T) {
	enableIPv6 = false
	input := "192.168.1.0/30\n"
	hosts := collectHosts(t, strings.NewReader(input))

	if len(hosts) != 4 {
		t.Fatalf("expected 4 hosts for /30, got %d", len(hosts))
	}
	expected := []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
	for i, h := range hosts {
		if h.IP.String() != expected[i] {
			t.Errorf("hosts[%d].IP = %v, want %v", i, h.IP, expected[i])
		}
		if h.Type != HostTypeCIDR {
			t.Errorf("hosts[%d].Type = %v, want HostTypeCIDR", i, h.Type)
		}
	}
}

func TestIterate_Domain(t *testing.T) {
	enableIPv6 = false
	input := "example.com\n"
	hosts := collectHosts(t, strings.NewReader(input))

	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].IP != nil {
		t.Errorf("hosts[0].IP should be nil for domain, got %v", hosts[0].IP)
	}
	if hosts[0].Origin != "example.com" {
		t.Errorf("hosts[0].Origin = %q, want %q", hosts[0].Origin, "example.com")
	}
	if hosts[0].Type != HostTypeDomain {
		t.Errorf("hosts[0].Type = %v, want HostTypeDomain", hosts[0].Type)
	}
}

func TestIterate_EmptyLines(t *testing.T) {
	enableIPv6 = false
	input := "\n1.2.3.4\n\n\n5.6.7.8\n\n"
	hosts := collectHosts(t, strings.NewReader(input))

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts (skipping empty lines), got %d", len(hosts))
	}
}

func TestIterate_IPv6Filtered(t *testing.T) {
	enableIPv6 = false
	input := "::1\n1.2.3.4\n"
	hosts := collectHosts(t, strings.NewReader(input))

	if len(hosts) != 1 {
		t.Fatalf("expected 1 host (IPv6 filtered), got %d", len(hosts))
	}
	if hosts[0].IP.String() != "1.2.3.4" {
		t.Errorf("hosts[0].IP = %v, want 1.2.3.4", hosts[0].IP)
	}
}

func TestIterate_IPv6Allowed(t *testing.T) {
	enableIPv6 = true
	input := "::1\n1.2.3.4\n"
	hosts := collectHosts(t, strings.NewReader(input))

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts (IPv6 allowed), got %d", len(hosts))
	}
}

func TestIterateAddr_CIDR(t *testing.T) {
	enableIPv6 = false
	hosts := collectHostsFromChan(IterateAddr("192.168.1.0/30"))

	if len(hosts) != 4 {
		t.Fatalf("expected 4 hosts for /30, got %d", len(hosts))
	}
	if hosts[0].Type != HostTypeCIDR {
		t.Fatalf("expected CIDR host type, got %v", hosts[0].Type)
	}
}

func TestIterateAddr_Invalid(t *testing.T) {
	ch := IterateAddr("bad host value with spaces")
	if host, ok := <-ch; ok {
		t.Fatalf("expected closed channel, got host %+v", host)
	}
}

func TestIterateAddr_InfiniteModeSequence(t *testing.T) {
	ch := IterateAddr("192.168.1.10")
	hosts := collectNHosts(t, ch, 5)

	expected := []string{
		"192.168.1.10",
		"192.168.1.9",
		"192.168.1.11",
		"192.168.1.8",
		"192.168.1.12",
	}
	for i, host := range hosts {
		if got := host.IP.String(); got != expected[i] {
			t.Fatalf("hosts[%d].IP = %s, want %s", i, got, expected[i])
		}
	}
}

func TestOutWriter(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	writeCount := 0
	allWritten := sync.NewCond(&mu)

	safeWriter := writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		n, err := buf.Write(p)
		writeCount++
		if writeCount == 2 {
			allWritten.Broadcast()
		}
		return n, err
	})

	ch := OutWriter(safeWriter)
	ch <- "hello "
	ch <- "world\n"
	close(ch)

	mu.Lock()
	for writeCount < 2 {
		allWritten.Wait()
	}
	defer mu.Unlock()

	if buf.String() != "hello world\n" {
		t.Errorf("OutWriter output = %q, want %q", buf.String(), "hello world\n")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func collectHosts(t *testing.T, reader io.Reader) []Host {
	t.Helper()
	ch := Iterate(reader)
	var hosts []Host
	for h := range ch {
		hosts = append(hosts, h)
	}
	return hosts
}

func collectNHosts(t *testing.T, ch <-chan Host, n int) []Host {
	t.Helper()
	hosts := make([]Host, 0, n)
	for len(hosts) < n {
		host, ok := <-ch
		if !ok {
			t.Fatalf("channel closed after %d hosts, want %d", len(hosts), n)
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func collectHostsFromChan(ch <-chan Host) []Host {
	var hosts []Host
	for h := range ch {
		hosts = append(hosts, h)
	}
	return hosts
}
