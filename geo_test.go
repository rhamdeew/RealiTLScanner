package main

import (
	"net"
	"testing"
)

func TestNewGeo_NoDB(t *testing.T) {
	geo := NewGeo()
	if geo == nil {
		t.Fatal("NewGeo() returned nil")
	}
}

func TestGetGeo_NoReader(t *testing.T) {
	geo := NewGeo()
	ip := net.ParseIP("1.1.1.1")
	got := geo.GetGeo(ip)
	if got != "N/A" {
		t.Errorf("GetGeo() without DB = %q, want %q", got, "N/A")
	}
}

func TestGetGeo_NilIP(t *testing.T) {
	geo := NewGeo()
	got := geo.GetGeo(nil)
	if got != "N/A" {
		t.Errorf("GetGeo(nil) = %q, want %q", got, "N/A")
	}
}
