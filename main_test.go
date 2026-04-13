package main

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain_InvalidInputCombination(t *testing.T) {
	tmpDir := t.TempDir()

	restore := prepareMainTest(t, tmpDir, []string{
		"-addr", "127.0.0.1",
		"-in", filepath.Join(tmpDir, "targets.txt"),
	})
	defer restore()

	main()

	if _, err := os.Stat(filepath.Join(tmpDir, "out.csv")); !os.IsNotExist(err) {
		t.Fatalf("expected no output file, got err=%v", err)
	}
}

func TestMain_WithInputFile(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "targets.txt")
	if err := os.WriteFile(inputPath, []byte("not valid input\n"), 0644); err != nil {
		t.Fatal(err)
	}

	restore := prepareMainTest(t, tmpDir, []string{
		"-in", inputPath,
		"-thread", "1",
	})
	defer restore()

	main()

	assertOutputHeader(t, filepath.Join(tmpDir, "out.csv"))
}

func TestMain_WithAddrCIDR(t *testing.T) {
	tmpDir := t.TempDir()

	restore := prepareMainTest(t, tmpDir, []string{
		"-addr", "127.0.0.1/32",
		"-port", "1",
		"-timeout", "1",
		"-thread", "1",
	})
	defer restore()

	main()

	assertOutputHeader(t, filepath.Join(tmpDir, "out.csv"))
}

func TestMain_WithURL(t *testing.T) {
	tmpDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<a href="https://localhost/a">one</a><a href="https://localhost/b">two</a>`)
	}))
	defer server.Close()

	restore := prepareMainTest(t, tmpDir, []string{
		"-url", server.URL,
		"-port", "1",
		"-timeout", "1",
		"-thread", "1",
	})
	defer restore()

	main()

	assertOutputHeader(t, filepath.Join(tmpDir, "out.csv"))
}

func prepareMainTest(t *testing.T, workDir string, args []string) func() {
	t.Helper()

	origArgs := os.Args
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	origCommandLine := flag.CommandLine
	origAddr, origIn, origOut, origURL := addr, in, out, url
	origPort, origThread, origTimeout := port, thread, timeout
	origVerbose, origEnableIPv6 := verbose, enableIPv6

	if err := os.Chdir(workDir); err != nil {
		t.Fatal(err)
	}

	flag.CommandLine = flag.NewFlagSet("RealiTLScanner", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = append([]string{"RealiTLScanner"}, args...)

	addr, in, out, url = "", "", "", ""
	port, thread, timeout = 0, 0, 0
	verbose, enableIPv6 = false, false

	return func() {
		addr, in, out, url = origAddr, origIn, origOut, origURL
		port, thread, timeout = origPort, origThread, origTimeout
		verbose, enableIPv6 = origVerbose, origEnableIPv6
		flag.CommandLine = origCommandLine
		os.Args = origArgs
		_ = os.Chdir(origWd)
	}
}

func assertOutputHeader(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"; !strings.HasPrefix(got, want) {
		t.Fatalf("output = %q, want prefix %q", got, want)
	}
}
