package portscan

import (
	"os"
	"slices"
	"testing"
)

func TestParseNmapXMLOpenPortsOnly(t *testing.T) {
	t.Parallel()

	raw := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25.3"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="filtered"/>
        <service name="hosts2-ns"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" tunnel="ssl" product="nginx" version="1.25.3" extrainfo="Ubuntu"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	results, err := parseNmapXML(raw)
	if err != nil {
		t.Fatalf("parseNmapXML: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results)=%d; want 2", len(results))
	}

	if results[0].IP != "1.2.3.4" || results[0].Port != 80 || results[0].Service != "http" || results[0].Version != "nginx 1.25.3" {
		t.Fatalf("first result=%+v", results[0])
	}
	if results[1].Port != 443 || results[1].Version != "ssl nginx 1.25.3 (Ubuntu)" {
		t.Fatalf("second result=%+v", results[1])
	}
}

func TestNormalizeIPv4TargetsFiltersAndSorts(t *testing.T) {
	t.Parallel()

	got := normalizeIPTargets([]string{"1.1.1.1", "2001:db8::1", " 1.1.1.1 ", "8.8.8.8"})
	want := []string{"1.1.1.1", "8.8.8.8"}
	if !slices.Equal(got, want) {
		t.Fatalf("got=%v; want %v", got, want)
	}
}

func TestValidateUserArgsRejectsOutputFlags(t *testing.T) {
	t.Parallel()

	if err := validateUserArgs([]string{"-Pn", "-oX", "-"}); err == nil {
		t.Fatal("expected error for conflicting output flag")
	}
}

func TestWriteTempScanResult(t *testing.T) {
	t.Parallel()

	path, err := writeTempScanResult([]byte("<nmaprun></nmaprun>"))
	if err != nil {
		t.Fatalf("writeTempScanResult: %v", err)
	}
	defer os.Remove(path)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", path, err)
	}
	if string(raw) != "<nmaprun></nmaprun>" {
		t.Fatalf("file contents=%q", string(raw))
	}
}

func TestCreateTempScanResultFile(t *testing.T) {
	t.Parallel()

	path, err := createTempScanResultFile()
	if err != nil {
		t.Fatalf("createTempScanResultFile: %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q): %v", path, err)
	}
	if info.IsDir() {
		t.Fatalf("expected file, got directory %q", path)
	}
	if info.Size() != 0 {
		t.Fatalf("size=%d; want 0", info.Size())
	}
}
