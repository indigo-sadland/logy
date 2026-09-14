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

func TestParseNmapXMLImportIncludesHostnamesAndSkipCount(t *testing.T) {
	t.Parallel()

	raw := []byte(`<?xml version="1.0"?>
<nmaprun start="1771300000">
  <host>
    <address addr="10.20.30.40" addrtype="ipv4"/>
    <hostnames>
      <hostname name="api.example.com" type="user"/>
      <hostname name="www.example.com." type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.62"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="filtered"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.20.30.41" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	imported, err := ParseNmapXMLImport(raw, ImportOptions{})
	if err != nil {
		t.Fatalf("ParseNmapXMLImport: %v", err)
	}
	if imported.HostsSeen != 2 {
		t.Fatalf("hosts seen=%d; want 2", imported.HostsSeen)
	}
	if imported.PortsSkipped != 2 {
		t.Fatalf("ports skipped=%d; want 2", imported.PortsSkipped)
	}
	if len(imported.Results) != 1 {
		t.Fatalf("len(results)=%d; want 1", len(imported.Results))
	}
	if imported.Results[0].Version != "Apache httpd 2.4.62" {
		t.Fatalf("version=%q; want Apache httpd 2.4.62", imported.Results[0].Version)
	}
	if len(imported.Hostnames) != 2 {
		t.Fatalf("len(hostnames)=%d; want 2", len(imported.Hostnames))
	}
	if imported.Hostnames[1].Hostname != "www.example.com" {
		t.Fatalf("second hostname=%q; want www.example.com", imported.Hostnames[1].Hostname)
	}
	if !slices.Equal(imported.ScannedIPs, []string{"10.20.30.40", "10.20.30.41"}) {
		t.Fatalf("scanned IPs=%v; want both hosts", imported.ScannedIPs)
	}
}

func TestParseNmapXMLImportCanIncludeNonOpen(t *testing.T) {
	t.Parallel()

	raw := []byte(`<nmaprun>
  <host>
    <address addr="10.20.30.40" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="81">
        <state state="filtered"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	imported, err := ParseNmapXMLImport(raw, ImportOptions{IncludeNonOpen: true})
	if err != nil {
		t.Fatalf("ParseNmapXMLImport: %v", err)
	}
	if len(imported.Results) != 1 {
		t.Fatalf("len(results)=%d; want 1", len(imported.Results))
	}
	if imported.Results[0].State != "filtered" {
		t.Fatalf("state=%q; want filtered", imported.Results[0].State)
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
