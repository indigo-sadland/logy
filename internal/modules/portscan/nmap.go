package portscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Binary       string
	SaveTempFile bool
}

type Result struct {
	IP        string
	Port      int
	Protocol  string
	State     string
	Service   string
	Version   string
	ScannedAt time.Time
}

type ScanOutput struct {
	Results      []Result
	TempFilePath string
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
}

// Run executes nmap with raw user arguments and streams stdout and stderr directly to the terminal.
func Run(ctx context.Context, cfg Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("at least one nmap argument is required")
	}
	binary := normalizeBinary(cfg.Binary)
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("%s is not installed or not in PATH", binary)
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ScanDetailed executes nmap with raw user arguments, captures XML output, and optionally persists it to a temp file.
func ScanDetailed(ctx context.Context, cfg Config, userArgs []string) (ScanOutput, error) {
	if len(userArgs) == 0 {
		return ScanOutput{}, fmt.Errorf("at least one nmap argument is required")
	}
	binary := normalizeBinary(cfg.Binary)
	if _, err := exec.LookPath(binary); err != nil {
		return ScanOutput{}, fmt.Errorf("%s is not installed or not in PATH", binary)
	}
	if err := validateUserArgs(userArgs); err != nil {
		return ScanOutput{}, err
	}

	xmlFilePath, err := createTempScanResultFile()
	if err != nil {
		return ScanOutput{}, err
	}
	cleanupXMLFile := !cfg.SaveTempFile
	defer func() {
		if cleanupXMLFile {
			_ = os.Remove(xmlFilePath)
		}
	}()

	args := make([]string, 0, len(userArgs)+2)
	args = append(args, userArgs...)
	args = append(args, "-oX", xmlFilePath)

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return ScanOutput{}, fmt.Errorf("nmap failed: %w", err)
	}

	rawXML, err := os.ReadFile(xmlFilePath)
	if err != nil {
		return ScanOutput{}, fmt.Errorf("read nmap xml output: %w", err)
	}

	results, err := parseNmapXML(rawXML)
	if err != nil {
		return ScanOutput{}, err
	}

	output := ScanOutput{Results: results}
	if cfg.SaveTempFile {
		output.TempFilePath = xmlFilePath
		cleanupXMLFile = false
	}

	return output, nil
}

// ScanIPsDetailed runs nmap against IP targets, parses XML output, and optionally persists it to a temp file.
func ScanIPsDetailed(ctx context.Context, targets []string, cfg Config, userArgs []string) (ScanOutput, error) {
	targets = normalizeIPTargets(targets)
	if len(targets) == 0 {
		return ScanOutput{}, fmt.Errorf("no resolved IP targets found")
	}
	args := make([]string, 0, len(userArgs)+len(targets))
	args = append(args, userArgs...)
	args = append(args, targets...)
	return ScanDetailed(ctx, cfg, args)
}

// parseNmapXML extracts open-port scan results from nmap XML output.
func parseNmapXML(raw []byte) ([]Result, error) {
	var payload nmapRun
	if err := xml.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	scannedAt := time.Now().UTC()
	results := make([]Result, 0, 64)
	for _, host := range payload.Hosts {
		ip := ""
		for _, address := range host.Addresses {
			if strings.EqualFold(strings.TrimSpace(address.AddrType), "ipv4") {
				ip = strings.TrimSpace(address.Addr)
				break
			}
		}
		if net.ParseIP(ip) == nil || strings.Contains(ip, ":") {
			continue
		}

		for _, port := range host.Ports {
			if strings.TrimSpace(port.State.State) != "open" {
				continue
			}
			portID, err := strconv.Atoi(strings.TrimSpace(port.PortID))
			if err != nil {
				return nil, fmt.Errorf("parse nmap port %q: %w", port.PortID, err)
			}
			results = append(results, Result{
				IP:        ip,
				Port:      portID,
				Protocol:  strings.TrimSpace(port.Protocol),
				State:     strings.TrimSpace(port.State.State),
				Service:   strings.TrimSpace(port.Service.Name),
				Version:   buildVersion(port.Service),
				ScannedAt: scannedAt,
			})
		}
	}

	slices.SortFunc(results, func(a, b Result) int {
		if cmp := strings.Compare(a.IP, b.IP); cmp != 0 {
			return cmp
		}
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})
	return results, nil
}

// normalizeIPTargets trims, deduplicates, sorts, and filters scan targets down to IPv4 addresses.
func normalizeIPTargets(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		ip := net.ParseIP(target)
		if ip == nil || ip.To4() == nil {
			continue
		}
		target = ip.To4().String()
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	slices.Sort(out)
	return out
}

// validateUserArgs rejects output flags that conflict with internal XML capture mode.
func validateUserArgs(args []string) error {
	for _, arg := range args {
		switch strings.TrimSpace(arg) {
		case "-oX", "-oA", "-oN", "-oG":
			return fmt.Errorf("nmap output flags -oX, -oA, -oN, and -oG are not allowed with --from-db")
		}
	}
	return nil
}

// buildVersion reconstructs a compact version string from nmap service attributes.
func buildVersion(service nmapService) string {
	parts := make([]string, 0, 4)
	if tunnel := strings.TrimSpace(service.Tunnel); tunnel != "" {
		parts = append(parts, tunnel)
	}
	if product := strings.TrimSpace(service.Product); product != "" {
		parts = append(parts, product)
	}
	if version := strings.TrimSpace(service.Version); version != "" {
		parts = append(parts, version)
	}
	value := strings.Join(parts, " ")
	if extra := strings.TrimSpace(service.ExtraInfo); extra != "" {
		if value == "" {
			return extra
		}
		return value + " (" + extra + ")"
	}
	return value
}

func normalizeBinary(binary string) string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return "nmap"
	}
	return binary
}

func writeTempScanResult(raw []byte) (string, error) {
	file, err := os.CreateTemp("", "logy-portscan-*.xml")
	if err != nil {
		return "", fmt.Errorf("create temp scan result file: %w", err)
	}

	path := filepath.Clean(file.Name())
	if _, err := file.Write(raw); err != nil {
		file.Close()
		os.Remove(path)
		return "", fmt.Errorf("write temp scan result file: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("close temp scan result file: %w", err)
	}
	return path, nil
}

func createTempScanResultFile() (string, error) {
	file, err := os.CreateTemp("", "logy-portscan-*.xml")
	if err != nil {
		return "", fmt.Errorf("create temp scan result file: %w", err)
	}
	path := filepath.Clean(file.Name())
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close temp scan result file: %w", err)
	}
	return path, nil
}
