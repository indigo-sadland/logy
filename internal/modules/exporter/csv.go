package exporter

import (
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/indigo-sadland/logy/internal/storage"
)

type csvExportRow struct {
	IPs      string
	Domain   string
	TCPPorts string
}

// ExportCSV writes resolved assets and their saved TCP ports as semicolon-separated CSV.
func ExportCSV(w io.Writer, subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord) (int, error) {
	rows := buildCSVExportRows(subdomains, scans)
	if err := writeCSVExport(w, rows); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func buildCSVExportRows(subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord) []csvExportRow {
	scansByIP := make(map[string][]storage.PortScanRecord)
	for _, scan := range scans {
		if !strings.EqualFold(strings.TrimSpace(scan.Protocol), "tcp") {
			continue
		}
		scansByIP[scan.IP] = append(scansByIP[scan.IP], scan)
	}

	domainsByIP := make(map[string][]string)
	for _, subdomain := range subdomains {
		if !subdomain.Resolved || len(subdomain.IPs) == 0 {
			continue
		}
		for _, ip := range subdomain.IPs {
			if strings.TrimSpace(ip) == "" {
				continue
			}
			domainsByIP[ip] = appendUniqueString(domainsByIP[ip], subdomain.Subdomain)
		}
	}

	ips := make([]string, 0, len(domainsByIP))
	for ip := range domainsByIP {
		ips = append(ips, ip)
	}
	slices.Sort(ips)

	rows := make([]csvExportRow, 0, len(ips))
	for _, ip := range ips {
		domains := domainsByIP[ip]
		slices.Sort(domains)

		// Each row represents one IP, with every resolved subdomain associated
		// with that address kept together in the DOMAIN column.
		assetScans := append([]storage.PortScanRecord(nil), scansByIP[ip]...)
		sortPortScans(assetScans)

		rows = append(rows, csvExportRow{
			IPs:      ip,
			Domain:   strings.Join(domains, "\n"),
			TCPPorts: formatTCPPorts(assetScans),
		})
	}
	return rows
}

func writeCSVExport(w io.Writer, rows []csvExportRow) error {
	writer := csv.NewWriter(w)
	writer.Comma = ';'
	if err := writer.Write([]string{"IP", "DOMAIN", "TCP PORTS"}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writer.Write([]string{row.IPs, row.Domain, row.TCPPorts}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func formatTCPPorts(scans []storage.PortScanRecord) string {
	lines := make([]string, 0, len(scans))
	for _, scan := range scans {
		portProto := fmt.Sprintf("%d/%s", scan.Port, strings.TrimSpace(scan.Protocol))
		line := fmt.Sprintf("%-9s %-5s %-18s %s", portProto, strings.TrimSpace(scan.State), strings.TrimSpace(scan.Service), strings.TrimSpace(scan.Version))
		lines = append(lines, strings.TrimRight(line, " "))
	}
	return strings.Join(lines, "\n")
}

func sortPortScans(scans []storage.PortScanRecord) {
	slices.SortFunc(scans, func(a, b storage.PortScanRecord) int {
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		if cmp := strings.Compare(a.Protocol, b.Protocol); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.IP, b.IP)
	})
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}
