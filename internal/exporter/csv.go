package exporter

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"time"

	"fahscan/internal/inventory"
	"fahscan/pkg/types"
)

func ServicesCSV(services []types.Service) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"scan_id", "port", "protocol", "service", "product", "version", "banner", "created_at"}); err != nil {
		return nil, err
	}
	for _, service := range services {
		if err := w.Write([]string{
			strconv.FormatInt(service.ScanID, 10),
			strconv.Itoa(service.Port),
			service.Protocol,
			service.Service,
			service.Product,
			service.Version,
			service.Banner,
			formatTime(service.CreatedAt),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

func FindingsCSV(findings []types.Finding) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"scan_id", "service_id", "severity", "cvss", "cve_id", "title", "confidence", "evidence", "recommendation", "created_at"}); err != nil {
		return nil, err
	}
	for _, finding := range findings {
		if err := w.Write([]string{
			strconv.FormatInt(finding.ScanID, 10),
			strconv.FormatInt(finding.ServiceID, 10),
			finding.Severity,
			fmt.Sprintf("%.1f", finding.CVSS),
			finding.CVEID,
			finding.Title,
			finding.Confidence,
			finding.Evidence,
			finding.Recommendation,
			formatTime(finding.CreatedAt),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

func InventoryCSV(snapshot inventory.Snapshot) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"target", "scan_count", "open_ports", "services", "products", "findings", "highest_severity", "exposure", "recommended_focus", "first_seen", "last_seen"}); err != nil {
		return nil, err
	}
	for _, asset := range snapshot.Assets {
		if err := w.Write([]string{
			asset.Target,
			strconv.Itoa(asset.ScanCount),
			ints(asset.OpenPorts),
			join(asset.Services),
			join(asset.Products),
			strconv.Itoa(asset.FindingCount),
			asset.HighestSeverity,
			asset.Exposure,
			asset.RecommendedFocus,
			formatTime(asset.FirstSeen),
			formatTime(asset.LastSeen),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

func ints(values []int) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ";"
		}
		out += strconv.Itoa(value)
	}
	return out
}

func join(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ";"
		}
		out += value
	}
	return out
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
