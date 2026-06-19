package cve

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"fahscan/pkg/types"
)

func LoadFile(path string) ([]types.CVERecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []types.CVERecord
	if err := json.Unmarshal(data, &records); err != nil {
		var one types.CVERecord
		if err2 := json.Unmarshal(data, &one); err2 != nil {
			return nil, err
		}
		records = []types.CVERecord{one}
	}
	for _, rec := range records {
		if strings.TrimSpace(rec.CVEID) == "" {
			return nil, fmt.Errorf("cve_id is required")
		}
	}
	return records, nil
}

func Match(service types.Service, records []types.CVERecord) []types.Finding {
	var findings []types.Finding
	hay := strings.ToLower(strings.Join([]string{service.Service, service.Product, service.Version, service.Banner}, " "))
	for _, rec := range records {
		product := strings.ToLower(rec.Product)
		vendor := strings.ToLower(rec.Vendor)
		if product == "" && vendor == "" {
			continue
		}
		productHit := product != "" && strings.Contains(hay, product)
		vendorHit := vendor != "" && strings.Contains(hay, vendor)
		serviceHit := product != "" && strings.Contains(strings.ToLower(service.Service), product)
		if !productHit && !vendorHit && !serviceHit {
			continue
		}
		confidence := "possible"
		if productHit && rec.AffectedVersion != "" && service.Version != "" && strings.Contains(strings.ToLower(service.Version), strings.ToLower(rec.AffectedVersion)) {
			confidence = "confirmed"
		} else if serviceHit {
			confidence = "informational"
		}
		findings = append(findings, types.Finding{
			ServiceID:      service.ID,
			Title:          rec.CVEID + " may affect " + service.Service,
			Severity:       SeverityFromCVSS(rec.CVSS),
			CVSS:           rec.CVSS,
			CVEID:          rec.CVEID,
			Description:    rec.Description,
			Evidence:       fmt.Sprintf("Matched local CVE record against service=%q product=%q version=%q", service.Service, service.Product, service.Version),
			Recommendation: rec.Recommendation,
			Confidence:     confidence,
		})
	}
	return findings
}

func Search(records []types.CVERecord, query string) []types.CVERecord {
	q := strings.ToLower(strings.TrimSpace(query))
	var out []types.CVERecord
	for _, rec := range records {
		text := strings.ToLower(strings.Join([]string{rec.CVEID, rec.Vendor, rec.Product, rec.AffectedVersion, rec.Severity, rec.Description}, " "))
		if q == "" || strings.Contains(text, q) {
			out = append(out, rec)
		}
	}
	return out
}

func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}
