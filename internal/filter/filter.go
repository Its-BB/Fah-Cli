package filter

import (
	"sort"
	"strings"

	"fahscan/pkg/types"
)

type FindingQuery struct {
	Severity   string
	Confidence string
	CVEOnly    bool
	Text       string
}

type ServiceQuery struct {
	Port     int
	Protocol string
	Service  string
	Product  string
	Text     string
}

func Findings(findings []types.Finding, query FindingQuery) []types.Finding {
	var out []types.Finding
	for _, finding := range findings {
		if query.Severity != "" && !strings.EqualFold(finding.Severity, query.Severity) {
			continue
		}
		if query.Confidence != "" && !strings.EqualFold(finding.Confidence, query.Confidence) {
			continue
		}
		if query.CVEOnly && finding.CVEID == "" {
			continue
		}
		if query.Text != "" && !containsText(query.Text, finding.Title, finding.Description, finding.Evidence, finding.Recommendation, finding.CVEID) {
			continue
		}
		out = append(out, finding)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityWeight(out[i].Severity) == severityWeight(out[j].Severity) {
			return out[i].Title < out[j].Title
		}
		return severityWeight(out[i].Severity) > severityWeight(out[j].Severity)
	})
	return out
}

func Services(services []types.Service, query ServiceQuery) []types.Service {
	var out []types.Service
	for _, service := range services {
		if query.Port != 0 && service.Port != query.Port {
			continue
		}
		if query.Protocol != "" && !strings.EqualFold(service.Protocol, query.Protocol) {
			continue
		}
		if query.Service != "" && !strings.Contains(strings.ToLower(service.Service), strings.ToLower(query.Service)) {
			continue
		}
		if query.Product != "" && !strings.Contains(strings.ToLower(service.Product), strings.ToLower(query.Product)) {
			continue
		}
		if query.Text != "" && !containsText(query.Text, service.Protocol, service.Service, service.Product, service.Version, service.Banner, metadataText(service.Metadata)) {
			continue
		}
		out = append(out, service)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].Service < out[j].Service
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func FindingSummary(findings []types.Finding) map[string]int {
	out := map[string]int{"total": len(findings)}
	for _, finding := range findings {
		out["severity:"+strings.ToLower(finding.Severity)]++
		if finding.CVEID != "" {
			out["cve"]++
		}
		if finding.Confidence != "" {
			out["confidence:"+strings.ToLower(finding.Confidence)]++
		}
	}
	return out
}

func ServiceSummary(services []types.Service) map[string]int {
	out := map[string]int{"total": len(services)}
	for _, service := range services {
		out["protocol:"+strings.ToLower(service.Protocol)]++
		out["service:"+strings.ToLower(service.Service)]++
		if service.Product != "" {
			out["product"]++
		}
	}
	return out
}

func containsText(query string, values ...string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func metadataText(metadata map[string]string) string {
	var parts []string
	for key, value := range metadata {
		parts = append(parts, key, value)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func severityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
