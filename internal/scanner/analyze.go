package scanner

import (
	"sort"
	"strings"

	"fahscan/pkg/types"
)

type Analysis struct {
	ServiceCount       int            `json:"service_count"`
	FindingCount       int            `json:"finding_count"`
	Ports              []int          `json:"ports"`
	Protocols          map[string]int `json:"protocols"`
	ServiceFamilies    map[string]int `json:"service_families"`
	HighValueExposures []string       `json:"high_value_exposures"`
	PassiveSignals     []string       `json:"passive_signals"`
}

func AnalyzeResult(services []types.Service, findings []types.Finding) Analysis {
	analysis := Analysis{
		ServiceCount:    len(services),
		FindingCount:    len(findings),
		Protocols:       map[string]int{},
		ServiceFamilies: map[string]int{},
	}
	portSet := map[int]bool{}
	signalSet := map[string]bool{}
	exposureSet := map[string]bool{}
	for _, service := range services {
		portSet[service.Port] = true
		analysis.Protocols[strings.ToLower(service.Protocol)]++
		family := family(service)
		analysis.ServiceFamilies[family]++
		if highValue(service) {
			exposureSet[serviceLabel(service)] = true
		}
		for key, value := range service.Metadata {
			if strings.TrimSpace(value) != "" {
				signalSet[key] = true
			}
		}
		if service.Banner != "" {
			signalSet["banner"] = true
		}
	}
	for _, finding := range findings {
		if finding.CVEID != "" {
			signalSet["cve"] = true
		}
		if finding.Evidence != "" {
			signalSet["finding_evidence"] = true
		}
	}
	for port := range portSet {
		analysis.Ports = append(analysis.Ports, port)
	}
	for exposure := range exposureSet {
		analysis.HighValueExposures = append(analysis.HighValueExposures, exposure)
	}
	for signal := range signalSet {
		analysis.PassiveSignals = append(analysis.PassiveSignals, signal)
	}
	sort.Ints(analysis.Ports)
	sort.Strings(analysis.HighValueExposures)
	sort.Strings(analysis.PassiveSignals)
	return analysis
}

func family(service types.Service) string {
	text := strings.ToLower(service.Service + " " + service.Product)
	switch {
	case containsAny(text, "http", "https", "web", "nginx", "apache"):
		return "web"
	case containsAny(text, "mysql", "postgres", "mongodb", "redis", "mssql", "oracle", "elastic", "memcached"):
		return "data"
	case containsAny(text, "ssh", "ftp", "rdp", "telnet"):
		return "remote-access"
	case containsAny(text, "smtp", "imap", "pop3"):
		return "mail"
	case containsAny(text, "prometheus", "grafana", "kibana", "jaeger"):
		return "observability"
	default:
		return "other"
	}
}

func highValue(service types.Service) bool {
	return family(service) == "data" || family(service) == "remote-access" || strings.Contains(strings.ToLower(service.Service), "admin")
}

func serviceLabel(service types.Service) string {
	label := service.Service
	if service.Product != "" {
		label += "/" + service.Product
	}
	return label
}

func containsAny(text string, tokens ...string) bool {
	for _, token := range tokens {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}
