package risk

import (
	"strings"

	"fahscan/pkg/types"
)

func Score(services []types.Service, findings []types.Finding) int {
	score := 100
	for _, finding := range findings {
		switch strings.ToLower(finding.Severity) {
		case "critical":
			score -= 20
		case "high":
			score -= 12
		case "medium":
			score -= 6
		case "low":
			score -= 2
		}
		t := strings.ToLower(finding.Title)
		if strings.Contains(t, "expired certificate") {
			score -= 10
		}
		if strings.Contains(t, "self-signed") {
			score -= 5
		}
		if strings.Contains(t, "hostname mismatch") {
			score -= 5
		}
		if strings.Contains(t, "strict-transport-security") || strings.Contains(t, "missing hsts") {
			score -= 4
		}
		if strings.Contains(t, "content-security-policy") || strings.Contains(t, "missing csp") {
			score -= 3
		}
	}
	for _, svc := range services {
		name := strings.ToLower(svc.Service)
		if isDatabase(name) {
			score -= 8
		}
		if isAdminLike(svc.Port, name) {
			score -= 5
		}
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func isDatabase(name string) bool {
	for _, token := range []string{"mysql", "postgresql", "mongodb", "redis", "mssql", "oracle", "couchdb", "cassandra", "elasticsearch", "memcached"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func isAdminLike(port int, name string) bool {
	if strings.Contains(name, "admin") {
		return true
	}
	switch port {
	case 7001, 8008, 8080, 8081, 8888, 9000, 9443:
		return true
	default:
		return false
	}
}
