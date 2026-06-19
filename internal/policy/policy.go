package policy

import (
	"strings"

	"fahscan/pkg/types"
)

type Control struct {
	ID          string
	Title       string
	Severity    string
	Description string
	Applies     func(types.Service, []types.Finding) bool
}

type Decision struct {
	ControlID string `json:"control_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Result    string `json:"result"`
	Reason    string `json:"reason"`
}

var Controls = []Control{
	{ID: "POL-001", Title: "No exposed database services", Severity: "medium", Description: "Database services should not be broadly exposed.", Applies: serviceNameContains("mysql", "postgresql", "mongodb", "redis", "mssql", "oracle", "elasticsearch", "memcached")},
	{ID: "POL-002", Title: "No cleartext web services", Severity: "medium", Description: "HTTP services should redirect to TLS.", Applies: serviceNameContains("http")},
	{ID: "POL-003", Title: "No administrative web surfaces", Severity: "medium", Description: "Administrative services require explicit access control.", Applies: serviceNameContains("admin")},
	{ID: "POL-004", Title: "TLS certificates must be valid", Severity: "high", Description: "Expired or mismatched certificates should be remediated.", Applies: findingTitleContains("expired certificate", "hostname mismatch")},
	{ID: "POL-005", Title: "Browser security headers should be present", Severity: "low", Description: "Security headers reduce browser-side exposure.", Applies: findingTitleContains("missing strict-transport-security", "missing content-security-policy", "missing x-frame-options")},
}

func Evaluate(services []types.Service, findings []types.Finding) []Decision {
	var decisions []Decision
	for _, control := range Controls {
		hit := false
		for _, service := range services {
			if control.Applies(service, findings) {
				hit = true
				break
			}
		}
		if !hit && control.Applies(types.Service{}, findings) {
			hit = true
		}
		result := "pass"
		reason := "No matching passive evidence observed."
		if hit {
			result = "review"
			reason = "Passive evidence matched this control."
		}
		decisions = append(decisions, Decision{ControlID: control.ID, Title: control.Title, Severity: control.Severity, Result: result, Reason: reason})
	}
	return decisions
}

func Summary(decisions []Decision) map[string]int {
	out := map[string]int{"pass": 0, "review": 0}
	for _, decision := range decisions {
		out[decision.Result]++
	}
	return out
}

func serviceNameContains(tokens ...string) func(types.Service, []types.Finding) bool {
	return func(service types.Service, findings []types.Finding) bool {
		text := strings.ToLower(strings.Join([]string{service.Service, service.Product, service.Banner}, " "))
		for _, token := range tokens {
			if strings.Contains(text, token) {
				return true
			}
		}
		return false
	}
}

func findingTitleContains(tokens ...string) func(types.Service, []types.Finding) bool {
	return func(service types.Service, findings []types.Finding) bool {
		for _, finding := range findings {
			title := strings.ToLower(finding.Title)
			for _, token := range tokens {
				if strings.Contains(title, token) {
					return true
				}
			}
		}
		return false
	}
}
