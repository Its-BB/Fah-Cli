package remediation

import (
	"sort"
	"strings"

	"fahscan/internal/severity"
	"fahscan/pkg/types"
)

type Action struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Priority    int      `json:"priority"`
	Severity    string   `json:"severity"`
	Effort      string   `json:"effort"`
	Targets     []string `json:"targets"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
}

func Build(findings []types.Finding, services []types.Service) []Action {
	var actions []Action
	actions = append(actions, fromFindings(findings)...)
	actions = append(actions, fromServices(services)...)
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Priority == actions[j].Priority {
			return actions[i].Title < actions[j].Title
		}
		return actions[i].Priority > actions[j].Priority
	})
	return merge(actions)
}

func fromFindings(findings []types.Finding) []Action {
	var actions []Action
	for _, finding := range findings {
		title := strings.ToLower(finding.Title)
		switch {
		case strings.Contains(title, "strict-transport-security"):
			actions = append(actions, headerAction("REM-HSTS", "Add HSTS", finding, "Strict-Transport-Security"))
		case strings.Contains(title, "content-security-policy"):
			actions = append(actions, headerAction("REM-CSP", "Add CSP", finding, "Content-Security-Policy"))
		case strings.Contains(title, "x-frame-options"):
			actions = append(actions, headerAction("REM-FRAME", "Add frame protection", finding, "X-Frame-Options or CSP frame-ancestors"))
		case strings.Contains(title, "expired certificate"):
			actions = append(actions, Action{ID: "REM-TLS-EXPIRED", Title: "Renew expired certificate", Priority: 90, Severity: "high", Effort: "medium", Description: "Replace the expired certificate and verify the served chain.", Steps: []string{"Identify the certificate owner.", "Renew or reissue the certificate.", "Deploy the new certificate.", "Re-scan the service."}})
		case strings.Contains(title, "hostname mismatch"):
			actions = append(actions, Action{ID: "REM-TLS-HOSTNAME", Title: "Fix certificate hostname mismatch", Priority: 85, Severity: "high", Effort: "medium", Description: "Deploy a certificate whose SAN covers the scanned hostname.", Steps: []string{"List served certificate SANs.", "Request a corrected certificate.", "Deploy and re-scan."}})
		case finding.CVEID != "":
			actions = append(actions, Action{ID: "REM-CVE-" + finding.CVEID, Title: "Review " + finding.CVEID, Priority: 80, Severity: severity.Normalize(finding.Severity), Effort: "variable", Description: finding.Description, Steps: []string{"Confirm product and version.", "Read vendor advisory.", "Patch or document compensating controls.", "Re-scan after remediation."}})
		}
	}
	return actions
}

func fromServices(services []types.Service) []Action {
	var actions []Action
	for _, service := range services {
		name := strings.ToLower(service.Service + " " + service.Product)
		if containsAny(name, "mysql", "postgresql", "mongodb", "redis", "mssql", "oracle", "elasticsearch", "memcached") {
			actions = append(actions, Action{ID: "REM-DB-EXPOSURE", Title: "Restrict database exposure", Priority: 70, Severity: "medium", Effort: "medium", Targets: []string{serviceName(service)}, Description: "Database-like services should be reachable only by authorized clients.", Steps: []string{"Confirm the service owner.", "Restrict listener or firewall scope.", "Verify application connectivity.", "Re-scan from the same vantage point."}})
		}
		if containsAny(name, "admin", "grafana", "kibana") || service.Port == 8080 || service.Port == 9000 {
			actions = append(actions, Action{ID: "REM-ADMIN-SURFACE", Title: "Review administrative web surface", Priority: 65, Severity: "medium", Effort: "low", Targets: []string{serviceName(service)}, Description: "Administrative surfaces should have explicit access controls.", Steps: []string{"Confirm whether the surface is required.", "Require authentication and network restrictions.", "Remove default content.", "Re-scan."}})
		}
	}
	return actions
}

func headerAction(id, title string, finding types.Finding, header string) Action {
	return Action{ID: id, Title: title, Priority: 40, Severity: severity.Normalize(finding.Severity), Effort: "low", Description: "A browser hardening header was not observed.", Steps: []string{"Choose a policy for " + header + ".", "Deploy in report-only or staged mode if appropriate.", "Monitor for breakage.", "Re-scan to confirm the header."}}
}

func merge(actions []Action) []Action {
	seen := map[string]int{}
	var out []Action
	for _, action := range actions {
		if idx, ok := seen[action.ID]; ok {
			out[idx].Targets = appendUnique(out[idx].Targets, action.Targets...)
			if action.Priority > out[idx].Priority {
				out[idx].Priority = action.Priority
			}
			continue
		}
		seen[action.ID] = len(out)
		out = append(out, action)
	}
	return out
}

func appendUnique(values []string, more ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range more {
		if strings.TrimSpace(value) != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func containsAny(text string, tokens ...string) bool {
	for _, token := range tokens {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func serviceName(service types.Service) string {
	return strings.TrimSpace(service.Service + " " + service.Product)
}
