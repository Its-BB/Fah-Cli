package advisor

import (
	"fmt"
	"sort"
	"strings"

	"fahscan/internal/remediation"
	"fahscan/pkg/types"
)

type Advice struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Priority    int      `json:"priority"`
	Category    string   `json:"category"`
	Why         string   `json:"why"`
	Actions     []string `json:"actions"`
	References  []string `json:"references"`
	AppliesTo   []string `json:"applies_to"`
	Suppressed  bool     `json:"suppressed"`
	Suppression string   `json:"suppression,omitempty"`
}

type Context struct {
	Scan     types.Scan
	Services []types.Service
	Findings []types.Finding
	Config   types.Config
	Tags     []string
	Accepted []string
	Strict   bool
}

type Book struct {
	Target       string   `json:"target"`
	RiskScore    int      `json:"risk_score"`
	Advice       []Advice `json:"advice"`
	Suppressed   []Advice `json:"suppressed"`
	Highest      string   `json:"highest"`
	NextBestStep string   `json:"next_best_step"`
}

func Build(ctx Context) Book {
	var advice []Advice
	advice = append(advice, fromRemediation(ctx)...)
	advice = append(advice, serviceAdvice(ctx)...)
	advice = append(advice, configAdvice(ctx)...)
	advice = append(advice, evidenceAdvice(ctx)...)
	advice = suppress(advice, ctx.Accepted)
	sort.SliceStable(advice, func(i, j int) bool {
		if advice[i].Suppressed != advice[j].Suppressed {
			return !advice[i].Suppressed
		}
		if advice[i].Priority == advice[j].Priority {
			return advice[i].Title < advice[j].Title
		}
		return advice[i].Priority > advice[j].Priority
	})
	book := Book{Target: ctx.Scan.Target, RiskScore: ctx.Scan.RiskScore}
	for _, item := range advice {
		if item.Suppressed {
			book.Suppressed = append(book.Suppressed, item)
		} else {
			book.Advice = append(book.Advice, item)
		}
	}
	book.Highest = highest(book.Advice)
	book.NextBestStep = nextBest(book.Advice)
	return book
}

func fromRemediation(ctx Context) []Advice {
	actions := remediation.Build(ctx.Findings, ctx.Services)
	out := make([]Advice, 0, len(actions))
	for _, action := range actions {
		out = append(out, Advice{
			ID:        "ADV-" + action.ID,
			Title:     action.Title,
			Priority:  action.Priority,
			Category:  "remediation",
			Why:       action.Description,
			Actions:   action.Steps,
			AppliesTo: action.Targets,
		})
	}
	return out
}

func serviceAdvice(ctx Context) []Advice {
	var out []Advice
	for _, service := range ctx.Services {
		name := strings.ToLower(strings.Join([]string{service.Service, service.Product}, " "))
		target := fmt.Sprintf("%s:%d", ctx.Scan.Target, service.Port)
		if containsAny(name, "redis", "memcached", "mongodb", "mysql", "postgresql", "mssql", "oracle", "elasticsearch") {
			out = append(out, Advice{
				ID:       "ADV-SERVICE-DATABASE-" + portID(service.Port),
				Title:    "Confirm database network boundary",
				Priority: 74,
				Category: "exposure",
				Why:      "A data service is reachable from this scan vantage point.",
				Actions: []string{
					"Identify the owning application or team.",
					"Confirm the listener is bound only to approved interfaces.",
					"Restrict inbound access to named client networks.",
					"Re-scan from the same location after changes.",
				},
				AppliesTo: []string{target},
			})
		}
		if service.Port == 21 || strings.Contains(name, "ftp") {
			out = append(out, Advice{ID: "ADV-SERVICE-FTP", Title: "Replace or constrain FTP", Priority: 62, Category: "transport", Why: "FTP metadata suggests a cleartext remote access workflow.", Actions: []string{"Confirm whether FTP is required.", "Prefer SFTP or another encrypted workflow.", "Restrict access to approved networks."}, AppliesTo: []string{target}})
		}
		if service.Port == 22 || strings.Contains(name, "ssh") {
			out = append(out, Advice{ID: "ADV-SERVICE-SSH", Title: "Review SSH hardening", Priority: 48, Category: "remote-access", Why: "SSH is suitable for administration but should have a documented access policy.", Actions: []string{"Confirm key-based access policy.", "Disable unused accounts.", "Review patch cadence and allowed source networks."}, AppliesTo: []string{target}})
		}
	}
	return out
}

func configAdvice(ctx Context) []Advice {
	var out []Advice
	if ctx.Config.MaxConcurrency > 50 {
		out = append(out, Advice{ID: "ADV-CONFIG-CONCURRENCY", Title: "Lower default concurrency", Priority: 35, Category: "configuration", Why: "High concurrency can create noisy scans against fragile systems.", Actions: []string{"Use a smaller max_concurrency value.", "Increase only for explicitly approved resilient targets."}})
	}
	if !ctx.Config.SaveRawEvidence {
		out = append(out, Advice{ID: "ADV-CONFIG-EVIDENCE", Title: "Consider retaining raw evidence", Priority: 28, Category: "evidence", Why: "Raw passive evidence helps remediation owners verify findings.", Actions: []string{"Enable save_raw_evidence when local storage policy allows.", "Use report exports for sharing sanitized summaries."}})
	}
	if ctx.Strict && ctx.Config.AllowPrivateIP {
		out = append(out, Advice{ID: "ADV-CONFIG-PRIVATE-IP", Title: "Review private IP allowance", Priority: 20, Category: "scope", Why: "Strict environments may require target inventory entries instead of ad hoc private IP scans.", Actions: []string{"Use target add/list workflows.", "Document authorization for private address scanning."}})
	}
	return out
}

func evidenceAdvice(ctx Context) []Advice {
	hasCVE := false
	hasTLS := false
	hasHeaders := false
	for _, finding := range ctx.Findings {
		title := strings.ToLower(finding.Title)
		if finding.CVEID != "" {
			hasCVE = true
		}
		if strings.Contains(title, "certificate") || strings.Contains(title, "tls") {
			hasTLS = true
		}
		if strings.Contains(title, "missing ") && strings.Contains(title, "-") {
			hasHeaders = true
		}
	}
	var out []Advice
	if hasCVE {
		out = append(out, Advice{ID: "ADV-EVIDENCE-CVE", Title: "Validate CVE matches manually", Priority: 76, Category: "cve", Why: "FahScan CVE matching is passive and local; it should be treated as triage evidence.", Actions: []string{"Confirm exact product and version.", "Check vendor advisory details.", "Patch or document non-applicability."}})
	}
	if hasTLS {
		out = append(out, Advice{ID: "ADV-EVIDENCE-TLS", Title: "Prioritize certificate hygiene", Priority: 68, Category: "tls", Why: "TLS identity issues affect user trust and automation reliability.", Actions: []string{"Check certificate chain.", "Verify SAN coverage.", "Review renewal automation."}})
	}
	if hasHeaders {
		out = append(out, Advice{ID: "ADV-EVIDENCE-HEADERS", Title: "Batch browser header fixes", Priority: 42, Category: "http", Why: "Multiple header findings can often be remediated at the same gateway or application layer.", Actions: []string{"Identify the layer that sets headers.", "Apply a standard baseline.", "Re-scan one representative service before broad rollout."}})
	}
	return out
}

func suppress(advice []Advice, accepted []string) []Advice {
	acceptedSet := map[string]string{}
	for _, id := range accepted {
		acceptedSet[strings.ToUpper(strings.TrimSpace(id))] = id
	}
	for i := range advice {
		if original, ok := acceptedSet[strings.ToUpper(advice[i].ID)]; ok {
			advice[i].Suppressed = true
			advice[i].Suppression = "accepted risk: " + original
		}
	}
	return advice
}

func highest(advice []Advice) string {
	if len(advice) == 0 {
		return "none"
	}
	switch {
	case advice[0].Priority >= 80:
		return "critical"
	case advice[0].Priority >= 65:
		return "high"
	case advice[0].Priority >= 40:
		return "medium"
	default:
		return "low"
	}
}

func nextBest(advice []Advice) string {
	for _, item := range advice {
		if !item.Suppressed {
			if len(item.Actions) > 0 {
				return item.Actions[0]
			}
			return item.Title
		}
	}
	return "No unsuppressed advice remains."
}

func containsAny(text string, tokens ...string) bool {
	for _, token := range tokens {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func portID(port int) string {
	if port == 0 {
		return "0"
	}
	digits := "0123456789"
	var out []byte
	for port > 0 {
		out = append([]byte{digits[port%10]}, out...)
		port /= 10
	}
	return string(out)
}
