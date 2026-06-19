package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"fahscan/internal/evidence"
	"fahscan/internal/policy"
	"fahscan/internal/remediation"
	"fahscan/internal/severity"
	"fahscan/pkg/types"
)

const AuthorizationNotice = "This report reflects a defensive scan that requires explicit authorization for the target."

func Data(scan types.Scan, services []types.Service, findings []types.Finding) types.ReportData {
	decisions := policy.Evaluate(services, findings)
	publicDecisions := make([]types.PolicyDecision, 0, len(decisions))
	for _, decision := range decisions {
		publicDecisions = append(publicDecisions, types.PolicyDecision{ControlID: decision.ControlID, Title: decision.Title, Severity: decision.Severity, Result: decision.Result, Reason: decision.Reason})
	}
	actions := remediation.Build(findings, services)
	publicActions := make([]types.RemediationAction, 0, len(actions))
	for _, action := range actions {
		publicActions = append(publicActions, types.RemediationAction{ID: action.ID, Title: action.Title, Priority: action.Priority, Severity: action.Severity, Effort: action.Effort, Targets: action.Targets, Description: action.Description, Steps: action.Steps})
	}
	var sev severity.Summary
	for _, finding := range findings {
		severity.Add(&sev, finding.Severity)
	}
	bundle := evidence.Build(scan, services, findings)
	return types.ReportData{
		Scan: scan, Services: services, Findings: findings, Policy: publicDecisions, Remediation: publicActions,
		SeveritySummary:     types.SeveritySummary{Info: sev.Info, Low: sev.Low, Medium: sev.Medium, High: sev.High, Critical: sev.Critical, Total: sev.Total},
		EvidenceFingerprint: bundle.Fingerprint, AuthorizationNotice: AuthorizationNotice, GeneratedAt: time.Now(),
	}
}

func Render(data types.ReportData, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(data, "", "  ")
	case "sarif":
		return RenderSARIF(data)
	case "html":
		return renderHTML(data), nil
	case "markdown", "md":
		return renderMarkdown(data), nil
	case "txt", "text":
		return renderText(data), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func Write(path, format string, data types.ReportData) error {
	body, err := Render(data, format)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

func renderText(data types.ReportData) []byte {
	var b bytes.Buffer
	fmt.Fprintln(&b, "FahScan report")
	fmt.Fprintf(&b, "target: %s\nprofile: %s\nscan time: %s - %s\nrisk score: %d\n\n", data.Scan.Target, data.Scan.Profile, data.Scan.StartedAt.Format(time.RFC3339), data.Scan.FinishedAt.Format(time.RFC3339), data.Scan.RiskScore)
	fmt.Fprintln(&b, "Open ports")
	for _, svc := range data.Services {
		fmt.Fprintf(&b, "- %d/%s %s %s\n", svc.Port, svc.Protocol, svc.Service, svc.Product)
	}
	fmt.Fprintln(&b, "\nFindings")
	for _, f := range data.Findings {
		fmt.Fprintf(&b, "- [%s] %s\n  evidence: %s\n  recommendation: %s\n", f.Severity, f.Title, f.Evidence, f.Recommendation)
	}
	fmt.Fprintln(&b, "\nPolicy")
	for _, decision := range data.Policy {
		fmt.Fprintf(&b, "- [%s] %s: %s\n", decision.Result, decision.ControlID, decision.Title)
	}
	fmt.Fprintln(&b, "\nRecommendations")
	for _, action := range data.Remediation {
		fmt.Fprintf(&b, "- P%d [%s] %s\n", action.Priority, action.Severity, action.Title)
	}
	fmt.Fprintf(&b, "\nMetadata\nservices: %d\nfindings: %d\nevidence fingerprint: %s\ngenerated_at: %s\n\nAuthorization notice\n%s\n", len(data.Services), len(data.Findings), data.EvidenceFingerprint, data.GeneratedAt.Format(time.RFC3339), data.AuthorizationNotice)
	return b.Bytes()
}

func renderMarkdown(data types.ReportData) []byte {
	var b bytes.Buffer
	fmt.Fprintln(&b, "# FahScan report")
	fmt.Fprintf(&b, "\n- Target: `%s`\n- Profile: `%s`\n- Scan time: `%s` to `%s`\n- Risk score: `%d`\n", data.Scan.Target, data.Scan.Profile, data.Scan.StartedAt.Format(time.RFC3339), data.Scan.FinishedAt.Format(time.RFC3339), data.Scan.RiskScore)
	fmt.Fprintln(&b, "\n## Open ports\n\n| Port | Protocol | Service | Product |\n| --- | --- | --- | --- |")
	for _, svc := range data.Services {
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", svc.Port, svc.Protocol, svc.Service, svc.Product)
	}
	fmt.Fprintln(&b, "\n## Findings")
	for _, f := range data.Findings {
		fmt.Fprintf(&b, "\n### %s\n\n- Severity: `%s`\n- Evidence: %s\n- Recommendation: %s\n", f.Title, f.Severity, f.Evidence, f.Recommendation)
	}
	fmt.Fprintln(&b, "\n## Policy\n\n| Control | Result | Severity | Title |\n| --- | --- | --- | --- |")
	for _, decision := range data.Policy {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", decision.ControlID, decision.Result, decision.Severity, decision.Title)
	}
	fmt.Fprintln(&b, "\n## Recommendations\n\n| Priority | Severity | Action | Effort |\n| --- | --- | --- | --- |")
	for _, action := range data.Remediation {
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", action.Priority, action.Severity, action.Title, action.Effort)
	}
	fmt.Fprintf(&b, "\n## Metadata\n\n- Services: `%d`\n- Findings: `%d`\n- Evidence fingerprint: `%s`\n- Generated at: `%s`\n\n## Authorization notice\n\n%s\n", len(data.Services), len(data.Findings), data.EvidenceFingerprint, data.GeneratedAt.Format(time.RFC3339), data.AuthorizationNotice)
	return b.Bytes()
}

func renderHTML(data types.ReportData) []byte {
	var b bytes.Buffer
	fmt.Fprintln(&b, `<!doctype html><html><head><meta charset="utf-8"><title>FahScan report</title><style>body{font-family:Arial,sans-serif;color:#111;background:#fff;line-height:1.45;margin:40px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:6px;text-align:left}code{background:#eee;padding:1px 3px}@media print{body{margin:20px}}</style></head><body>`)
	fmt.Fprintln(&b, "<h1>FahScan report</h1>")
	fmt.Fprintf(&b, "<p><strong>Target:</strong> %s<br><strong>Profile:</strong> %s<br><strong>Scan time:</strong> %s - %s<br><strong>Risk score:</strong> %d</p>", esc(data.Scan.Target), esc(data.Scan.Profile), data.Scan.StartedAt.Format(time.RFC3339), data.Scan.FinishedAt.Format(time.RFC3339), data.Scan.RiskScore)
	fmt.Fprintln(&b, "<h2>Open ports</h2><table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th></tr>")
	for _, svc := range data.Services {
		fmt.Fprintf(&b, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", svc.Port, esc(svc.Protocol), esc(svc.Service), esc(svc.Product))
	}
	fmt.Fprintln(&b, "</table><h2>Findings</h2>")
	for _, f := range data.Findings {
		fmt.Fprintf(&b, "<h3>%s</h3><p><strong>Severity:</strong> %s<br><strong>Evidence:</strong> %s<br><strong>Recommendation:</strong> %s</p>", esc(f.Title), esc(f.Severity), esc(f.Evidence), esc(f.Recommendation))
	}
	fmt.Fprintln(&b, "<h2>Policy</h2><table><tr><th>Control</th><th>Result</th><th>Severity</th><th>Title</th></tr>")
	for _, decision := range data.Policy {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", esc(decision.ControlID), esc(decision.Result), esc(decision.Severity), esc(decision.Title))
	}
	fmt.Fprintln(&b, "</table><h2>Recommendations</h2><table><tr><th>Priority</th><th>Severity</th><th>Action</th><th>Effort</th></tr>")
	for _, action := range data.Remediation {
		fmt.Fprintf(&b, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", action.Priority, esc(action.Severity), esc(action.Title), esc(action.Effort))
	}
	fmt.Fprintf(&b, "</table><h2>Metadata</h2><p>Services: %d<br>Findings: %d<br>Evidence fingerprint: %s<br>Generated at: %s</p><h2>Authorization notice</h2><p>%s</p></body></html>", len(data.Services), len(data.Findings), esc(data.EvidenceFingerprint), data.GeneratedAt.Format(time.RFC3339), esc(data.AuthorizationNotice))
	return b.Bytes()
}

func esc(s string) string { return html.EscapeString(s) }
