package report

import (
	"fmt"
	"strings"

	"fahscan/pkg/types"
)

type Narrative struct {
	Headline string    `json:"headline"`
	Summary  string    `json:"summary"`
	Sections []Section `json:"sections"`
	Notes    []string  `json:"notes"`
}

type Section struct {
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

func BuildNarrative(data types.ReportData) Narrative {
	n := Narrative{}
	n.Headline = fmt.Sprintf("FahScan report for %s", data.Scan.Target)
	n.Summary = summarySentence(data)
	n.Sections = append(n.Sections, servicesSection(data), findingsSection(data), remediationSection(data), policySection(data))
	n.Notes = []string{
		"FahScan uses passive checks and local matching only.",
		"Findings should be validated by the service owner before remediation tracking is closed.",
		data.AuthorizationNotice,
	}
	return n
}

func (n Narrative) Text() string {
	var b strings.Builder
	b.WriteString(n.Headline)
	b.WriteString("\n\n")
	b.WriteString(n.Summary)
	b.WriteString("\n")
	for _, section := range n.Sections {
		b.WriteString("\n")
		b.WriteString(section.Title)
		b.WriteString("\n")
		for _, line := range section.Lines {
			b.WriteString("- ")
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	if len(n.Notes) > 0 {
		b.WriteString("\nNotes\n")
		for _, note := range n.Notes {
			b.WriteString("- ")
			b.WriteString(note)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func summarySentence(data types.ReportData) string {
	return fmt.Sprintf("The scan completed with risk score %d, %d open service(s), and %d finding(s).", data.Scan.RiskScore, len(data.Services), len(data.Findings))
}

func servicesSection(data types.ReportData) Section {
	section := Section{Title: "Services"}
	if len(data.Services) == 0 {
		section.Lines = append(section.Lines, "No open TCP services were observed.")
		return section
	}
	for _, service := range data.Services {
		line := fmt.Sprintf("%d/%s %s", service.Port, service.Protocol, service.Service)
		if service.Product != "" {
			line += " (" + service.Product + ")"
		}
		section.Lines = append(section.Lines, line)
	}
	return section
}

func findingsSection(data types.ReportData) Section {
	section := Section{Title: "Findings"}
	if len(data.Findings) == 0 {
		section.Lines = append(section.Lines, "No passive findings were generated.")
		return section
	}
	for _, finding := range data.Findings {
		line := fmt.Sprintf("[%s] %s", strings.ToUpper(finding.Severity), finding.Title)
		if finding.CVEID != "" {
			line += " (" + finding.CVEID + ")"
		}
		section.Lines = append(section.Lines, line)
	}
	return section
}

func remediationSection(data types.ReportData) Section {
	section := Section{Title: "Recommendations"}
	if len(data.Remediation) == 0 {
		section.Lines = append(section.Lines, "No remediation actions were generated.")
		return section
	}
	for _, action := range data.Remediation {
		section.Lines = append(section.Lines, fmt.Sprintf("P%d %s", action.Priority, action.Title))
	}
	return section
}

func policySection(data types.ReportData) Section {
	section := Section{Title: "Policy"}
	if len(data.Policy) == 0 {
		section.Lines = append(section.Lines, "No policy decisions were generated.")
		return section
	}
	for _, decision := range data.Policy {
		section.Lines = append(section.Lines, fmt.Sprintf("%s %s: %s", strings.ToUpper(decision.Result), decision.ControlID, decision.Title))
	}
	return section
}
