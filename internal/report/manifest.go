package report

import (
	"sort"
	"strings"
	"time"

	"fahscan/pkg/types"
)

type Manifest struct {
	ScanID      int64           `json:"scan_id"`
	Target      string          `json:"target"`
	GeneratedAt time.Time       `json:"generated_at"`
	Artifacts   []Artifact      `json:"artifacts"`
	Sections    []SectionStatus `json:"sections"`
	Labels      []string        `json:"labels"`
}

type Artifact struct {
	Format      string `json:"format"`
	Path        string `json:"path,omitempty"`
	Description string `json:"description"`
	MimeType    string `json:"mime_type"`
}

type SectionStatus struct {
	Name     string `json:"name"`
	Present  bool   `json:"present"`
	Count    int    `json:"count"`
	Priority int    `json:"priority"`
}

func BuildManifest(data types.ReportData, formats []string) Manifest {
	manifest := Manifest{ScanID: data.Scan.ID, Target: data.Scan.Target, GeneratedAt: time.Now()}
	for _, format := range formats {
		manifest.Artifacts = append(manifest.Artifacts, ArtifactFor(format))
	}
	manifest.Sections = []SectionStatus{
		{Name: "target", Present: data.Scan.Target != "", Count: 1, Priority: 100},
		{Name: "services", Present: len(data.Services) > 0, Count: len(data.Services), Priority: 90},
		{Name: "findings", Present: len(data.Findings) > 0, Count: len(data.Findings), Priority: 95},
		{Name: "policy", Present: len(data.Policy) > 0, Count: len(data.Policy), Priority: 70},
		{Name: "remediation", Present: len(data.Remediation) > 0, Count: len(data.Remediation), Priority: 80},
		{Name: "metadata", Present: data.EvidenceFingerprint != "", Count: 1, Priority: 50},
	}
	sort.SliceStable(manifest.Sections, func(i, j int) bool {
		return manifest.Sections[i].Priority > manifest.Sections[j].Priority
	})
	manifest.Labels = Labels(data)
	return manifest
}

func ArtifactFor(format string) Artifact {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "json":
		return Artifact{Format: "json", Description: "Complete machine-readable scan report.", MimeType: "application/json"}
	case "sarif":
		return Artifact{Format: "sarif", Description: "Static analysis interchange report for security tooling.", MimeType: "application/sarif+json"}
	case "html":
		return Artifact{Format: "html", Description: "Standalone printable HTML report.", MimeType: "text/html"}
	case "markdown", "md":
		return Artifact{Format: "markdown", Description: "GitHub-compatible Markdown report.", MimeType: "text/markdown"}
	case "txt", "text":
		return Artifact{Format: "txt", Description: "Plain terminal-style text report.", MimeType: "text/plain"}
	default:
		return Artifact{Format: format, Description: "Custom report artifact.", MimeType: "application/octet-stream"}
	}
}

func Labels(data types.ReportData) []string {
	seen := map[string]bool{}
	add := func(label string) {
		label = strings.ToLower(strings.TrimSpace(label))
		if label != "" {
			seen[label] = true
		}
	}
	add("profile:" + data.Scan.Profile)
	if data.Scan.RiskScore < 50 {
		add("risk:high")
	} else if data.Scan.RiskScore < 80 {
		add("risk:medium")
	} else {
		add("risk:low")
	}
	for _, service := range data.Services {
		add("service:" + service.Service)
		if service.Product != "" {
			add("product:" + service.Product)
		}
	}
	for _, finding := range data.Findings {
		add("severity:" + finding.Severity)
		if finding.CVEID != "" {
			add("cve")
		}
	}
	labels := make([]string, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

func MissingSections(manifest Manifest) []string {
	var missing []string
	for _, section := range manifest.Sections {
		if !section.Present {
			missing = append(missing, section.Name)
		}
	}
	sort.Strings(missing)
	return missing
}
