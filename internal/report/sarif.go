package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"fahscan/pkg/types"
)

type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
}

type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription SARIFMessage    `json:"shortDescription"`
	FullDescription  SARIFMessage    `json:"fullDescription"`
	Help             SARIFMessage    `json:"help"`
	Properties       SARIFProperties `json:"properties"`
}

type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    SARIFMessage    `json:"message"`
	Locations  []SARIFLocation `json:"locations,omitempty"`
	Properties SARIFProperties `json:"properties,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFProperties map[string]any

func RenderSARIF(data types.ReportData) ([]byte, error) {
	rules := make([]SARIFRule, 0, len(data.Findings))
	results := make([]SARIFResult, 0, len(data.Findings))
	seenRules := map[string]bool{}
	for _, finding := range data.Findings {
		ruleID := sarifRuleID(finding)
		if !seenRules[ruleID] {
			seenRules[ruleID] = true
			rules = append(rules, SARIFRule{
				ID:               ruleID,
				Name:             finding.Title,
				ShortDescription: SARIFMessage{Text: finding.Title},
				FullDescription:  SARIFMessage{Text: finding.Description},
				Help:             SARIFMessage{Text: finding.Recommendation},
				Properties:       SARIFProperties{"severity": finding.Severity, "confidence": finding.Confidence, "cve_id": finding.CVEID},
			})
		}
		results = append(results, SARIFResult{
			RuleID:  ruleID,
			Level:   sarifLevel(finding.Severity),
			Message: SARIFMessage{Text: resultMessage(finding)},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: data.Scan.Target}},
			}},
			Properties: SARIFProperties{"scan_id": data.Scan.ID, "service_id": finding.ServiceID, "evidence": finding.Evidence},
		})
	}
	log := SARIFLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{{
			Tool:    SARIFTool{Driver: SARIFDriver{Name: "FahScan", SemanticVersion: "1.0.0", Rules: rules}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func sarifRuleID(finding types.Finding) string {
	if strings.TrimSpace(finding.CVEID) != "" {
		return finding.CVEID
	}
	id := strings.ToUpper(finding.Title)
	replacer := strings.NewReplacer(" ", "-", "/", "-", "_", "-", ":", "-", ".", "-")
	id = replacer.Replace(id)
	for strings.Contains(id, "--") {
		id = strings.ReplaceAll(id, "--", "-")
	}
	id = strings.Trim(id, "-")
	if id == "" {
		return "FAHSCAN-FINDING"
	}
	return "FAHSCAN-" + id
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}

func resultMessage(finding types.Finding) string {
	msg := finding.Title
	if finding.CVEID != "" {
		msg = fmt.Sprintf("%s (%s)", msg, finding.CVEID)
	}
	if finding.Evidence != "" {
		msg += ": " + finding.Evidence
	}
	return msg
}
