package compare

import (
	"fmt"
	"sort"

	"fahscan/pkg/types"
)

type Delta struct {
	BaseScanID int64           `json:"base_scan_id"`
	NewScanID  int64           `json:"new_scan_id"`
	Target     string          `json:"target"`
	Ports      PortDelta       `json:"ports"`
	Services   ServiceDelta    `json:"services"`
	Findings   FindingDelta    `json:"findings"`
	Risk       RiskDelta       `json:"risk"`
	Summary    []SummaryChange `json:"summary"`
}

type PortDelta struct {
	Opened []int `json:"opened"`
	Closed []int `json:"closed"`
	Stable []int `json:"stable"`
}

type ServiceDelta struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Stable  []string `json:"stable"`
}

type FindingDelta struct {
	Added    []string `json:"added"`
	Resolved []string `json:"resolved"`
	Stable   []string `json:"stable"`
}

type RiskDelta struct {
	Before int    `json:"before"`
	After  int    `json:"after"`
	Change int    `json:"change"`
	Trend  string `json:"trend"`
}

type SummaryChange struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func Scans(base types.Scan, baseServices []types.Service, baseFindings []types.Finding, next types.Scan, nextServices []types.Service, nextFindings []types.Finding) Delta {
	delta := Delta{
		BaseScanID: base.ID,
		NewScanID:  next.ID,
		Target:     next.Target,
		Ports:      comparePorts(servicePorts(baseServices), servicePorts(nextServices)),
		Services:   compareStrings(serviceKeys(baseServices), serviceKeys(nextServices)),
		Findings:   compareFindings(baseFindings, nextFindings),
		Risk:       compareRisk(base.RiskScore, next.RiskScore),
	}
	delta.Summary = summarize(delta)
	return delta
}

func comparePorts(before, after []int) PortDelta {
	beforeSet := intSet(before)
	afterSet := intSet(after)
	var delta PortDelta
	for port := range afterSet {
		if !beforeSet[port] {
			delta.Opened = append(delta.Opened, port)
		} else {
			delta.Stable = append(delta.Stable, port)
		}
	}
	for port := range beforeSet {
		if !afterSet[port] {
			delta.Closed = append(delta.Closed, port)
		}
	}
	sort.Ints(delta.Opened)
	sort.Ints(delta.Closed)
	sort.Ints(delta.Stable)
	return delta
}

func compareStrings(before, after []string) ServiceDelta {
	beforeSet := stringSet(before)
	afterSet := stringSet(after)
	var delta ServiceDelta
	for value := range afterSet {
		if !beforeSet[value] {
			delta.Added = append(delta.Added, value)
		} else {
			delta.Stable = append(delta.Stable, value)
		}
	}
	for value := range beforeSet {
		if !afterSet[value] {
			delta.Removed = append(delta.Removed, value)
		}
	}
	sort.Strings(delta.Added)
	sort.Strings(delta.Removed)
	sort.Strings(delta.Stable)
	return delta
}

func compareFindings(before, after []types.Finding) FindingDelta {
	beforeSet := findingSet(before)
	afterSet := findingSet(after)
	var delta FindingDelta
	for value := range afterSet {
		if !beforeSet[value] {
			delta.Added = append(delta.Added, value)
		} else {
			delta.Stable = append(delta.Stable, value)
		}
	}
	for value := range beforeSet {
		if !afterSet[value] {
			delta.Resolved = append(delta.Resolved, value)
		}
	}
	sort.Strings(delta.Added)
	sort.Strings(delta.Resolved)
	sort.Strings(delta.Stable)
	return delta
}

func compareRisk(before, after int) RiskDelta {
	change := after - before
	trend := "unchanged"
	if change > 0 {
		trend = "improved"
	}
	if change < 0 {
		trend = "worse"
	}
	return RiskDelta{Before: before, After: after, Change: change, Trend: trend}
}

func summarize(delta Delta) []SummaryChange {
	var out []SummaryChange
	if len(delta.Ports.Opened) > 0 {
		out = append(out, SummaryChange{Kind: "ports", Message: fmt.Sprintf("%d newly open port(s)", len(delta.Ports.Opened))})
	}
	if len(delta.Ports.Closed) > 0 {
		out = append(out, SummaryChange{Kind: "ports", Message: fmt.Sprintf("%d port(s) closed", len(delta.Ports.Closed))})
	}
	if len(delta.Findings.Added) > 0 {
		out = append(out, SummaryChange{Kind: "findings", Message: fmt.Sprintf("%d new finding(s)", len(delta.Findings.Added))})
	}
	if len(delta.Findings.Resolved) > 0 {
		out = append(out, SummaryChange{Kind: "findings", Message: fmt.Sprintf("%d finding(s) resolved", len(delta.Findings.Resolved))})
	}
	if delta.Risk.Change != 0 {
		out = append(out, SummaryChange{Kind: "risk", Message: fmt.Sprintf("risk score %s by %+d", delta.Risk.Trend, delta.Risk.Change)})
	}
	if len(out) == 0 {
		out = append(out, SummaryChange{Kind: "stable", Message: "No material passive changes detected."})
	}
	return out
}

func servicePorts(services []types.Service) []int {
	var ports []int
	for _, service := range services {
		ports = append(ports, service.Port)
	}
	return ports
}

func serviceKeys(services []types.Service) []string {
	var keys []string
	for _, service := range services {
		keys = append(keys, fmt.Sprintf("%d/%s/%s", service.Port, service.Protocol, service.Service))
	}
	return keys
}

func intSet(values []int) map[int]bool {
	out := map[int]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func stringSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func findingSet(findings []types.Finding) map[string]bool {
	out := map[string]bool{}
	for _, finding := range findings {
		key := finding.CVEID
		if key == "" {
			key = finding.Title
		}
		out[key] = true
	}
	return out
}
