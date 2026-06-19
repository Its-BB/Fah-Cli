package database

import (
	"fmt"
	"strings"
	"time"

	"fahscan/pkg/types"
)

type ScanQuery struct {
	Target        string
	Profile       string
	Status        string
	MinRisk       int
	MaxRisk       int
	StartedAfter  time.Time
	StartedBefore time.Time
	Limit         int
}

type TargetSummary struct {
	Target       string    `json:"target"`
	Scans        int       `json:"scans"`
	LatestScanID int64     `json:"latest_scan_id"`
	LatestRisk   int       `json:"latest_risk"`
	LastSeen     time.Time `json:"last_seen"`
	OpenServices int       `json:"open_services"`
	Findings     int       `json:"findings"`
}

type FindingSummary struct {
	Severity   string `json:"severity"`
	Count      int    `json:"count"`
	CVECount   int    `json:"cve_count"`
	Confidence string `json:"confidence,omitempty"`
}

func (db *DB) QueryScans(query ScanQuery) ([]types.Scan, error) {
	scans, err := db.ListScans()
	if err != nil {
		return nil, err
	}
	var out []types.Scan
	for _, scan := range scans {
		if query.Target != "" && !strings.Contains(strings.ToLower(scan.Target), strings.ToLower(query.Target)) {
			continue
		}
		if query.Profile != "" && !strings.EqualFold(scan.Profile, query.Profile) {
			continue
		}
		if query.Status != "" && !strings.EqualFold(scan.Status, query.Status) {
			continue
		}
		if query.MinRisk != 0 && scan.RiskScore < query.MinRisk {
			continue
		}
		if query.MaxRisk != 0 && scan.RiskScore > query.MaxRisk {
			continue
		}
		if !query.StartedAfter.IsZero() && scan.StartedAt.Before(query.StartedAfter) {
			continue
		}
		if !query.StartedBefore.IsZero() && scan.StartedAt.After(query.StartedBefore) {
			continue
		}
		out = append(out, scan)
		if query.Limit > 0 && len(out) >= query.Limit {
			break
		}
	}
	return out, nil
}

func (db *DB) TargetSummaries() ([]TargetSummary, error) {
	scans, err := db.ListScans()
	if err != nil {
		return nil, err
	}
	byTarget := map[string]*TargetSummary{}
	for _, scan := range scans {
		summary := byTarget[scan.Target]
		if summary == nil {
			summary = &TargetSummary{Target: scan.Target}
			byTarget[scan.Target] = summary
		}
		summary.Scans++
		if scan.FinishedAt.After(summary.LastSeen) {
			summary.LastSeen = scan.FinishedAt
			summary.LatestScanID = scan.ID
			summary.LatestRisk = scan.RiskScore
			services, _ := db.Services(scan.ID)
			findings, _ := db.Findings(scan.ID)
			summary.OpenServices = len(services)
			summary.Findings = len(findings)
		}
	}
	out := make([]TargetSummary, 0, len(byTarget))
	for _, summary := range byTarget {
		out = append(out, *summary)
	}
	return out, nil
}

func (db *DB) FindingSummaries(scanID int64) ([]FindingSummary, error) {
	findings, err := db.Findings(scanID)
	if err != nil {
		return nil, err
	}
	type key struct {
		severity   string
		confidence string
	}
	counts := map[key]*FindingSummary{}
	for _, finding := range findings {
		k := key{severity: strings.ToLower(finding.Severity), confidence: strings.ToLower(finding.Confidence)}
		summary := counts[k]
		if summary == nil {
			summary = &FindingSummary{Severity: k.severity, Confidence: k.confidence}
			counts[k] = summary
		}
		summary.Count++
		if finding.CVEID != "" {
			summary.CVECount++
		}
	}
	out := make([]FindingSummary, 0, len(counts))
	for _, summary := range counts {
		out = append(out, *summary)
	}
	return out, nil
}

func (db *DB) LatestScanForTarget(target string) (types.Scan, error) {
	scans, err := db.QueryScans(ScanQuery{Target: target})
	if err != nil {
		return types.Scan{}, err
	}
	for _, scan := range scans {
		if strings.EqualFold(scan.Target, target) {
			return scan, nil
		}
	}
	return types.Scan{}, fmt.Errorf("no scan found for target %q", target)
}
