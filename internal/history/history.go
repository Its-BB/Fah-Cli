package history

import (
	"sort"
	"strings"
	"time"

	"fahscan/pkg/types"
)

type Timeline struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Targets     []TargetTrend `json:"targets"`
	Overall     OverallTrend  `json:"overall"`
}

type TargetTrend struct {
	Target          string       `json:"target"`
	FirstScanID     int64        `json:"first_scan_id"`
	LastScanID      int64        `json:"last_scan_id"`
	FirstSeen       time.Time    `json:"first_seen"`
	LastSeen        time.Time    `json:"last_seen"`
	ScanCount       int          `json:"scan_count"`
	BestRiskScore   int          `json:"best_risk_score"`
	WorstRiskScore  int          `json:"worst_risk_score"`
	LatestRiskScore int          `json:"latest_risk_score"`
	RiskTrend       string       `json:"risk_trend"`
	OpenPortTrend   CountTrend   `json:"open_port_trend"`
	FindingTrend    CountTrend   `json:"finding_trend"`
	Events          []TrendEvent `json:"events"`
}

type OverallTrend struct {
	ScanCount       int         `json:"scan_count"`
	TargetCount     int         `json:"target_count"`
	AverageRisk     float64     `json:"average_risk"`
	LatestScanAt    time.Time   `json:"latest_scan_at"`
	HighestRiskDrop TargetDelta `json:"highest_risk_drop"`
	HighestRiskGain TargetDelta `json:"highest_risk_gain"`
}

type CountTrend struct {
	First  int    `json:"first"`
	Latest int    `json:"latest"`
	Change int    `json:"change"`
	Trend  string `json:"trend"`
}

type TargetDelta struct {
	Target string `json:"target"`
	Change int    `json:"change"`
}

type TrendEvent struct {
	ScanID    int64     `json:"scan_id"`
	When      time.Time `json:"when"`
	Kind      string    `json:"kind"`
	Message   string    `json:"message"`
	RiskScore int       `json:"risk_score"`
}

type ScanFacts struct {
	Scan         types.Scan
	ServiceCount int
	FindingCount int
	OpenPorts    []int
	Severities   map[string]int
}

func Build(scans []types.Scan, services map[int64][]types.Service, findings map[int64][]types.Finding) Timeline {
	facts := make([]ScanFacts, 0, len(scans))
	for _, scan := range scans {
		facts = append(facts, factsFor(scan, services[scan.ID], findings[scan.ID]))
	}
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].Scan.Target == facts[j].Scan.Target {
			return facts[i].Scan.StartedAt.Before(facts[j].Scan.StartedAt)
		}
		return facts[i].Scan.Target < facts[j].Scan.Target
	})
	byTarget := map[string][]ScanFacts{}
	for _, fact := range facts {
		byTarget[fact.Scan.Target] = append(byTarget[fact.Scan.Target], fact)
	}
	timeline := Timeline{GeneratedAt: time.Now()}
	for target, targetFacts := range byTarget {
		trend := targetTrend(target, targetFacts)
		timeline.Targets = append(timeline.Targets, trend)
	}
	sort.Slice(timeline.Targets, func(i, j int) bool { return timeline.Targets[i].Target < timeline.Targets[j].Target })
	timeline.Overall = overall(timeline.Targets)
	return timeline
}

func factsFor(scan types.Scan, services []types.Service, findings []types.Finding) ScanFacts {
	fact := ScanFacts{Scan: scan, ServiceCount: len(services), FindingCount: len(findings), Severities: map[string]int{}}
	seenPorts := map[int]bool{}
	for _, service := range services {
		if !seenPorts[service.Port] {
			seenPorts[service.Port] = true
			fact.OpenPorts = append(fact.OpenPorts, service.Port)
		}
	}
	sort.Ints(fact.OpenPorts)
	for _, finding := range findings {
		fact.Severities[strings.ToLower(finding.Severity)]++
	}
	return fact
}

func targetTrend(target string, facts []ScanFacts) TargetTrend {
	sort.Slice(facts, func(i, j int) bool { return facts[i].Scan.StartedAt.Before(facts[j].Scan.StartedAt) })
	first := facts[0]
	last := facts[len(facts)-1]
	trend := TargetTrend{
		Target:          target,
		FirstScanID:     first.Scan.ID,
		LastScanID:      last.Scan.ID,
		FirstSeen:       first.Scan.StartedAt,
		LastSeen:        last.Scan.FinishedAt,
		ScanCount:       len(facts),
		BestRiskScore:   first.Scan.RiskScore,
		WorstRiskScore:  first.Scan.RiskScore,
		LatestRiskScore: last.Scan.RiskScore,
		OpenPortTrend:   countTrend(len(first.OpenPorts), len(last.OpenPorts)),
		FindingTrend:    countTrend(first.FindingCount, last.FindingCount),
	}
	for _, fact := range facts {
		if fact.Scan.RiskScore > trend.BestRiskScore {
			trend.BestRiskScore = fact.Scan.RiskScore
		}
		if fact.Scan.RiskScore < trend.WorstRiskScore {
			trend.WorstRiskScore = fact.Scan.RiskScore
		}
		trend.Events = append(trend.Events, eventsFor(fact)...)
	}
	trend.RiskTrend = riskTrend(first.Scan.RiskScore, last.Scan.RiskScore)
	return trend
}

func eventsFor(fact ScanFacts) []TrendEvent {
	var events []TrendEvent
	if fact.FindingCount > 0 {
		events = append(events, TrendEvent{ScanID: fact.Scan.ID, When: fact.Scan.FinishedAt, Kind: "findings", Message: countMessage(fact.FindingCount, "finding"), RiskScore: fact.Scan.RiskScore})
	}
	if len(fact.OpenPorts) > 0 {
		events = append(events, TrendEvent{ScanID: fact.Scan.ID, When: fact.Scan.FinishedAt, Kind: "services", Message: countMessage(len(fact.OpenPorts), "open port"), RiskScore: fact.Scan.RiskScore})
	}
	if fact.Severities["critical"] > 0 || fact.Severities["high"] > 0 {
		events = append(events, TrendEvent{ScanID: fact.Scan.ID, When: fact.Scan.FinishedAt, Kind: "severity", Message: "high-impact findings observed", RiskScore: fact.Scan.RiskScore})
	}
	return events
}

func overall(targets []TargetTrend) OverallTrend {
	var out OverallTrend
	out.TargetCount = len(targets)
	if len(targets) == 0 {
		return out
	}
	totalRisk := 0
	out.HighestRiskDrop.Change = 0
	out.HighestRiskGain.Change = 0
	for _, target := range targets {
		out.ScanCount += target.ScanCount
		totalRisk += target.LatestRiskScore
		if target.LastSeen.After(out.LatestScanAt) {
			out.LatestScanAt = target.LastSeen
		}
		change := target.LatestRiskScore - target.WorstRiskScore
		if change > out.HighestRiskGain.Change {
			out.HighestRiskGain = TargetDelta{Target: target.Target, Change: change}
		}
		drop := target.LatestRiskScore - target.BestRiskScore
		if drop < out.HighestRiskDrop.Change {
			out.HighestRiskDrop = TargetDelta{Target: target.Target, Change: drop}
		}
	}
	out.AverageRisk = float64(totalRisk) / float64(len(targets))
	return out
}

func countTrend(first, latest int) CountTrend {
	change := latest - first
	trend := "unchanged"
	if change > 0 {
		trend = "increased"
	}
	if change < 0 {
		trend = "decreased"
	}
	return CountTrend{First: first, Latest: latest, Change: change, Trend: trend}
}

func riskTrend(first, latest int) string {
	switch {
	case latest > first:
		return "improved"
	case latest < first:
		return "worse"
	default:
		return "unchanged"
	}
}

func countMessage(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return intText(count) + " " + noun + "s"
}

func intText(n int) string {
	if n == 0 {
		return "0"
	}
	digits := "0123456789"
	var out []byte
	for n > 0 {
		out = append([]byte{digits[n%10]}, out...)
		n /= 10
	}
	return string(out)
}
