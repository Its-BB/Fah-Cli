package metrics

import (
	"sort"
	"strings"

	"fahscan/pkg/types"
)

type Metrics struct {
	Scans          int            `json:"scans"`
	Targets        int            `json:"targets"`
	Services       int            `json:"services"`
	Findings       int            `json:"findings"`
	OpenPorts      int            `json:"open_ports"`
	AverageRisk    float64        `json:"average_risk"`
	BySeverity     map[string]int `json:"by_severity"`
	ByService      map[string]int `json:"by_service"`
	ByProtocol     map[string]int `json:"by_protocol"`
	TopPorts       []PortMetric   `json:"top_ports"`
	RiskiestTarget string         `json:"riskiest_target"`
}

type PortMetric struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}

func Build(scans []types.Scan, services map[int64][]types.Service, findings map[int64][]types.Finding) Metrics {
	m := Metrics{BySeverity: map[string]int{}, ByService: map[string]int{}, ByProtocol: map[string]int{}}
	targets := map[string]bool{}
	portCounts := map[int]int{}
	totalRisk := 0
	lowestRisk := 101
	for _, scan := range scans {
		m.Scans++
		targets[scan.Target] = true
		totalRisk += scan.RiskScore
		if scan.RiskScore < lowestRisk {
			lowestRisk = scan.RiskScore
			m.RiskiestTarget = scan.Target
		}
		for _, service := range services[scan.ID] {
			m.Services++
			portCounts[service.Port]++
			m.ByService[strings.ToLower(service.Service)]++
			m.ByProtocol[strings.ToLower(service.Protocol)]++
		}
		for _, finding := range findings[scan.ID] {
			m.Findings++
			m.BySeverity[strings.ToLower(finding.Severity)]++
		}
	}
	m.Targets = len(targets)
	m.OpenPorts = len(portCounts)
	if m.Scans > 0 {
		m.AverageRisk = float64(totalRisk) / float64(m.Scans)
	}
	for port, count := range portCounts {
		m.TopPorts = append(m.TopPorts, PortMetric{Port: port, Count: count})
	}
	sort.Slice(m.TopPorts, func(i, j int) bool {
		if m.TopPorts[i].Count == m.TopPorts[j].Count {
			return m.TopPorts[i].Port < m.TopPorts[j].Port
		}
		return m.TopPorts[i].Count > m.TopPorts[j].Count
	})
	if len(m.TopPorts) > 10 {
		m.TopPorts = m.TopPorts[:10]
	}
	return m
}

func Merge(values ...Metrics) Metrics {
	out := Metrics{BySeverity: map[string]int{}, ByService: map[string]int{}, ByProtocol: map[string]int{}}
	portCounts := map[int]int{}
	totalRisk := 0.0
	for _, value := range values {
		out.Scans += value.Scans
		out.Targets += value.Targets
		out.Services += value.Services
		out.Findings += value.Findings
		out.OpenPorts += value.OpenPorts
		totalRisk += value.AverageRisk * float64(value.Scans)
		for k, v := range value.BySeverity {
			out.BySeverity[k] += v
		}
		for k, v := range value.ByService {
			out.ByService[k] += v
		}
		for k, v := range value.ByProtocol {
			out.ByProtocol[k] += v
		}
		for _, port := range value.TopPorts {
			portCounts[port.Port] += port.Count
		}
	}
	if out.Scans > 0 {
		out.AverageRisk = totalRisk / float64(out.Scans)
	}
	for port, count := range portCounts {
		out.TopPorts = append(out.TopPorts, PortMetric{Port: port, Count: count})
	}
	sort.Slice(out.TopPorts, func(i, j int) bool { return out.TopPorts[i].Count > out.TopPorts[j].Count })
	return out
}
