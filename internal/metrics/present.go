package metrics

import (
	"fmt"
	"sort"
)

type Row struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func Rows(m Metrics) []Row {
	rows := []Row{
		{Key: "scans", Value: intText(m.Scans)},
		{Key: "targets", Value: intText(m.Targets)},
		{Key: "services", Value: intText(m.Services)},
		{Key: "findings", Value: intText(m.Findings)},
		{Key: "open_ports", Value: intText(m.OpenPorts)},
		{Key: "average_risk", Value: fmt.Sprintf("%.1f", m.AverageRisk)},
		{Key: "riskiest_target", Value: m.RiskiestTarget},
	}
	for _, key := range sortedKeys(m.BySeverity) {
		rows = append(rows, Row{Key: "severity." + key, Value: intText(m.BySeverity[key])})
	}
	for _, port := range m.TopPorts {
		rows = append(rows, Row{Key: fmt.Sprintf("port.%d", port.Port), Value: intText(port.Count)})
	}
	return rows
}

func sortedKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
