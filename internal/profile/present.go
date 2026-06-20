package profile

import (
	"fmt"
	"strings"
)

type Summary struct {
	Name        string `json:"name"`
	PortCount   int    `json:"port_count"`
	Families    string `json:"families"`
	Tags        string `json:"tags"`
	Description string `json:"description"`
}

func Summaries(defs []Definition) []Summary {
	out := make([]Summary, 0, len(defs))
	for _, def := range defs {
		out = append(out, Summary{
			Name:        def.Name,
			PortCount:   len(def.Ports),
			Families:    strings.Join(def.Families, ","),
			Tags:        strings.Join(def.Tags, ","),
			Description: def.Description,
		})
	}
	return out
}

func DescribeResult(result ComposeResult) []string {
	lines := []string{
		"name: " + result.Name,
		"ports: " + ports(result.Ports),
		"port_count: " + fmt.Sprint(result.PortCount),
	}
	if len(result.Sources) > 0 {
		lines = append(lines, "sources: "+strings.Join(result.Sources, ","))
	}
	if len(result.Excluded) > 0 {
		lines = append(lines, "excluded: "+ports(result.Excluded))
	}
	for _, warning := range result.Warnings {
		lines = append(lines, "warning: "+warning)
	}
	return lines
}

func ports(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprint(value)
	}
	return strings.Join(parts, ",")
}
