package knowledge

import "strings"

type Rule struct {
	ID             string
	Category       string
	Title          string
	Signal         string
	Severity       string
	Recommendation string
	Tags           []string
}

type PortRecord struct {
	Port        int
	Protocol    string
	Service     string
	Category    string
	Description string
	RiskHint    string
	Tags        []string
}

type Query struct {
	Text     string
	Category string
	Severity string
	Tag      string
}

func Rules() []Rule {
	return append([]Rule(nil), ruleCatalog...)
}

func Ports() []PortRecord {
	return append([]PortRecord(nil), portCatalog...)
}

func SearchRules(q Query) []Rule {
	var out []Rule
	for _, rule := range ruleCatalog {
		if matchText(q.Text, rule.ID, rule.Category, rule.Title, rule.Signal, rule.Severity, rule.Recommendation, strings.Join(rule.Tags, " ")) &&
			matchExact(q.Category, rule.Category) &&
			matchExact(q.Severity, rule.Severity) &&
			matchTag(q.Tag, rule.Tags) {
			out = append(out, rule)
		}
	}
	return out
}

func SearchPorts(q Query) []PortRecord {
	var out []PortRecord
	for _, port := range portCatalog {
		if matchText(q.Text, port.Protocol, port.Service, port.Category, port.Description, port.RiskHint, strings.Join(port.Tags, " ")) &&
			matchExact(q.Category, port.Category) &&
			matchTag(q.Tag, port.Tags) {
			out = append(out, port)
		}
	}
	return out
}

func RuleStats() map[string]int {
	stats := map[string]int{"total": len(ruleCatalog)}
	for _, rule := range ruleCatalog {
		stats["category:"+rule.Category]++
		stats["severity:"+rule.Severity]++
		for _, tag := range rule.Tags {
			stats["tag:"+tag]++
		}
	}
	return stats
}

func PortStats() map[string]int {
	stats := map[string]int{"total": len(portCatalog)}
	for _, port := range portCatalog {
		stats["category:"+port.Category]++
		stats["protocol:"+port.Protocol]++
		for _, tag := range port.Tags {
			stats["tag:"+tag]++
		}
	}
	return stats
}

func matchText(query string, values ...string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func matchExact(query string, value string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	return strings.ToLower(value) == query
}

func matchTag(query string, tags []string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	for _, tag := range tags {
		if strings.ToLower(tag) == query {
			return true
		}
	}
	return false
}
