package normalize

import (
	"sort"
	"strings"
	"unicode"

	"fahscan/pkg/types"
)

func Space(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func Lower(value string) string {
	return strings.ToLower(Space(value))
}

func Slug(value string) string {
	value = Lower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func Label(value string) string {
	value = Space(strings.ReplaceAll(value, "_", " "))
	if value == "" {
		return ""
	}
	parts := strings.Fields(value)
	for i, part := range parts {
		if isInitialism(part) {
			parts[i] = strings.ToUpper(part)
			continue
		}
		runes := []rune(strings.ToLower(part))
		runes[0] = unicode.ToUpper(runes[0])
		parts[i] = string(runes)
	}
	return strings.Join(parts, " ")
}

func ServiceKey(service types.Service) string {
	return strings.Join([]string{
		intString(service.Port),
		Lower(service.Protocol),
		Lower(service.Service),
		Lower(service.Product),
		Lower(service.Version),
	}, "|")
}

func FindingKey(finding types.Finding) string {
	if finding.CVEID != "" {
		return "cve|" + strings.ToUpper(Space(finding.CVEID))
	}
	return strings.Join([]string{
		"finding",
		Lower(finding.Title),
		Lower(finding.Severity),
		Lower(finding.Evidence),
	}, "|")
}

func TargetKey(target string) string {
	return Lower(strings.TrimSuffix(target, "."))
}

func UniqueStrings(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		key := Lower(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; !ok {
			seen[key] = Space(value)
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func UniqueServices(services []types.Service) []types.Service {
	seen := map[string]types.Service{}
	for _, service := range services {
		key := ServiceKey(service)
		if _, ok := seen[key]; !ok {
			seen[key] = service
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]types.Service, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func UniqueFindings(findings []types.Finding) []types.Finding {
	seen := map[string]types.Finding{}
	for _, finding := range findings {
		key := FindingKey(finding)
		if _, ok := seen[key]; !ok {
			seen[key] = finding
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]types.Finding, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func Metadata(metadata map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range metadata {
		cleanKey := Slug(key)
		if cleanKey == "" {
			continue
		}
		out[cleanKey] = Space(value)
	}
	return out
}

func PortLabel(port int, protocol string) string {
	protocol = Lower(protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	return intString(port) + "/" + protocol
}

func ServiceLabel(service types.Service) string {
	parts := []string{PortLabel(service.Port, service.Protocol)}
	if service.Service != "" {
		parts = append(parts, service.Service)
	}
	if service.Product != "" {
		parts = append(parts, "("+service.Product+")")
	}
	return Space(strings.Join(parts, " "))
}

func FindingLabel(finding types.Finding) string {
	prefix := strings.ToUpper(Space(finding.Severity))
	if prefix == "" {
		prefix = "INFO"
	}
	title := Space(finding.Title)
	if finding.CVEID != "" {
		title += " [" + strings.ToUpper(Space(finding.CVEID)) + "]"
	}
	return "[" + prefix + "] " + title
}

func SortLabels(values []string) []string {
	out := UniqueStrings(values)
	sort.SliceStable(out, func(i, j int) bool {
		return Lower(out[i]) < Lower(out[j])
	})
	return out
}

func isInitialism(value string) bool {
	switch strings.ToLower(value) {
	case "http", "https", "tls", "tcp", "udp", "ssh", "ftp", "smtp", "dns", "cve", "json", "html", "txt", "csv", "ip", "id":
		return true
	default:
		return false
	}
}

func intString(n int) string {
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
