package fingerprint

import (
	"regexp"
	"strings"

	"fahscan/pkg/types"
)

type Match struct {
	Product    string
	Version    string
	Family     string
	Confidence int
	Reason     string
}

type Signature struct {
	Name       string
	Family     string
	Product    string
	Pattern    *regexp.Regexp
	VersionRe  *regexp.Regexp
	Confidence int
}

var signatures = []Signature{
	mustSig("apache-httpd", "web-server", "apache", `(?i)\bApache/?([0-9][^\s;]*)?`, `(?i)Apache/?([0-9][^\s;]*)`, 85),
	mustSig("nginx", "web-server", "nginx", `(?i)\bnginx/?([0-9][^\s;]*)?`, `(?i)nginx/?([0-9][^\s;]*)`, 85),
	mustSig("openssh", "remote-access", "openssh", `(?i)\bOpenSSH[_/\- ]?([0-9][^\s]*)?`, `(?i)OpenSSH[_/\- ]?([0-9][^\s]*)`, 90),
	mustSig("redis", "cache", "redis", `(?i)\bredis\b`, `(?i)redis[_/\- ]?([0-9][^\s]*)`, 70),
	mustSig("mysql", "database", "mysql", `(?i)\b(mysql|mariadb)\b`, `(?i)(?:mysql|mariadb)[_/\- ]?([0-9][^\s]*)`, 70),
	mustSig("postgresql", "database", "postgresql", `(?i)\bpostgres(?:ql)?\b`, `(?i)postgres(?:ql)?[_/\- ]?([0-9][^\s]*)`, 70),
	mustSig("mongodb", "database", "mongodb", `(?i)\bmongodb\b`, `(?i)mongodb[_/\- ]?([0-9][^\s]*)`, 70),
	mustSig("elasticsearch", "search", "elasticsearch", `(?i)\belasticsearch\b`, `(?i)elasticsearch[_/\- ]?([0-9][^\s]*)`, 75),
}

func Analyze(service types.Service) []Match {
	text := strings.Join([]string{service.Service, service.Product, service.Version, service.Banner, metadataText(service.Metadata)}, " ")
	var out []Match
	for _, sig := range signatures {
		if !sig.Pattern.MatchString(text) {
			continue
		}
		version := ""
		if sig.VersionRe != nil {
			if found := sig.VersionRe.FindStringSubmatch(text); len(found) > 1 {
				version = strings.Trim(found[1], " ;,)")
			}
		}
		out = append(out, Match{Product: sig.Product, Version: version, Family: sig.Family, Confidence: sig.Confidence, Reason: sig.Name + " signature matched passive metadata"})
	}
	return out
}

func Best(service types.Service) Match {
	matches := Analyze(service)
	var best Match
	for _, match := range matches {
		if match.Confidence > best.Confidence {
			best = match
		}
	}
	return best
}

func Apply(service *types.Service) {
	best := Best(*service)
	if best.Product == "" {
		return
	}
	if service.Product == "" {
		service.Product = best.Product
	}
	if service.Version == "" {
		service.Version = best.Version
	}
	if service.Metadata == nil {
		service.Metadata = map[string]string{}
	}
	service.Metadata["fingerprint_family"] = best.Family
	service.Metadata["fingerprint_confidence"] = intString(best.Confidence)
	service.Metadata["fingerprint_reason"] = best.Reason
}

func metadataText(metadata map[string]string) string {
	var parts []string
	for key, value := range metadata {
		parts = append(parts, key, value)
	}
	return strings.Join(parts, " ")
}

func mustSig(name, family, product, pattern, version string, confidence int) Signature {
	sig := Signature{Name: name, Family: family, Product: product, Pattern: regexp.MustCompile(pattern), Confidence: confidence}
	if version != "" {
		sig.VersionRe = regexp.MustCompile(version)
	}
	return sig
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
