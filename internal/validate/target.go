package validate

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"fahscan/pkg/types"
)

var domainRe = regexp.MustCompile(`(?i)^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type TargetInfo struct {
	Value string
	Type  string
}

func Target(raw string, cfg types.Config, authorized bool) (TargetInfo, error) {
	value := strings.TrimSpace(raw)
	if !authorized {
		return TargetInfo{}, fmt.Errorf("scan requires --i-am-authorized")
	}
	return ParseTarget(value, cfg)
}

func ParseTarget(value string, cfg types.Config) (TargetInfo, error) {
	if value == "" {
		return TargetInfo{}, fmt.Errorf("target cannot be empty")
	}
	if strings.ContainsAny(value, " \t\r\n,") {
		return TargetInfo{}, fmt.Errorf("exactly one target is allowed")
	}
	if strings.Contains(value, "/") {
		return TargetInfo{}, fmt.Errorf("CIDR and path targets are not supported")
	}
	if strings.Contains(value, "*") {
		return TargetInfo{}, fmt.Errorf("wildcard targets are not supported")
	}
	if strings.EqualFold(value, "localhost") {
		if !cfg.AllowLocalhost {
			return TargetInfo{}, fmt.Errorf("localhost targets are disabled by configuration")
		}
		return TargetInfo{Value: "localhost", Type: "localhost"}, nil
	}
	if ip := net.ParseIP(value); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return TargetInfo{}, fmt.Errorf("only IPv4 targets are supported")
		}
		if isPrivate(ip4) && !cfg.AllowPrivateIP {
			return TargetInfo{}, fmt.Errorf("private IPv4 targets are disabled by configuration")
		}
		if ip4.IsLoopback() && !cfg.AllowLocalhost {
			return TargetInfo{}, fmt.Errorf("loopback targets are disabled by configuration")
		}
		return TargetInfo{Value: ip4.String(), Type: "ipv4"}, nil
	}
	if strings.HasPrefix(value, "-") || strings.HasSuffix(value, ".") || !domainRe.MatchString(value) {
		return TargetInfo{}, fmt.Errorf("malformed domain target")
	}
	return TargetInfo{Value: strings.ToLower(value), Type: "domain"}, nil
}

func isPrivate(ip net.IP) bool {
	privateBlocks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	for _, block := range privateBlocks {
		_, n, _ := net.ParseCIDR(block)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
