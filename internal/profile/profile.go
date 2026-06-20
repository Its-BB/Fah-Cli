package profile

import (
	"fmt"
	"sort"
	"strings"
)

type Definition struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Ports       []int    `json:"ports"`
	Families    []string `json:"families"`
	Tags        []string `json:"tags"`
}

type ComposeRequest struct {
	IncludeProfiles []string `json:"include_profiles"`
	IncludeFamilies []string `json:"include_families"`
	IncludePorts    []int    `json:"include_ports"`
	ExcludePorts    []int    `json:"exclude_ports"`
	MaxPorts        int      `json:"max_ports"`
}

type ComposeResult struct {
	Name      string   `json:"name"`
	Ports     []int    `json:"ports"`
	Sources   []string `json:"sources"`
	Excluded  []int    `json:"excluded"`
	Warnings  []string `json:"warnings"`
	PortCount int      `json:"port_count"`
}

var definitions = []Definition{
	{Name: "quick", Description: "Conservative common service coverage.", Ports: []int{21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443}, Families: []string{"web", "mail", "remote", "database"}, Tags: []string{"default", "safe"}},
	{Name: "web", Description: "HTTP and HTTPS application surfaces.", Ports: []int{80, 443, 8000, 8080, 8081, 3000, 5000, 5173, 7001, 8008, 8443, 8888, 9000, 9443}, Families: []string{"web", "admin"}, Tags: []string{"web"}},
	{Name: "database", Description: "Common database and data services.", Ports: []int{1433, 1521, 27017, 3306, 5432, 6379, 9200, 9300, 11211, 5984, 9042}, Families: []string{"database", "cache", "search"}, Tags: []string{"data"}},
	{Name: "remote-access", Description: "Remote administration protocols.", Ports: []int{21, 22, 23, 3389, 5900, 5985, 5986}, Families: []string{"remote"}, Tags: []string{"admin"}},
	{Name: "observability", Description: "Monitoring and operational dashboards.", Ports: []int{3000, 5601, 9090, 9093, 9100, 9200, 16686, 4317, 4318}, Families: []string{"observability", "admin"}, Tags: []string{"ops"}},
}

func List() []Definition {
	return append([]Definition(nil), definitions...)
}

func Get(name string) (Definition, bool) {
	for _, def := range definitions {
		if strings.EqualFold(def.Name, name) {
			return def, true
		}
	}
	return Definition{}, false
}

func Compose(req ComposeRequest) (ComposeResult, error) {
	if req.MaxPorts <= 0 || req.MaxPorts > 100 {
		req.MaxPorts = 100
	}
	result := ComposeResult{Name: "custom-composed"}
	ports := map[int]bool{}
	for _, name := range req.IncludeProfiles {
		def, ok := Get(name)
		if !ok {
			return result, fmt.Errorf("unknown profile %q", name)
		}
		addPorts(ports, def.Ports...)
		result.Sources = append(result.Sources, "profile:"+def.Name)
	}
	for _, family := range req.IncludeFamilies {
		found := false
		for _, def := range definitions {
			if contains(def.Families, family) {
				found = true
				addPorts(ports, def.Ports...)
				result.Sources = append(result.Sources, "family:"+family+"/"+def.Name)
			}
		}
		if !found {
			result.Warnings = append(result.Warnings, "no profile family matched "+family)
		}
	}
	addPorts(ports, req.IncludePorts...)
	excluded := map[int]bool{}
	for _, port := range req.ExcludePorts {
		if ports[port] {
			result.Excluded = append(result.Excluded, port)
		}
		delete(ports, port)
		excluded[port] = true
	}
	for port := range ports {
		if port < 1 || port > 65535 || excluded[port] {
			continue
		}
		result.Ports = append(result.Ports, port)
	}
	sort.Ints(result.Ports)
	sort.Ints(result.Excluded)
	if len(result.Ports) > req.MaxPorts {
		result.Warnings = append(result.Warnings, fmt.Sprintf("port list truncated from %d to %d", len(result.Ports), req.MaxPorts))
		result.Ports = result.Ports[:req.MaxPorts]
	}
	result.PortCount = len(result.Ports)
	if result.PortCount == 0 {
		return result, fmt.Errorf("composed profile has no ports")
	}
	return result, nil
}

func FamilyIndex() map[string][]Definition {
	index := map[string][]Definition{}
	for _, def := range definitions {
		for _, family := range def.Families {
			index[family] = append(index[family], def)
		}
	}
	return index
}

func ValidatePorts(ports []int, max int) error {
	if max <= 0 {
		max = 100
	}
	if len(ports) > max {
		return fmt.Errorf("port count %d exceeds max %d", len(ports), max)
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d", port)
		}
	}
	return nil
}

func addPorts(dst map[int]bool, ports ...int) {
	for _, port := range ports {
		dst[port] = true
	}
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}
