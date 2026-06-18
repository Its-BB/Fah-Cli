package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var Profiles = map[string][]int{
	"quick":     {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443},
	"web":       {80, 443, 8000, 8080, 8081, 3000, 5000, 5173, 7001, 8008, 8443, 8888, 9000, 9443},
	"database":  {1433, 1521, 27017, 3306, 5432, 6379, 9200, 9300, 11211, 5984, 9042},
	"full-safe": {1, 3, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700},
}

func ProfilePorts(name string) ([]int, error) {
	ports, ok := Profiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown port profile %q", name)
	}
	return append([]int(nil), ports...), nil
}

func ParseCustomPorts(raw string, max int) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("ports cannot be empty")
	}
	if max <= 0 || max > 100 {
		max = 100
	}
	seen := map[int]bool{}
	var ports []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid TCP port %q", part)
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
		if len(ports) > max {
			return nil, fmt.Errorf("custom port list exceeds max of %d", max)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

func InferService(port int) string {
	names := map[int]string{
		21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap",
		443: "https", 465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s", 1433: "mssql",
		1521: "oracle", 3000: "web", 3306: "mysql", 5000: "web", 5173: "web", 5432: "postgresql",
		5984: "couchdb", 6379: "redis", 7001: "admin-web", 8080: "http", 8081: "http",
		8443: "https", 8888: "admin-web", 9000: "admin-web", 9042: "cassandra", 9200: "elasticsearch",
		9300: "elasticsearch", 9443: "https", 11211: "memcached", 27017: "mongodb",
	}
	if name, ok := names[port]; ok {
		return name
	}
	return "unknown"
}
