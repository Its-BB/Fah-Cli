package scanner

import (
	"fmt"
	"sort"
	"time"
)

type Plan struct {
	Target         string
	Profile        string
	Ports          []int
	Concurrency    int
	ConnectTimeout time.Duration
	EstimatedWork  int
	Warnings       []string
}

func NewPlan(target, profile string, ports []int, concurrency int, timeout time.Duration) (Plan, error) {
	if target == "" {
		return Plan{}, fmt.Errorf("target is required")
	}
	if len(ports) == 0 {
		return Plan{}, fmt.Errorf("at least one port is required")
	}
	clean := normalizePorts(ports)
	if concurrency <= 0 {
		concurrency = 1
	}
	plan := Plan{Target: target, Profile: profile, Ports: clean, Concurrency: concurrency, ConnectTimeout: timeout, EstimatedWork: len(clean)}
	if len(clean) > 100 {
		plan.Warnings = append(plan.Warnings, "large port set; confirm this is authorized and intentionally scoped")
	}
	if concurrency > len(clean) {
		plan.Warnings = append(plan.Warnings, "concurrency exceeds port count; excess workers will be idle")
	}
	return plan, nil
}

func (p Plan) Batches() [][]int {
	if p.Concurrency <= 0 {
		return [][]int{append([]int(nil), p.Ports...)}
	}
	var batches [][]int
	for i := 0; i < len(p.Ports); i += p.Concurrency {
		end := i + p.Concurrency
		if end > len(p.Ports) {
			end = len(p.Ports)
		}
		batches = append(batches, append([]int(nil), p.Ports[i:end]...))
	}
	return batches
}

func normalizePorts(ports []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}
