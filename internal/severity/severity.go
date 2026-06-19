package severity

import "strings"

type Level int

const (
	Info Level = iota
	Low
	Medium
	High
	Critical
)

type Summary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}

func Parse(raw string) Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return Critical
	case "high":
		return High
	case "medium":
		return Medium
	case "low":
		return Low
	default:
		return Info
	}
}

func String(level Level) string {
	switch level {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "info"
	}
}

func Weight(level Level) int {
	switch level {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	default:
		return 1
	}
}

func FromCVSS(score float64) Level {
	switch {
	case score >= 9:
		return Critical
	case score >= 7:
		return High
	case score >= 4:
		return Medium
	case score > 0:
		return Low
	default:
		return Info
	}
}

func Add(summary *Summary, raw string) {
	summary.Total++
	switch Parse(raw) {
	case Critical:
		summary.Critical++
	case High:
		summary.High++
	case Medium:
		summary.Medium++
	case Low:
		summary.Low++
	default:
		summary.Info++
	}
}

func Highest(values ...string) string {
	best := Info
	for _, value := range values {
		level := Parse(value)
		if Weight(level) > Weight(best) {
			best = level
		}
	}
	return String(best)
}

func Normalize(raw string) string {
	return String(Parse(raw))
}
