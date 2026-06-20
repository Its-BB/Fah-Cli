package schedule

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Frequency string

const (
	Once    Frequency = "once"
	Hourly  Frequency = "hourly"
	Daily   Frequency = "daily"
	Weekly  Frequency = "weekly"
	Monthly Frequency = "monthly"
)

type Window struct {
	Name     string         `json:"name"`
	Start    Clock          `json:"start"`
	End      Clock          `json:"end"`
	Days     []time.Weekday `json:"days"`
	Timezone string         `json:"timezone"`
	Blackout bool           `json:"blackout"`
	Reason   string         `json:"reason,omitempty"`
}

type Clock struct {
	Hour   int `json:"hour"`
	Minute int `json:"minute"`
}

type Plan struct {
	Name        string        `json:"name"`
	Frequency   Frequency     `json:"frequency"`
	Every       int           `json:"every"`
	Anchor      time.Time     `json:"anchor"`
	Windows     []Window      `json:"windows"`
	MaxJitter   time.Duration `json:"max_jitter"`
	TargetTags  []string      `json:"target_tags"`
	Profiles    []string      `json:"profiles"`
	RequireAuth bool          `json:"require_auth"`
}

type Occurrence struct {
	PlanName string    `json:"plan_name"`
	At       time.Time `json:"at"`
	Window   string    `json:"window"`
	Profile  string    `json:"profile"`
	Reason   string    `json:"reason"`
}

type Evaluation struct {
	Now          time.Time    `json:"now"`
	Next         *Occurrence  `json:"next,omitempty"`
	Candidates   []Occurrence `json:"candidates"`
	Skipped      []Occurrence `json:"skipped"`
	AllowedNow   bool         `json:"allowed_now"`
	ActiveWindow string       `json:"active_window,omitempty"`
}

func ParseClock(raw string) (Clock, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 2 {
		return Clock{}, fmt.Errorf("clock must be HH:MM")
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return Clock{}, err
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return Clock{}, err
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return Clock{}, fmt.Errorf("clock outside 00:00-23:59")
	}
	return Clock{Hour: hour, Minute: minute}, nil
}

func (c Clock) String() string {
	return fmt.Sprintf("%02d:%02d", c.Hour, c.Minute)
}

func NewWindow(name, start, end string, days []time.Weekday) (Window, error) {
	s, err := ParseClock(start)
	if err != nil {
		return Window{}, err
	}
	e, err := ParseClock(end)
	if err != nil {
		return Window{}, err
	}
	return Window{Name: name, Start: s, End: e, Days: days}, nil
}

func DefaultWindows() []Window {
	return []Window{
		{Name: "weekday-evening", Start: Clock{Hour: 18}, End: Clock{Hour: 23}, Days: []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday}},
		{Name: "weekend-day", Start: Clock{Hour: 9}, End: Clock{Hour: 18}, Days: []time.Weekday{time.Saturday, time.Sunday}},
	}
}

func ConservativePlan() Plan {
	return Plan{
		Name:        "conservative-local",
		Frequency:   Weekly,
		Every:       1,
		Anchor:      time.Now(),
		Windows:     DefaultWindows(),
		MaxJitter:   15 * time.Minute,
		Profiles:    []string{"quick"},
		RequireAuth: true,
	}
}

func Evaluate(plan Plan, now time.Time, horizon time.Duration) Evaluation {
	if horizon <= 0 {
		horizon = 30 * 24 * time.Hour
	}
	if plan.Every <= 0 {
		plan.Every = 1
	}
	if len(plan.Profiles) == 0 {
		plan.Profiles = []string{"quick"}
	}
	var eval Evaluation
	eval.Now = now
	eval.AllowedNow, eval.ActiveWindow = allowedAt(plan.Windows, now)
	for _, base := range candidateTimes(plan, now, now.Add(horizon)) {
		for _, profile := range plan.Profiles {
			occ := Occurrence{PlanName: plan.Name, At: base, Profile: profile, Reason: string(plan.Frequency)}
			if ok, window := allowedAt(plan.Windows, base); ok {
				occ.Window = window
				eval.Candidates = append(eval.Candidates, occ)
			} else {
				occ.Reason = "outside allowed windows"
				eval.Skipped = append(eval.Skipped, occ)
			}
		}
	}
	sort.Slice(eval.Candidates, func(i, j int) bool { return eval.Candidates[i].At.Before(eval.Candidates[j].At) })
	if len(eval.Candidates) > 0 {
		next := eval.Candidates[0]
		eval.Next = &next
	}
	return eval
}

func candidateTimes(plan Plan, start, end time.Time) []time.Time {
	var out []time.Time
	anchor := plan.Anchor
	if anchor.IsZero() {
		anchor = start
	}
	step := frequencyDuration(plan.Frequency, plan.Every)
	if step <= 0 {
		step = 24 * time.Hour
	}
	for anchor.Before(start) {
		anchor = anchor.Add(step)
	}
	for !anchor.After(end) {
		out = append(out, anchor)
		anchor = anchor.Add(step)
	}
	return out
}

func frequencyDuration(freq Frequency, every int) time.Duration {
	if every <= 0 {
		every = 1
	}
	switch freq {
	case Once:
		return 0
	case Hourly:
		return time.Duration(every) * time.Hour
	case Daily:
		return time.Duration(every) * 24 * time.Hour
	case Weekly:
		return time.Duration(every) * 7 * 24 * time.Hour
	case Monthly:
		return time.Duration(every) * 30 * 24 * time.Hour
	default:
		return time.Duration(every) * 24 * time.Hour
	}
}

func allowedAt(windows []Window, at time.Time) (bool, string) {
	if len(windows) == 0 {
		return true, "always"
	}
	allowed := false
	active := ""
	for _, window := range windows {
		if !dayAllowed(window.Days, at.Weekday()) || !clockContains(window.Start, window.End, at) {
			continue
		}
		if window.Blackout {
			return false, window.Name
		}
		allowed = true
		active = window.Name
	}
	return allowed, active
}

func dayAllowed(days []time.Weekday, day time.Weekday) bool {
	if len(days) == 0 {
		return true
	}
	for _, d := range days {
		if d == day {
			return true
		}
	}
	return false
}

func clockContains(start, end Clock, at time.Time) bool {
	minute := at.Hour()*60 + at.Minute()
	s := start.Hour*60 + start.Minute
	e := end.Hour*60 + end.Minute
	if s == e {
		return true
	}
	if s < e {
		return minute >= s && minute < e
	}
	return minute >= s || minute < e
}

func Describe(plan Plan) []string {
	var lines []string
	lines = append(lines, "name="+plan.Name)
	lines = append(lines, "frequency="+string(plan.Frequency))
	lines = append(lines, "profiles="+strings.Join(plan.Profiles, ","))
	for _, window := range plan.Windows {
		kind := "allow"
		if window.Blackout {
			kind = "blackout"
		}
		lines = append(lines, fmt.Sprintf("window=%s %s-%s %s", window.Name, window.Start.String(), window.End.String(), kind))
	}
	return lines
}
