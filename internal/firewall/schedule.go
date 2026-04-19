package firewall

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Schedule is the parsed form of a rule's JSON-encoded schedule.
//
//	{
//	  "windows": [
//	    {"start": "09:00", "end": "17:00", "days": ["mon","tue","wed","thu","fri"]}
//	  ],
//	  "timezone": "America/Montreal"
//	}
//
// Semantics:
//
//   - A rule is active if `now` falls in ANY window (OR over windows).
//   - An empty days list means every day of the week.
//   - A window where end < start wraps across midnight.
//   - timezone defaults to UTC. Invalid zones fall back to UTC with no error.
//   - An empty Schedule (zero windows) means "always active". Rules with no
//     ScheduleRaw field skip this evaluator entirely — see Rule.IsLive.
type Schedule struct {
	Windows  []Window `json:"windows"`
	Timezone string   `json:"timezone"`
}

// Window is one active time range.
type Window struct {
	Start string   `json:"start"` // "HH:MM"
	End   string   `json:"end"`
	Days  []string `json:"days"` // lowercased three-letter abbreviations
}

// ParseSchedule unmarshals the JSON form and validates each window.
func ParseSchedule(raw string) (*Schedule, error) {
	if strings.TrimSpace(raw) == "" {
		return &Schedule{}, nil
	}
	var s Schedule
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, fmt.Errorf("schedule: %w", err)
	}
	for i, w := range s.Windows {
		if _, _, err := parseHM(w.Start); err != nil {
			return nil, fmt.Errorf("schedule.windows[%d].start: %w", i, err)
		}
		if _, _, err := parseHM(w.End); err != nil {
			return nil, fmt.Errorf("schedule.windows[%d].end: %w", i, err)
		}
	}
	return &s, nil
}

// Active reports whether the schedule permits activity at now.
func (s *Schedule) Active(now time.Time) bool {
	if s == nil {
		return true
	}
	if len(s.Windows) == 0 {
		return true
	}

	loc := time.UTC
	if s.Timezone != "" {
		if l, err := time.LoadLocation(s.Timezone); err == nil {
			loc = l
		}
	}
	local := now.In(loc)
	day := dayAbbrev(local.Weekday())
	minutes := local.Hour()*60 + local.Minute()

	for _, w := range s.Windows {
		if !dayAllowed(w.Days, day) {
			continue
		}
		sh, sm, _ := parseHM(w.Start)
		eh, em, _ := parseHM(w.End)
		startMin := sh*60 + sm
		endMin := eh*60 + em
		if endMin == startMin {
			// Degenerate: zero-length window. Match only exact start minute.
			if minutes == startMin {
				return true
			}
			continue
		}
		if endMin > startMin {
			if minutes >= startMin && minutes < endMin {
				return true
			}
			continue
		}
		// Wraps midnight: active ≥ start OR < end.
		if minutes >= startMin || minutes < endMin {
			return true
		}
	}
	return false
}

// parseHM parses "HH:MM" → (hour, minute, error).
func parseHM(s string) (int, int, error) {
	var h, m int
	n, err := fmt.Sscanf(s, "%d:%d", &h, &m)
	if err != nil || n != 2 {
		return 0, 0, fmt.Errorf("bad time %q (want HH:MM)", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("out-of-range time %q", s)
	}
	return h, m, nil
}

// dayAbbrev returns the lowercase 3-letter day name.
func dayAbbrev(d time.Weekday) string {
	return []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}[int(d)]
}

// dayAllowed returns true if allowed is empty or contains day (case-insensitive).
func dayAllowed(allowed []string, day string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(a, day) {
			return true
		}
	}
	return false
}
