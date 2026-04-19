package health

import (
	"testing"
	"time"
)

func TestFromScore(t *testing.T) {
	cases := []struct {
		score int
		want  Status
	}{
		{100, StatusExcellent},
		{91, StatusExcellent},
		{90, StatusGood},
		{71, StatusGood},
		{70, StatusDegraded},
		{51, StatusDegraded},
		{50, StatusPoor},
		{31, StatusPoor},
		{30, StatusFailing},
		{0, StatusFailing},
	}
	for _, c := range cases {
		if got := FromScore(c.score); got != c.want {
			t.Errorf("FromScore(%d) = %v; want %v", c.score, got, c.want)
		}
	}
}

func TestScoreAllZero(t *testing.T) {
	if s := Score(Metrics{}); s != 0 {
		t.Errorf("Score(zero) = %d; want 0", s)
	}
}

func TestScoreFreshHandshakeDirectHighRTT(t *testing.T) {
	m := Metrics{
		LastHandshake:  time.Now().Add(-60 * time.Second),
		PingRTT:        20 * time.Millisecond,
		PingSuccess:    true,
		RxBytesPerSec:  2048,
		TxBytesPerSec:  2048,
		ConnMethodRank: 100, // DIRECT
	}
	s := Score(m)
	if s < 90 {
		t.Errorf("Score = %d; want >= 90 (fresh direct)", s)
	}
}

func TestScoreRelayLowTraffic(t *testing.T) {
	m := Metrics{
		LastHandshake:  time.Now().Add(-300 * time.Second),
		PingRTT:        150 * time.Millisecond,
		PingSuccess:    true,
		RxBytesPerSec:  0,
		TxBytesPerSec:  0,
		ConnMethodRank: 40, // RELAY
	}
	s := Score(m)
	status := FromScore(s)
	if status != StatusDegraded && status != StatusPoor {
		t.Errorf("Score = %d, status = %v; want Degraded or Poor", s, status)
	}
}

func TestScoreStaleHandshakePingFail(t *testing.T) {
	m := Metrics{
		LastHandshake:  time.Now().Add(-30 * time.Minute),
		PingSuccess:    false,
		ConnMethodRank: 20,
	}
	s := Score(m)
	if status := FromScore(s); status != StatusFailing {
		t.Errorf("Score = %d, status = %v; want Failing", s, status)
	}
}

func TestStatusString(t *testing.T) {
	cases := map[Status]string{
		StatusExcellent: "excellent",
		StatusGood:      "good",
		StatusDegraded:  "degraded",
		StatusPoor:      "poor",
		StatusFailing:   "failing",
		StatusUnknown:   "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("%d.String() = %q; want %q", int(s), got, want)
		}
	}
}
