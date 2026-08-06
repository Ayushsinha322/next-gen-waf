package certmon

import "testing"

func TestSeverityFor(t *testing.T) {
	tests := []struct {
		days int64
		want string
	}{
		{-5, "critical"}, // already expired
		{0, "critical"},
		{1, "critical"},
		{7, "critical"},
		{8, "high"},
		{14, "high"},
		{15, "medium"},
		{30, "medium"},
		{31, ""}, // healthy — no alert
		{365, ""},
	}
	for _, tc := range tests {
		if got := severityFor(tc.days); got != tc.want {
			t.Errorf("severityFor(%d) = %q, want %q", tc.days, got, tc.want)
		}
	}
}
