package main

import (
	"reflect"
	"testing"
)

func TestExtractStatuses(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "single status ok",
			in: `state:      active
domain:     example.se
status:     ok
`,
			want: []string{"ok"},
		},
		{
			name: "multiple statuses with EPP annotations",
			in: `status:     serverTransferProhibited (EPP)
status:     serverRenewProhibited
holder:     handle12345
`,
			want: []string{"serverTransferProhibited", "serverRenewProhibited"},
		},
		{
			name: "case insensitive key match",
			in: `STATUS: serverUpdateProhibited
Status: serverDeleteProhibited
`,
			want: []string{"serverUpdateProhibited", "serverDeleteProhibited"},
		},
		{
			name: "no status lines",
			in: `domain: example.se
holder: handle
`,
			want: nil,
		},
		{
			name: "blank status value is skipped",
			in: `status:
status: ok
`,
			want: []string{"ok"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractStatuses([]byte(tc.in))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchesAny(t *testing.T) {
	needles := []string{"serverTransferProhibited", "serverRenewProhibited"}
	tests := []struct {
		name string
		in   []string
		want bool
	}{
		{"match first", []string{"ok", "serverTransferProhibited"}, true},
		{"match second", []string{"serverRenewProhibited"}, true},
		{"no match", []string{"ok", "clientTransferProhibited"}, false},
		{"empty input", nil, false},
		{"case mismatch does not match", []string{"servertransferprohibited"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesAny(tc.in, needles); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
