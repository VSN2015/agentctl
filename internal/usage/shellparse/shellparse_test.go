package shellparse

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseAWS(t *testing.T) {
	tests := []struct {
		cmd  string
		want []string // targets
	}{
		{"aws s3 ls", []string{""}},
		{"aws s3 ls --profile prod", []string{"prod"}},
		{"aws --profile=prod s3 ls", []string{"prod"}},
		{"AWS_PROFILE=prod aws s3 ls", []string{"prod"}},
		{"env AWS_PROFILE=prod aws sts get-caller-identity", []string{"prod"}},
		{"sudo aws s3 ls", []string{""}},
		{"cd x && aws s3 ls | head", []string{""}},
		{"bash -c 'aws s3 ls --profile prod'", []string{"prod"}},
		{"echo $(aws sts get-caller-identity --profile dev)", []string{"dev"}},
		{"aws s3 ls --profile a && aws s3 ls --profile b", []string{"a", "b"}},
		{"awscli-wrapper x", nil},
		{"naws x", nil},
		{"paws", nil},
	}
	for _, tc := range tests {
		var got []string
		for _, inv := range Parse(tc.cmd) {
			if inv.Tool != "aws" || inv.Sub != "" {
				t.Errorf("%q: unexpected invocation %+v", tc.cmd, inv)
			}
			got = append(got, inv.Target)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: targets %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

func TestParseGH(t *testing.T) {
	tests := []struct {
		cmd  string
		want []Invocation
	}{
		{"gh pr list", []Invocation{{"gh", "pr", ""}}},
		{"gh api repos/x/y", []Invocation{{"gh", "api", ""}}},
		{"gh --version", []Invocation{{"gh", "", ""}}},
		{"GH_HOST=ghe.example.com gh issue list", []Invocation{{"gh", "issue", "ghe.example.com"}}},
		{"gh pr list --hostname ghe.example.com", []Invocation{{"gh", "pr", "ghe.example.com"}}},
		{"ghost x", nil},
		{"gh pr list && gh run list", []Invocation{{"gh", "pr", ""}, {"gh", "run", ""}}},
	}
	for _, tc := range tests {
		if got := Parse(tc.cmd); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %+v, want %+v", tc.cmd, got, tc.want)
		}
	}
}

func TestParseNoneForOtherTools(t *testing.T) {
	for _, cmd := range []string{"ls -la", "git push", ""} {
		if got := Parse(cmd); len(got) != 0 {
			t.Errorf("%q: got %+v, want none", cmd, got)
		}
	}
}

func TestParseDoesNotRetainSecrets(t *testing.T) {
	got := Parse("AWS_SECRET_ACCESS_KEY=CANARY-SECRET-DO-NOT-PRINT aws s3 ls")
	if len(got) != 1 {
		t.Fatalf("got %+v, want one invocation", got)
	}
	if s := fmt.Sprintf("%+v", got); strings.Contains(s, "CANARY") {
		t.Errorf("result retains command text: %s", s)
	}
}
