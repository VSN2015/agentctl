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
		{`aws s3 ls --profile "prod"`, []string{"prod"}},
		{`AWS_PROFILE='prod' aws s3 ls`, []string{"prod"}},
		{`export AWS_PROFILE="prod"; aws s3 ls`, []string{"prod"}},
		{"aws sts get-caller-identity && aws s3 ls --profile prod", []string{"prod", ""}},
		// accepted over-count: calls outnumber profile matches
		{"export AWS_PROFILE=prod; aws a; aws b", []string{"prod", ""}},
		{"aws s3 ls; aws s3 ls", []string{""}},
		{"aws a --profile p && aws b --profile p", []string{"p"}},
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
		{`gh pr list --hostname "ghe.example.com"`, []Invocation{{"gh", "pr", "ghe.example.com"}}},
		{"gh run list && gh pr list --hostname ghe.example.com", []Invocation{
			{"gh", "run", "ghe.example.com"}, {"gh", "run", ""}, {"gh", "pr", "ghe.example.com"}, {"gh", "pr", ""}}},
		{"GH_HOST=h gh pr list && gh run list --hostname h", []Invocation{{"gh", "pr", "h"}, {"gh", "run", "h"}}},
		{"ghost x", nil},
		{"gh pr list && gh run list", []Invocation{{"gh", "pr", ""}, {"gh", "run", ""}}},
	}
	for _, tc := range tests {
		if got := Parse(tc.cmd); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %+v, want %+v", tc.cmd, got, tc.want)
		}
	}
}

func TestParseDocker(t *testing.T) {
	tests := []struct {
		cmd  string
		want []Invocation
	}{
		{"docker ps", []Invocation{{Tool: "docker"}}},
		{"docker-compose up -d", []Invocation{{Tool: "docker"}}},
		{"docker compose up", []Invocation{{Tool: "docker"}}},
		{"sudo docker run --rm x && docker ps", []Invocation{{Tool: "docker"}}}, // one per command
		{"echo $(docker ps -q)", []Invocation{{Tool: "docker"}}},
		{"cd /srv/docker/app && ls", nil},
		{"dockerd --debug", nil},
		{"mydocker ps", nil},
		{"aws s3 ls; docker ps", []Invocation{{Tool: "aws"}, {Tool: "docker"}}},
	}
	for _, tc := range tests {
		if got := Parse(tc.cmd); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %+v, want %+v", tc.cmd, got, tc.want)
		}
	}
}

func TestParseKubectl(t *testing.T) {
	k := func(target string) Invocation { return Invocation{Tool: "kubectl", Target: target} }
	arn := "arn:aws:eks:us-east-1:123456789012:cluster/prod"
	tests := []struct {
		cmd  string
		want []Invocation
	}{
		{"kubectl get pods", []Invocation{k("")}},
		{"kubectl --context prod get pods", []Invocation{k("prod")}},
		{"kubectl --context=prod get pods", []Invocation{k("prod")}},
		{`kubectl get pods --context "` + arn + `"`, []Invocation{k(arn)}},
		{"kubectl --context a get po; kubectl get po", []Invocation{k("a"), k("")}},
		{"kubectl --context a get po; kubectl --context b get po", []Invocation{k("a"), k("b")}},
		{"kubectl config use-context prod", []Invocation{k("")}}, // documented limit: names no --context
		{"kubectl", []Invocation{k("")}},
		{"kubectlx get pods", nil},
		{"k get pods", nil},
		{"helm --kube-context prod ls", nil},
		{"docker --context colima ps && kubectl get pods", []Invocation{{Tool: "docker"}, k("")}},
		{"istioctl --context prod-mesh x; kubectl get pods", []Invocation{k("")}},
		{"kubectl get pods; helm --context x ls", []Invocation{k("")}},
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
