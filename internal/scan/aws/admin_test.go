package aws

import (
	"strings"
	"testing"
)

func TestIsAdmin(t *testing.T) {
	doc := func(s string) []Policy { return []Policy{{Name: "p", Document: []byte(s)}} }
	cases := []struct {
		name string
		ps   []Policy
		want bool
	}{
		{"managed admin", []Policy{{Name: "AdministratorAccess", ARN: adminARN}}, true},
		{"star star", doc(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`), true},
		{"lists", doc(`{"Statement":[{"Effect":"Allow","Action":["s3:*","*"],"Resource":["*"]}]}`), true},
		{"single statement object", doc(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`), true},
		{"service wildcard", doc(`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`), false},
		{"deny", doc(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`), false},
		{"scoped resource", doc(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b"}]}`), false},
		{"condition", doc(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"x":"true"}}}]}`), false},
		{"not action", doc(`{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`), false},
		{"garbage", doc(`not json`), false},
		{"nil document", []Policy{{Name: "x"}}, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got, _ := IsAdmin(c.ps); got != c.want {
			t.Errorf("%s: IsAdmin = %v, want %v", c.name, got, c.want)
		}
	}
	_, why := IsAdmin(cases[0].ps)
	if !strings.Contains(why, "AdministratorAccess") || !strings.Contains(why, "attached policies only") {
		t.Errorf("why = %q", why)
	}
}
