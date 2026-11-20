package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

type fakeAPI struct {
	id       Identity
	idErr    error
	policies []Policy
	polErr   error
	last     *time.Time
	lastErr  error
	polCalls int
}

func (f *fakeAPI) CallerIdentity(context.Context) (Identity, error) { return f.id, f.idErr }
func (f *fakeAPI) Policies(context.Context, Identity) ([]Policy, error) {
	f.polCalls++
	return f.policies, f.polErr
}
func (f *fakeAPI) AccessKeyLastUsed(context.Context, string) (*time.Time, error) {
	return f.last, f.lastErr
}

// scannerWith returns a discovered scanner whose factory records the profiles it is asked for.
func scannerWith(t *testing.T, f *fakeAPI, config, keys string, vars map[string]string) (*Scanner, []model.Credential, *[]string) {
	t.Helper()
	var profiles []string
	s := New(func(_ context.Context, p string) (API, error) { profiles = append(profiles, p); return f, nil })
	creds, err := s.Discover(env(fakeHome(t, config, keys), vars))
	if err != nil {
		t.Fatal(err)
	}
	return s, creds, &profiles
}

func find(t *testing.T, cs []model.Credential, id string) model.Credential {
	t.Helper()
	for _, c := range cs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no credential %q", id)
	return model.Credential{}
}

func TestResolveAdminRoleViaFake(t *testing.T) {
	arn := "arn:aws:sts::123456789012:assumed-role/Admin/sess"
	f := &fakeAPI{id: Identity{ARN: arn, Kind: "role", Name: "Admin"}, policies: []Policy{{Name: "AdministratorAccess", ARN: adminARN}}}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	r, err := s.Resolve(context.Background(), find(t, creds, "default"))
	if err != nil || r.Identity != arn || !r.Admin || !r.AdminChecked {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestResolveRootIsAdmin(t *testing.T) {
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:root", Kind: "root"}}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	r, err := s.Resolve(context.Background(), find(t, creds, "default"))
	if err != nil || !r.Admin || !r.AdminChecked || f.polCalls != 0 {
		t.Fatalf("r=%+v err=%v policyCalls=%d", r, err, f.polCalls)
	}
}

func TestResolvePolicyFailureDegrades(t *testing.T) {
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"}, polErr: errors.New("AccessDenied")}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	r, err := s.Resolve(context.Background(), find(t, creds, "default"))
	if err != nil || r.Admin || r.AdminChecked || !strings.Contains(r.AdminWhy, "could not read policies") || len(r.AdminWhy) > 200 {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestResolveNonAdminPoliciesAreChecked(t *testing.T) {
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"},
		policies: []Policy{{Name: "ro", Document: []byte(`{"Statement":{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}}`)}}}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	r, err := s.Resolve(context.Background(), find(t, creds, "default"))
	if err != nil || r.Admin || !r.AdminChecked {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestResolveKeyLastUsed(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"}, last: &when}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	c := find(t, creds, "default")
	r, err := s.Resolve(context.Background(), c)
	if err != nil || !r.KeyChecked || r.KeyLastUsed == nil || !r.KeyLastUsed.Equal(when) {
		t.Fatalf("used: r=%+v err=%v", r, err)
	}
	f.last = nil
	if r, _ = s.Resolve(context.Background(), c); !r.KeyChecked || r.KeyLastUsed != nil {
		t.Fatalf("never used: %+v", r)
	}
	f.lastErr = errors.New("AccessDenied")
	r, err = s.Resolve(context.Background(), c)
	if err != nil || r == nil || r.KeyChecked || r.KeyLastUsed != nil {
		t.Fatalf("denied: r=%+v err=%v", r, err)
	}
}

func TestResolveSkipsPromptingProfiles(t *testing.T) {
	cfg := "[profile proc]\ncredential_process = /bin/true\n\n[profile mfa]\nrole_arn = arn:aws:iam::1:role/r\nmfa_serial = arn:aws:iam::1:mfa/me\nsource_profile = default\n"
	s, creds, profiles := scannerWith(t, &fakeAPI{}, cfg, basicKeys, nil)
	for _, id := range []string{"proc", "mfa"} {
		_, err := s.Resolve(context.Background(), find(t, creds, id))
		var skip *scan.SkipError
		if !errors.As(err, &skip) {
			t.Errorf("%s: err = %v, want SkipError", id, err)
		}
	}
	if len(*profiles) != 0 {
		t.Errorf("factory called: %v", *profiles)
	}
}

func TestResolveUnreadableSkips(t *testing.T) {
	s := New(nil)
	_, err := s.Resolve(context.Background(), model.Credential{ID: "unreadable", Source: "file"})
	var skip *scan.SkipError
	if !errors.As(err, &skip) {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveErrorsAreSanitisedAndDegrade(t *testing.T) {
	f := &fakeAPI{idErr: errors.New("bad\x1b[31m " + strings.Repeat("x", 500))}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	_, err := s.Resolve(context.Background(), find(t, creds, "default"))
	if err == nil || len([]rune(err.Error())) > 200 || err.Error() != model.Sanitize(err.Error()) {
		t.Fatalf("err = %q", err)
	}
}

func TestResolveUsesChainForEnvironmentAndChain(t *testing.T) {
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"}}
	vars := map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_WEB_IDENTITY_TOKEN_FILE": "/x"}
	cfg := "[profile environment]\naws_access_key_id = AKIAIOSFODNN7EXAMPLF\n"
	s, creds, profiles := scannerWith(t, f, cfg, basicKeys, vars)
	for _, id := range []string{"environment", "chain", "default", "profile:environment"} {
		if _, err := s.Resolve(context.Background(), find(t, creds, id)); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"", "", "default", "environment"}
	if strings.Join(*profiles, "|") != strings.Join(want, "|") {
		t.Errorf("profiles = %q, want %q", *profiles, want)
	}
}
