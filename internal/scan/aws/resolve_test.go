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
	last     *KeyUse
	calls    []string
	lastErr  error
	polCalls int
}

func (f *fakeAPI) CallerIdentity(context.Context) (Identity, error) { return f.id, f.idErr }
func (f *fakeAPI) Policies(context.Context, Identity) ([]Policy, error) {
	f.calls = append(f.calls, "policies")
	f.polCalls++
	return f.policies, f.polErr
}
func (f *fakeAPI) AccessKeyLastUsed(context.Context, string) (*KeyUse, error) {
	f.calls = append(f.calls, "lastused")
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
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"}, last: &KeyUse{At: when, Service: "s3"}}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	c := find(t, creds, "default")
	r, err := s.Resolve(context.Background(), c)
	if err != nil || !r.KeyChecked || r.KeyLastUsed == nil || !r.KeyLastUsed.Equal(when) || r.KeyLastUsedService != "s3" {
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

func TestResolveKeyLastUsedBeforePolicies(t *testing.T) {
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"}}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	if _, err := s.Resolve(context.Background(), find(t, creds, "default")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls, ","); got != "lastused,policies" {
		t.Errorf("call order = %s", got)
	}
}

func TestResolveUninspectedPrincipalIsNotChecked(t *testing.T) {
	f := &fakeAPI{id: Identity{ARN: "arn:aws:sts::1:federated-user/x", Kind: "other"}}
	s, creds, _ := scannerWith(t, f, basicConfig, basicKeys, nil)
	r, err := s.Resolve(context.Background(), find(t, creds, "default"))
	if err != nil || r.AdminChecked || r.Admin || r.AdminWhy != "principal type not inspected" {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestResolveSkipsPromptingProfiles(t *testing.T) {
	cfg := "[profile proc]\ncredential_process = /bin/true\n\n[profile mfa]\nrole_arn = arn:aws:iam::1:role/r\nmfa_serial = arn:aws:iam::1:mfa/me\nsource_profile = default\n\n[profile hop]\nrole_arn = arn:aws:iam::1:role/r\nsource_profile = proc\n"
	s, creds, profiles := scannerWith(t, &fakeAPI{}, cfg, basicKeys, nil)
	for _, id := range []string{"proc", "mfa", "hop"} {
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

func TestResolveSourceProfileCycleTerminates(t *testing.T) {
	cfg := "[profile a]\nrole_arn = arn:aws:iam::1:role/a\nsource_profile = b\n\n[profile b]\nrole_arn = arn:aws:iam::1:role/b\nsource_profile = a\n"
	f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"}}
	s, creds, _ := scannerWith(t, f, cfg, "", nil)
	if _, err := s.Resolve(context.Background(), find(t, creds, "a")); err != nil {
		t.Fatal(err)
	}
}

func TestResolveFallbackProfileOfChainIsChecked(t *testing.T) {
	cfg := "[default]\ncredential_process = /bin/true\n\n[profile safe]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
	chainVars := map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/x"}
	cases := []struct {
		name string
		vars map[string]string
		id   string
		skip bool
	}{
		{"chain falls back to default", chainVars, "chain", true},
		{"chain honours AWS_PROFILE", map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/x", "AWS_PROFILE": "safe"}, "chain", false},
		{"env without secret falls back", map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}, "environment", true},
		{"env with secret does not", map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY": "x"}, "environment", false},
	}
	for _, c := range cases {
		f := &fakeAPI{id: Identity{ARN: "arn:aws:iam::1:user/u", Kind: "user", Name: "u"}}
		s, creds, _ := scannerWith(t, f, cfg, "", c.vars)
		_, err := s.Resolve(context.Background(), find(t, creds, c.id))
		var skip *scan.SkipError
		if errors.As(err, &skip) != c.skip || (!c.skip && err != nil) {
			t.Errorf("%s: err = %v, want skip=%v", c.name, err, c.skip)
		}
	}
}

func TestResolveSkipsLoginSessionProfiles(t *testing.T) {
	cfg := "[profile lg]\nlogin_session = arn:aws:iam::1:user/u\nregion = us-east-1\n\n[profile hop]\nrole_arn = arn:aws:iam::1:role/r\nsource_profile = lg\n"
	s, creds, profiles := scannerWith(t, &fakeAPI{}, cfg, "", nil)
	if k := find(t, creds, "lg").Kind; k != "login" {
		t.Errorf("kind = %q, want login", k)
	}
	for _, id := range []string{"lg", "hop"} {
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

func TestResolveFallbackHonoursAWSDefaultProfile(t *testing.T) {
	cfg := "[profile p]\ncredential_process = /bin/true\n\n[profile lg]\nlogin_session = x\n"
	for name, vars := range map[string]map[string]string{
		"AWS_DEFAULT_PROFILE": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_DEFAULT_PROFILE": "p"},
		"login via env":       {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_PROFILE": "lg"},
	} {
		s, creds, profiles := scannerWith(t, &fakeAPI{}, cfg, "", vars)
		_, err := s.Resolve(context.Background(), find(t, creds, "environment"))
		var skip *scan.SkipError
		if !errors.As(err, &skip) || len(*profiles) != 0 {
			t.Errorf("%s: err = %v, factory calls %v", name, err, *profiles)
		}
	}
}
