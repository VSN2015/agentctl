package aws

import (
	"context"
	"errors"
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

// Resolve asks AWS who the credential is, whether it is admin, and when its key was last used.
// Failures after the identity is known degrade into a partial resolution.
func (s *Scanner) Resolve(ctx context.Context, c model.Credential) (*model.Resolution, error) {
	profile := ""
	switch {
	case c.ID == "unreadable":
		return nil, &scan.SkipError{Reason: "credential file could not be read"}
	case c.Source == "file":
		profile = c.ID
		if rest, ok := strings.CutPrefix(profile, "profile:"); ok && reserved(rest) {
			profile = rest
		}
		if c.Kind == "credential-process" || s.mfa[c.ID] {
			return nil, &scan.SkipError{Reason: "resolving would run a credential process or prompt for MFA"}
		}
	}
	api, err := s.api(ctx, profile)
	if err != nil {
		return nil, cleanErr("aws setup", err)
	}
	id, err := api.CallerIdentity(ctx)
	if err != nil {
		return nil, cleanErr("aws identity", err)
	}
	r := &model.Resolution{Identity: id.ARN}
	if id.Kind == "root" {
		r.AdminChecked, r.Admin, r.AdminWhy = true, true, "root account"
	} else if ps, err := api.Policies(ctx, id); err != nil {
		r.AdminWhy = "could not read policies: " + cleanErr("", err).Error()
	} else {
		r.AdminChecked = true
		if r.Admin, r.AdminWhy = IsAdmin(ps); !r.Admin {
			r.AdminWhy = "no admin policy found (attached policies only)"
		}
	}
	if key := s.keys[c.ID]; key != "" {
		if t, err := api.AccessKeyLastUsed(ctx, key); err == nil {
			r.KeyChecked, r.KeyLastUsed = true, t
		}
	}
	return r, nil
}

func reserved(name string) bool {
	return name == "environment" || name == "chain" || name == "unreadable"
}

// cleanErr strips control characters and caps length so provider text cannot spoof the terminal.
func cleanErr(prefix string, err error) error {
	msg := []rune(model.Sanitize(err.Error()))
	if len(msg) > 150 {
		msg = append(msg[:150], '…')
	}
	if prefix == "" {
		return errors.New(string(msg))
	}
	return errors.New(prefix + ": " + string(msg))
}

var _ scan.Scanner = (*Scanner)(nil)
