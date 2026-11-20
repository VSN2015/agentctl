package aws

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/smithy-go"

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
	case s.skip[c.ID]:
		return nil, &scan.SkipError{Reason: "resolving would run a credential process, prompt for MFA or refresh an aws login session"}
	case c.Source == "file":
		profile = c.ID
		if rest, ok := strings.CutPrefix(profile, "profile:"); ok && reserved(rest) {
			profile = rest
		}
	}
	api, err := s.api(ctx, profile)
	if err != nil {
		var skip *scan.SkipError
		if errors.As(err, &skip) {
			return nil, err
		}
		return nil, cleanErr("aws setup failed", err, false)
	}
	id, err := api.CallerIdentity(ctx)
	if err != nil {
		return nil, cleanErr("aws identity check failed", err, true)
	}
	r := &model.Resolution{Identity: id.ARN}
	// before Policies: our own IAM calls may update the key's last-used record
	if key := s.keys[c.ID]; key != "" {
		if u, err := api.AccessKeyLastUsed(ctx, key); err == nil {
			r.KeyChecked = true
			if u != nil {
				r.KeyLastUsed, r.KeyLastUsedService = &u.At, u.Service
			}
		}
	}
	switch id.Kind {
	case "root":
		r.AdminChecked, r.Admin, r.AdminWhy = true, true, "root account"
	case "user", "role":
		if ps, err := api.Policies(ctx, id); err != nil {
			r.AdminWhy = "could not read policies" + errCode(err)
		} else {
			r.AdminChecked = true
			if r.Admin, r.AdminWhy = IsAdmin(ps); !r.Admin {
				r.AdminWhy = "no admin policy found (attached policies only)"
			}
		}
	default:
		r.AdminWhy = "principal type not inspected"
	}
	return r, nil
}

func reserved(name string) bool {
	return name == "environment" || name == "chain" || name == "unreadable"
}

// errCode returns " (Code)" for an AWS API error and "" otherwise. SDK error text is never shown:
// it can embed provider or credential-helper output.
func errCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return " (" + model.Sanitize(ae.ErrorCode()) + ")"
	}
	return ""
}

// cleanErr maps an SDK error to a fixed phrase, plus the API error code when withCode is set.
func cleanErr(phrase string, err error, withCode bool) error {
	if withCode {
		phrase += errCode(err)
	}
	return errors.New(phrase)
}

var _ scan.Scanner = (*Scanner)(nil)
