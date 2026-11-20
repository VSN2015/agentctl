package aws

import (
	"context"

	"github.com/OWNER/agentctl/internal/model"
	"github.com/OWNER/agentctl/internal/scan"
)

// Resolve is a placeholder until the API-backed implementation lands.
func (s *Scanner) Resolve(ctx context.Context, c model.Credential) (*model.Resolution, error) {
	return nil, &scan.SkipError{Reason: "not implemented"}
}

var _ scan.Scanner = (*Scanner)(nil)
