package aws

import (
	"context"
	"time"
)

type Identity struct{ ARN, Account, Kind, Name string } // Kind "user"|"role"|"root"|"other"

type Policy struct {
	Name, ARN string
	Document  []byte
}

type API interface {
	CallerIdentity(ctx context.Context) (Identity, error)
	Policies(ctx context.Context, id Identity) ([]Policy, error)
	AccessKeyLastUsed(ctx context.Context, keyID string) (*time.Time, error) // nil => never used
}

// APIFactory builds an API for a profile; "" means the default credential chain.
type APIFactory func(ctx context.Context, profile string) (API, error)
