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

// KeyUse is the provider's record of an access key's last use; Service is lower-cased ("sts", "s3").
type KeyUse struct {
	At      time.Time
	Service string
}

type API interface {
	CallerIdentity(ctx context.Context) (Identity, error)
	Policies(ctx context.Context, id Identity) ([]Policy, error)
	AccessKeyLastUsed(ctx context.Context, keyID string) (*KeyUse, error) // nil => never used
}

// APIFactory builds an API for a profile; "" means the default credential chain.
type APIFactory func(ctx context.Context, profile string) (API, error)
