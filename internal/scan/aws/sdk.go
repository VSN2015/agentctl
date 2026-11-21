package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/VSN2015/agentctl/internal/scan"
)

// Only Get* and List* calls may appear in these interfaces (enforced by a test).
type stsAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type iamAPI interface {
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	ListGroupsForUser(context.Context, *iam.ListGroupsForUserInput, ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error)
	ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListGroupPolicies(context.Context, *iam.ListGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error)
	GetGroupPolicy(context.Context, *iam.GetGroupPolicyInput, ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
}

type sdkAPI struct {
	sts stsAPI
	iam iamAPI
}

// NewSDK returns a factory over the real AWS SDK.
//
// A profile chosen with config.WithSharedConfigProfile takes precedence over environment
// credentials (SDK resolveCredentialChain: sharedProfileSet is checked before envConfig keys),
// so explicit profiles need no special provider. An AWS_PROFILE variable alone does not.
// The default region avoids MissingRegionError from STS/IAM when the profile has none.
func NewSDK() APIFactory {
	return func(ctx context.Context, profile string) (API, error) {
		opts := []func(*config.LoadOptions) error{
			config.WithDefaultRegion("us-east-1"), config.WithRetryMaxAttempts(2),
			config.WithSSOTokenProviderOptions(noRefresh),
		}
		if profile != "" {
			opts = append(opts, config.WithSharedConfigProfile(profile))
		}
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, err
		}
		// The SDK's own view of where credentials would come from, taken before anything is
		// retrieved: helper processes and `aws login` refreshes must never run from here.
		if ps, ok := cfg.Credentials.(awssdk.CredentialProviderSource); ok {
			for _, src := range ps.ProviderSources() {
				switch src {
				case awssdk.CredentialSourceProcess, awssdk.CredentialSourceProfileProcess,
					awssdk.CredentialSourceLogin, awssdk.CredentialSourceProfileLogin:
					return nil, &scan.SkipError{Reason: "resolving would run a credential process or refresh an aws login session"}
				}
			}
		}
		return &sdkAPI{sts: sts.NewFromConfig(cfg), iam: iam.NewFromConfig(cfg)}, nil
	}
}

func (a *sdkAPI) CallerIdentity(ctx context.Context) (Identity, error) {
	out, err := a.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, err
	}
	return identityFromARN(awssdk.ToString(out.Arn), awssdk.ToString(out.Account)), nil
}

func identityFromARN(arn, account string) Identity {
	id := Identity{ARN: arn, Account: account, Kind: "other"}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return id
	}
	res := strings.Split(parts[5], "/")
	switch {
	case parts[2] == "iam" && parts[5] == "root":
		id.Kind = "root"
	case parts[2] == "iam" && res[0] == "user" && len(res) > 1:
		id.Kind, id.Name = "user", res[len(res)-1]
	case parts[2] == "sts" && res[0] == "assumed-role" && len(res) > 2:
		id.Kind, id.Name = "role", res[1]
	}
	return id
}

func (a *sdkAPI) AccessKeyLastUsed(ctx context.Context, keyID string) (*KeyUse, error) {
	out, err := a.iam.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: &keyID})
	if err != nil {
		return nil, err
	}
	u := out.AccessKeyLastUsed
	if u == nil || u.LastUsedDate == nil {
		return nil, nil
	}
	return &KeyUse{At: *u.LastUsedDate, Service: strings.ToLower(awssdk.ToString(u.ServiceName))}, nil
}

const adminARN = "arn:aws:iam::aws:policy/AdministratorAccess"

func (a *sdkAPI) Policies(ctx context.Context, id Identity) ([]Policy, error) {
	switch id.Kind {
	case "user":
		ps, err := a.entity(ctx, id.Name, "user")
		if err != nil {
			return nil, err
		}
		groups, err := pages(func(m *string) ([]types.Group, *string, error) {
			o, err := a.iam.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: &id.Name, Marker: m})
			if err != nil {
				return nil, nil, err
			}
			return o.Groups, next(o.IsTruncated, o.Marker), nil
		})
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			gp, err := a.entity(ctx, awssdk.ToString(g.GroupName), "group")
			if err != nil {
				return nil, err
			}
			ps = append(ps, gp...)
		}
		return ps, nil
	case "role":
		return a.entity(ctx, id.Name, "role")
	}
	return nil, nil // root is handled by the caller; other principals are not inspected
}

// entity returns attached (documents resolved) and inline policies of a user, group or role.
func (a *sdkAPI) entity(ctx context.Context, name, kind string) ([]Policy, error) {
	var attached []types.AttachedPolicy
	var inline []string
	var err error
	var get func(policy string) (*string, error)
	switch kind {
	case "user":
		attached, err = pages(func(m *string) ([]types.AttachedPolicy, *string, error) {
			o, err := a.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &name, Marker: m})
			if err != nil {
				return nil, nil, err
			}
			return o.AttachedPolicies, next(o.IsTruncated, o.Marker), nil
		})
		if err == nil {
			inline, err = pages(func(m *string) ([]string, *string, error) {
				o, err := a.iam.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &name, Marker: m})
				if err != nil {
					return nil, nil, err
				}
				return o.PolicyNames, next(o.IsTruncated, o.Marker), nil
			})
		}
		get = func(p string) (*string, error) {
			o, err := a.iam.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: &name, PolicyName: &p})
			if err != nil {
				return nil, err
			}
			return o.PolicyDocument, nil
		}
	case "group":
		attached, err = pages(func(m *string) ([]types.AttachedPolicy, *string, error) {
			o, err := a.iam.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: &name, Marker: m})
			if err != nil {
				return nil, nil, err
			}
			return o.AttachedPolicies, next(o.IsTruncated, o.Marker), nil
		})
		if err == nil {
			inline, err = pages(func(m *string) ([]string, *string, error) {
				o, err := a.iam.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: &name, Marker: m})
				if err != nil {
					return nil, nil, err
				}
				return o.PolicyNames, next(o.IsTruncated, o.Marker), nil
			})
		}
		get = func(p string) (*string, error) {
			o, err := a.iam.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: &name, PolicyName: &p})
			if err != nil {
				return nil, err
			}
			return o.PolicyDocument, nil
		}
	default:
		attached, err = pages(func(m *string) ([]types.AttachedPolicy, *string, error) {
			o, err := a.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &name, Marker: m})
			if err != nil {
				return nil, nil, err
			}
			return o.AttachedPolicies, next(o.IsTruncated, o.Marker), nil
		})
		if err == nil {
			inline, err = pages(func(m *string) ([]string, *string, error) {
				o, err := a.iam.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &name, Marker: m})
				if err != nil {
					return nil, nil, err
				}
				return o.PolicyNames, next(o.IsTruncated, o.Marker), nil
			})
		}
		get = func(p string) (*string, error) {
			o, err := a.iam.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &name, PolicyName: &p})
			if err != nil {
				return nil, err
			}
			return o.PolicyDocument, nil
		}
	}
	if err != nil {
		return nil, err
	}
	var ps []Policy
	for _, ap := range attached {
		p := Policy{Name: awssdk.ToString(ap.PolicyName), ARN: awssdk.ToString(ap.PolicyArn)}
		if p.ARN != adminARN { // the ARN alone decides admin; skip two calls
			if p.Document, err = a.managedDocument(ctx, p.ARN); err != nil {
				return nil, err
			}
		}
		ps = append(ps, p)
	}
	for _, n := range inline {
		doc, err := get(n)
		if err != nil {
			return nil, err
		}
		d, err := decodeDoc(doc)
		if err != nil {
			return nil, err
		}
		ps = append(ps, Policy{Name: n, Document: d})
	}
	return ps, nil
}

func (a *sdkAPI) managedDocument(ctx context.Context, arn string) ([]byte, error) {
	p, err := a.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &arn})
	if err != nil {
		return nil, err
	}
	if p.Policy == nil {
		return nil, fmt.Errorf("policy %s not returned", arn)
	}
	v, err := a.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: &arn, VersionId: p.Policy.DefaultVersionId})
	if err != nil {
		return nil, err
	}
	if v.PolicyVersion == nil {
		return nil, fmt.Errorf("policy version of %s not returned", arn)
	}
	return decodeDoc(v.PolicyVersion.Document)
}

// decodeDoc undoes the URL encoding IAM applies to policy documents.
func decodeDoc(s *string) ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	d, err := url.PathUnescape(*s) // not QueryUnescape: a literal '+' must survive
	return []byte(d), err
}

func next(truncated bool, marker *string) *string {
	if truncated {
		return marker
	}
	return nil
}

// pages collects every page; fetch returns the items and the next marker (nil = done).
func pages[T any](fetch func(marker *string) ([]T, *string, error)) ([]T, error) {
	var all []T
	var m *string
	for {
		items, nm, err := fetch(m)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if nm == nil {
			return all, nil
		}
		m = nm
	}
}

// noRefresh makes an expired SSO token fail instead of being renewed: SDK refreshToken calls
// ssooidc CreateToken and only afterwards rewrites ~/.aws/sso/cache, so an erroring client
// blocks both the call and the write. Legacy sso_start_url profiles read the cache without
// any refresh path (ssocreds Provider.Retrieve returns InvalidTokenError when expired).
func noRefresh(o *ssocreds.SSOTokenProviderOptions) { o.Client = noCreateToken{} }

type noCreateToken struct{}

func (noCreateToken) CreateToken(context.Context, *ssooidc.CreateTokenInput, ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	return nil, errors.New("SSO session expired; run aws sso login (agentctl never renews tokens)")
}
