package aws

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

func TestSDKInterfacesAreReadOnly(t *testing.T) {
	for _, it := range []reflect.Type{reflect.TypeOf((*stsAPI)(nil)).Elem(), reflect.TypeOf((*iamAPI)(nil)).Elem()} {
		for i := 0; i < it.NumMethod(); i++ {
			if n := it.Method(i).Name; !strings.HasPrefix(n, "Get") && !strings.HasPrefix(n, "List") {
				t.Errorf("%s.%s is not read-only", it.Name(), n)
			}
		}
	}
}

// fakeIAM implements only what Policies needs; any other call panics on the nil embedded interface.
type fakeIAM struct{ iamAPI }

func (fakeIAM) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	if in.Marker == nil {
		return &iam.ListAttachedUserPoliciesOutput{IsTruncated: true, Marker: awssdk.String("m2"),
			AttachedPolicies: []types.AttachedPolicy{{PolicyName: awssdk.String("A"), PolicyArn: awssdk.String("arn:aws:iam::1:policy/A")}}}, nil
	}
	return &iam.ListAttachedUserPoliciesOutput{
		AttachedPolicies: []types.AttachedPolicy{{PolicyName: awssdk.String("AdministratorAccess"), PolicyArn: awssdk.String(adminARN)}}}, nil
}
func (fakeIAM) ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{PolicyNames: []string{"inl"}}, nil
}
func (fakeIAM) GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	return &iam.GetUserPolicyOutput{PolicyDocument: awssdk.String("%7B%22Statement%22%3A%7B%22Action%22%3A%22s3%3A%2A%22%2C%22Note%22%3A%22a+b%22%7D%7D")}, nil
}
func (fakeIAM) ListGroupsForUser(context.Context, *iam.ListGroupsForUserInput, ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error) {
	return &iam.ListGroupsForUserOutput{Groups: []types.Group{{GroupName: awssdk.String("g")}}}, nil
}
func (fakeIAM) ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return &iam.ListAttachedGroupPoliciesOutput{}, nil
}
func (fakeIAM) ListGroupPolicies(context.Context, *iam.ListGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	return &iam.ListGroupPoliciesOutput{PolicyNames: []string{"ginl"}}, nil
}
func (fakeIAM) GetGroupPolicy(context.Context, *iam.GetGroupPolicyInput, ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error) {
	return &iam.GetGroupPolicyOutput{PolicyDocument: awssdk.String("%7B%7D")}, nil
}
func (fakeIAM) GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &types.Policy{DefaultVersionId: awssdk.String("v1")}}, nil
}
func (fakeIAM) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{Document: awssdk.String("%7B%22Statement%22%3A%5B%5D%7D")}}, nil
}

func TestSDKPoliciesDecodesAndPages(t *testing.T) {
	a := &sdkAPI{iam: fakeIAM{}}
	ps, err := a.Policies(context.Background(), Identity{Kind: "user", Name: "u"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range ps {
		got[p.Name] = string(p.Document)
	}
	want := map[string]string{
		"A": `{"Statement":[]}`, "AdministratorAccess": "",
		"inl": `{"Statement":{"Action":"s3:*","Note":"a+b"}}`, "ginl": "{}",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("policies = %v, want %v", got, want)
	}
}

func TestIdentityFromARN(t *testing.T) {
	cases := map[string]Identity{
		"arn:aws:iam::1:root":                         {Kind: "root"},
		"arn:aws:iam::1:user/path/bob":                {Kind: "user", Name: "bob"},
		"arn:aws:sts::1:assumed-role/Admin/session-1": {Kind: "role", Name: "Admin"},
		"arn:aws:sts::1:federated-user/x":             {Kind: "other"},
		"garbage":                                     {Kind: "other"},
	}
	for arn, want := range cases {
		want.ARN, want.Account = arn, "1"
		if got := identityFromARN(arn, "1"); got != want {
			t.Errorf("%s: %+v, want %+v", arn, got, want)
		}
	}
}

type fakeKeyIAM struct {
	iamAPI
	use *types.AccessKeyLastUsed
}

func (f fakeKeyIAM) GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	return &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: f.use}, nil
}

func TestSDKAccessKeyLastUsedCarriesLowerCasedService(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a := &sdkAPI{iam: fakeKeyIAM{use: &types.AccessKeyLastUsed{LastUsedDate: &when, ServiceName: awssdk.String("STS")}}}
	u, err := a.AccessKeyLastUsed(context.Background(), "k")
	if err != nil || u == nil || !u.At.Equal(when) || u.Service != "sts" {
		t.Fatalf("u=%+v err=%v", u, err)
	}
	a = &sdkAPI{iam: fakeKeyIAM{use: &types.AccessKeyLastUsed{ServiceName: awssdk.String("N/A")}}} // never used: no date
	if u, err = a.AccessKeyLastUsed(context.Background(), "k"); err != nil || u != nil {
		t.Fatalf("never used: u=%+v err=%v", u, err)
	}
}

func TestSSOTokenRefreshIsDisabled(t *testing.T) {
	var o ssocreds.SSOTokenProviderOptions
	noRefresh(&o)
	if o.Client == nil {
		t.Fatal("no client set")
	}
	if _, err := o.Client.CreateToken(context.Background(), &ssooidc.CreateTokenInput{}); err == nil {
		t.Fatal("CreateToken must fail")
	}
}
